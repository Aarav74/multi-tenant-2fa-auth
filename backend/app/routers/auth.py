from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from app.database import get_db
from app.schemas.auth import (
    UserLogin, UserRegister, Token, TOTPSetup, TOTPVerify, UserResponse
)
from app.services.auth_service import AuthService
from app.services.totp_service import TOTPService
from app.models.user import User
from app.models.tenant import Tenant
from datetime import timedelta
from app.config import get_settings

router = APIRouter(prefix="/auth", tags=["authentication"])
settings = get_settings()

@router.post("/register", response_model=UserResponse)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if tenant exists
    tenant = db.query(Tenant).filter(Tenant.domain == user_data.tenant_domain).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    # Check if user exists
    existing_user = db.query(User).filter(
        User.email == user_data.email,
        User.tenant_id == tenant.id
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    hashed_password = AuthService.get_password_hash(user_data.password)
    new_user = User(
        email=user_data.email,
        hashed_password=hashed_password,
        tenant_id=tenant.id
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return UserResponse(
        id=new_user.id,
        email=new_user.email,
        is_2fa_enabled=new_user.is_2fa_enabled,
        tenant_domain=tenant.domain
    )

@router.post("/login", response_model=Token)
def login(login_data: UserLogin, db: Session = Depends(get_db)):
    """Login endpoint - returns token or indicates 2FA required"""
    user = AuthService.authenticate_user(
        db, login_data.tenant_domain, login_data.email, login_data.password
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials"
        )
    
    # If 2FA is enabled, return partial token
    if user.is_2fa_enabled:
        # Create temporary token for 2FA verification
        temp_token = AuthService.create_access_token(
            data={"sub": str(user.id), "temp": True},
            expires_delta=timedelta(minutes=5)
        )
        return Token(
            access_token=temp_token,
            token_type="bearer",
            requires_2fa=True
        )
    
    # Create full access token
    access_token = AuthService.create_access_token(
        data={"sub": str(user.id), "tenant_id": user.tenant_id},
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes)
    )
    
    return Token(access_token=access_token, token_type="bearer")

@router.post("/2fa/setup")
def setup_2fa(user_id: int = Query(...), db: Session = Depends(get_db)):
    """Setup 2FA for user"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Generate TOTP secret and QR code
        secret, qr_code = TOTPService.get_totp_setup(user.email)
        
        # Save secret (temporary, will be confirmed on verification)
        user.totp_secret = secret
        db.commit()
        
        return TOTPSetup(secret=secret, qr_code=qr_code)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error setting up 2FA: {str(e)}")

@router.post("/2fa/verify", response_model=Token)
def verify_2fa(verify_data: TOTPVerify, db: Session = Depends(get_db)):
    """Verify 2FA code and complete login"""
    
    # Decode temporary token
    try:
        payload = jwt.decode(
            verify_data.token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )
        user_id = int(payload.get("sub"))
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify TOTP code
    if not TOTPService.verify_totp(user.totp_secret, verify_data.totp_code):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")
    
    # Enable 2FA if not already enabled
    if not user.is_2fa_enabled:
        user.is_2fa_enabled = True
        db.commit()
    
    # Create full access token
    access_token = AuthService.create_access_token(
        data={"sub": str(user.id), "tenant_id": user.tenant_id},
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes)
    )
    
    return Token(access_token=access_token, token_type="bearer")

@router.post("/2fa/enable")
def enable_2fa(enable_data: dict, db: Session = Depends(get_db)):
    """Enable 2FA for user after verification"""
    try:
        user_id = enable_data.get("user_id")
        totp_code = enable_data.get("totp_code")
        
        if not user_id or not totp_code:
            raise HTTPException(status_code=400, detail="User ID and TOTP code are required")
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.totp_secret:
            raise HTTPException(status_code=404, detail="User not found or 2FA not setup")
        
        # Verify TOTP code
        if not TOTPService.verify_totp(user.totp_secret, totp_code):
            raise HTTPException(status_code=401, detail="Invalid 2FA code")
        
        # Enable 2FA
        user.is_2fa_enabled = True
        db.commit()
        
        return {"message": "2FA enabled successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error enabling 2FA: {str(e)}")

@router.post("/tenant/create")
def create_tenant(tenant_data: dict, db: Session = Depends(get_db)):
    """Create a new tenant (for testing)"""
    # Check if tenant already exists
    existing_tenant = db.query(Tenant).filter(Tenant.domain == tenant_data["domain"]).first()
    if existing_tenant:
        raise HTTPException(status_code=400, detail="Tenant with this domain already exists")
    
    tenant = Tenant(
        name=tenant_data["name"],
        domain=tenant_data["domain"]
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return {"id": tenant.id, "domain": tenant.domain}

# Add a simple user info endpoint for the frontend
@router.get("/me")
def get_current_user():
    """Get current user info (placeholder)"""
    # This is a simplified version - in a real app, you'd decode the JWT
    return {
        "email": "user@example.com",
        "tenant_domain": "example",
        "is_2fa_enabled": False,
        "full_name": "Test User"
    }

# Add a simple endpoint to get user ID for testing
@router.get("/users")
def get_users(db: Session = Depends(get_db)):
    """Get all users (for testing)"""
    users = db.query(User).all()
    return [{"id": user.id, "email": user.email, "tenant_id": user.tenant_id} for user in users]