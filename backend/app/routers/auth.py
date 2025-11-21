
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
import logging

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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Setup logging
logger = logging.getLogger(__name__)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    return user

@router.post("/register", response_model=UserResponse)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user"""
    try:
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
        
        logger.info(f"New user registered: {new_user.email} for tenant: {tenant.domain}")
        
        return UserResponse(
            id=new_user.id,
            email=new_user.email,
            is_2fa_enabled=new_user.is_2fa_enabled,
            tenant_domain=tenant.domain
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in user registration: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during registration")

@router.post("/login", response_model=Token)
def login(login_data: UserLogin, db: Session = Depends(get_db)):
    """Login endpoint - returns token or indicates 2FA required"""
    try:
        user = AuthService.authenticate_user(
            db, login_data.tenant_domain, login_data.email, login_data.password
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect credentials"
            )
        
        logger.info(f"User login: {user.email}, 2FA enabled: {user.is_2fa_enabled}")
        
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
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in user login: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during login")

@router.post("/2fa/setup", response_model=TOTPSetup)
def setup_2fa(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Setup 2FA for current user"""
    try:
        logger.info(f"Setting up 2FA for user_id: {user.id}")
        
        # Generate TOTP secret and QR code
        secret, qr_code = TOTPService.get_totp_setup(user.email)
        
        # Save secret (temporary, will be confirmed on verification)
        user.totp_secret = secret
        db.commit()
        
        logger.info(f"2FA setup successful for user: {user.email}, secret: {secret[:10]}...")
        
        return TOTPSetup(secret=secret, qr_code=qr_code)
        
    except Exception as e:
        logger.error(f"Error setting up 2FA for user {user.id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error setting up 2FA: {str(e)}")

@router.post("/2fa/verify", response_model=Token)
def verify_2fa(verify_data: TOTPVerify, db: Session = Depends(get_db)):
    """Verify 2FA code and complete login"""
    try:
        # Decode temporary token
        try:
            payload = jwt.decode(
                verify_data.token,
                settings.secret_key,
                algorithms=[settings.algorithm]
            )
            user_id = int(payload.get("sub"))
            is_temp = payload.get("temp", False)
            
            if not is_temp:
                raise HTTPException(status_code=401, detail="Invalid token type")
                
        except JWTError as e:
            logger.error(f"JWT error in 2FA verification: {str(e)}")
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            logger.error(f"User not found for 2FA verification: {user_id}")
            raise HTTPException(status_code=404, detail="User not found")
        
        if not user.totp_secret:
            logger.error(f"No TOTP secret for user: {user_id}")
            raise HTTPException(status_code=400, detail="2FA not setup for this user")
        
        logger.info(f"Verifying 2FA for user: {user.email}, code: {verify_data.totp_code}")
        
        # Verify TOTP code
        if not TOTPService.verify_totp(user.totp_secret, verify_data.totp_code):
            logger.warning(f"Invalid 2FA code for user: {user.email}")
            raise HTTPException(status_code=401, detail="Invalid 2FA code")
        
        # Enable 2FA if not already enabled
        if not user.is_2fa_enabled:
            user.is_2fa_enabled = True
            db.commit()
            logger.info(f"2FA enabled for user: {user.email}")
        
        # Create full access token
        access_token = AuthService.create_access_token(
            data={"sub": str(user.id), "tenant_id": user.tenant_id},
            expires_delta=timedelta(minutes=settings.access_token_expire_minutes)
        )
        
        logger.info(f"2FA verification successful for user: {user.email}")
        
        return Token(access_token=access_token, token_type="bearer")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in 2FA verification: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during 2FA verification")

@router.post("/2fa/enable")
def enable_2fa(enable_data: dict, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Enable 2FA for user after verification"""
    try:
        logger.info(f"Received enable_2fa request for user: {user.email}")
        
        totp_code = enable_data.get("totp_code")
        
        if not totp_code:
            raise HTTPException(status_code=400, detail="TOTP code is required")
        
        # Clean the code
        clean_code = str(totp_code).strip().replace(" ", "")
        
        if len(clean_code) != 6 or not clean_code.isdigit():
            raise HTTPException(status_code=400, detail="TOTP code must be 6 digits")
        
        if not user.totp_secret:
            logger.error(f"No TOTP secret for user during enable: {user.id}")
            raise HTTPException(status_code=400, detail="2FA not setup for this user. Please setup 2FA first.")
        
        logger.info(f"Enabling 2FA for user: {user.email}, code: {clean_code}")
        
        # Verify TOTP code
        is_valid = TOTPService.verify_totp(user.totp_secret, clean_code)
        
        if not is_valid:
            # Get current expected code for debugging
            current_code = TOTPService.get_current_totp_code(user.totp_secret)
            logger.warning(f"Invalid TOTP code for user {user.email}. Expected around: {current_code}")
            raise HTTPException(
                status_code=401, 
                detail="Invalid 2FA code. Please check the code and try again."
            )
        
        # Enable 2FA
        user.is_2fa_enabled = True
        db.commit()
        
        logger.info(f"2FA successfully enabled for user: {user.email}")
        
        return {
            "message": "2FA enabled successfully", 
            "user_id": user.id,
            "email": user.email,
            "is_2fa_enabled": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error enabling 2FA: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.post("/tenant/create")
def create_tenant(tenant_data: dict, db: Session = Depends(get_db)):
    """Create a new tenant (for testing)"""
    try:
        domain = tenant_data.get("domain")
        name = tenant_data.get("name")
        
        if not domain or not name:
            raise HTTPException(status_code=400, detail="Domain and name are required")
        
        # Check if tenant already exists
        existing_tenant = db.query(Tenant).filter(Tenant.domain == domain).first()
        if existing_tenant:
            raise HTTPException(status_code=400, detail="Tenant with this domain already exists")
        
        tenant = Tenant(
            name=name,
            domain=domain
        )
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        
        logger.info(f"New tenant created: {tenant.name} ({tenant.domain})")
        
        return {"id": tenant.id, "domain": tenant.domain, "name": tenant.name}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating tenant: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during tenant creation")

@router.get("/me")
def read_users_me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current user info"""
    try:
        # Get tenant info
        tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
        
        return {
            "id": user.id,
            "email": user.email,
            "tenant_domain": tenant.domain if tenant else "unknown",
            "is_2fa_enabled": user.is_2fa_enabled,
            "full_name": f"User {user.id}" # Placeholder as User model might not have full_name
        }
    except Exception as e:
        logger.error(f"Error in /me endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving user info")

@router.get("/users")
def get_users(db: Session = Depends(get_db)):
    """Get all users (for testing)"""
    try:
        users = db.query(User).all()
        return [
            {
                "id": user.id, 
                "email": user.email, 
                "tenant_id": user.tenant_id,
                "is_2fa_enabled": user.is_2fa_enabled,
                "has_totp_secret": bool(user.totp_secret)
            } 
            for user in users
        ]
    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving users")

# Debug endpoints for 2FA testing
@router.get("/debug/2fa-status")
def debug_2fa_status(user_id: int = Query(...), db: Session = Depends(get_db)):
    """Debug endpoint to check 2FA status"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"error": "User not found"}
        
        current_code = TOTPService.get_current_totp_code(user.totp_secret) if user.totp_secret else "No secret"
        
        return {
            "user_id": user.id,
            "email": user.email,
            "is_2fa_enabled": user.is_2fa_enabled,
            "has_totp_secret": bool(user.totp_secret),
            "totp_secret_preview": user.totp_secret[:10] + "..." if user.totp_secret else None,
            "current_totp_code": current_code,
            "tenant_id": user.tenant_id
        }
    except Exception as e:
        logger.error(f"Error in debug 2fa status: {str(e)}")
        return {"error": str(e)}

@router.post("/debug/set-totp-secret")
def debug_set_totp_secret(
    user_id: int = Query(...), 
    secret: str = Query(...), 
    db: Session = Depends(get_db)
):
    """Debug endpoint to manually set TOTP secret"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user.totp_secret = secret
        db.commit()
        
        logger.info(f"Manually set TOTP secret for user: {user.email}")
        
        return {
            "message": "TOTP secret set",
            "user_id": user.id,
            "email": user.email,
            "secret_preview": secret[:10] + "..."
        }
    except Exception as e:
        logger.error(f"Error setting TOTP secret: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error setting TOTP secret: {str(e)}")

@router.get("/debug/test-totp")
def debug_test_totp(user_id: int = Query(...), code: str = Query(None), db: Session = Depends(get_db)):
    """Debug endpoint to test TOTP verification"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"error": "User not found"}
        
        if not user.totp_secret:
            return {"error": "No TOTP secret set for user"}
        
        current_code = TOTPService.get_current_totp_code(user.totp_secret)
        result = {
            "user_id": user.id,
            "email": user.email,
            "totp_secret": user.totp_secret[:10] + "...",
            "current_totp_code": current_code,
            "is_2fa_enabled": user.is_2fa_enabled
        }
        
        if code:
            is_valid = TOTPService.verify_totp(user.totp_secret, code)
            result["provided_code"] = code
            result["is_valid"] = is_valid
        
        return result
    except Exception as e:
        logger.error(f"Error in debug TOTP test: {str(e)}")
        return {"error": str(e)}
