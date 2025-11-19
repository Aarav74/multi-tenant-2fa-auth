from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.tenant import Tenant
from app.config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        return pwd_context.hash(password)
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
        return encoded_jwt
    
    @staticmethod
    def authenticate_user(db: Session, tenant_domain: str, email: str, password: str) -> Optional[User]:
        # Get tenant
        tenant = db.query(Tenant).filter(Tenant.domain == tenant_domain).first()
        if not tenant:
            return None
        
        # Get user
        user = db.query(User).filter(
            User.email == email,
            User.tenant_id == tenant.id
        ).first()
        
        if not user:
            return None
        if not AuthService.verify_password(password, user.hashed_password):
            return None
        return user