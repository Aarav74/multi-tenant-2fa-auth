from pydantic import BaseModel, EmailStr
from typing import Optional

class TenantBase(BaseModel):
    domain: str
    name: str

class UserLogin(BaseModel):
    tenant_domain: str
    email: EmailStr
    password: str

class UserRegister(BaseModel):
    tenant_domain: str
    email: EmailStr
    password: str
    name: str

class Token(BaseModel):
    access_token: str
    token_type: str
    requires_2fa: bool = False

class TOTPSetup(BaseModel):
    secret: str
    qr_code: str

class TOTPVerify(BaseModel):
    token: str
    totp_code: str

class UserResponse(BaseModel):
    id: int
    email: str
    is_2fa_enabled: bool
    tenant_domain: str
    
    class Config:
        from_attributes = True