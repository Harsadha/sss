from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional
import re

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str
    password: str = Field(..., min_length=8)

    @validator('username')
    def username_alphanumeric(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username must be alphanumeric (underscores allowed)')
        return v.lower()

    @validator('email')
    def email_valid(cls, v):
        if '@' not in v or '.' not in v.split('@')[-1]:
            raise ValueError('Invalid email address')
        return v.lower()

class ChallengeRequest(BaseModel):
    username: str

class ChallengeResponse(BaseModel):
    challenge_id: str
    nonce: str
    expires_in: int = 300

class LoginStep1Request(BaseModel):
    challenge_id: str
    username: str
    response: str  # HMAC-SHA256(password_hash, nonce)
    timestamp: str  # Unix timestamp for replay prevention
    request_nonce: str  # Unique per-request nonce

class OTPVerifyRequest(BaseModel):
    temp_token: str  # Issued after successful step 1
    otp_code: str = Field(..., min_length=6, max_length=6)
    timestamp: str
    request_nonce: str

class RegisterResponse(BaseModel):
    success: bool
    message: str
    otp_secret: Optional[str] = None
    otp_uri: Optional[str] = None
    username: Optional[str] = None

class LoginStep1Response(BaseModel):
    success: bool
    message: str
    temp_token: Optional[str] = None
    requires_otp: bool = True

class SessionInfo(BaseModel):
    username: str
    email: str
    created_at: str
    last_activity: str
    ip_address: Optional[str] = None

class LogoutRequest(BaseModel):
    session_token: str

class PasswordStrengthRequest(BaseModel):
    password: str

class AuditEntry(BaseModel):
    event_type: str
    username: Optional[str]
    ip_address: Optional[str]
    details: Optional[str]
    success: bool
    created_at: str
