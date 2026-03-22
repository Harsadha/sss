import hashlib
import hmac
import secrets
import time
import base64
import struct
import os
from datetime import datetime, timedelta
from typing import Optional, Tuple
import json

# ─── Password Security ───────────────────────────────────────────────────────

def generate_salt(length: int = 32) -> str:
    """Generate a cryptographically secure random salt."""
    return secrets.token_hex(length)

def hash_password(password: str, salt: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with salt."""
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations=310000,  # NIST recommended minimum
        dklen=32
    )
    return base64.b64encode(key).decode('utf-8')

def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """Verify password against stored hash using constant-time comparison."""
    computed = hash_password(password, salt)
    return hmac.compare_digest(computed.encode(), stored_hash.encode())

# ─── Challenge-Response ───────────────────────────────────────────────────────

def generate_challenge() -> Tuple[str, str]:
    """Generate a unique challenge ID and nonce for challenge-response auth."""
    challenge_id = secrets.token_urlsafe(32)
    nonce = secrets.token_hex(64)
    return challenge_id, nonce

def compute_challenge_response(password: str, salt: str, nonce: str) -> str:
    """
    Compute challenge response: HMAC-SHA256(password_hash, nonce)
    Client computes this — only someone who knows the password can respond correctly.
    """
    pw_hash = hash_password(password, salt)
    response = hmac.new(
        pw_hash.encode('utf-8'),
        nonce.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return response

def verify_challenge_response(stored_hash: str, salt: str, nonce: str, client_response: str) -> bool:
    """Verify the client's challenge response."""
    expected = hmac.new(
        stored_hash.encode('utf-8'),
        nonce.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected.encode(), client_response.encode())

# ─── TOTP (Time-based OTP) ────────────────────────────────────────────────────

def generate_otp_secret() -> str:
    """Generate a base32-encoded OTP secret."""
    secret_bytes = secrets.token_bytes(20)  # 160-bit secret
    return base64.b32encode(secret_bytes).decode('utf-8')

def _hotp(secret: str, counter: int) -> int:
    """HOTP algorithm per RFC 4226."""
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    msg = struct.pack('>Q', counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack('>I', h[offset:offset+4])[0] & 0x7FFFFFFF
    return code % 1000000

def generate_totp(secret: str, time_step: int = 30) -> str:
    """Generate current TOTP code."""
    counter = int(time.time()) // time_step
    return str(_hotp(secret, counter)).zfill(6)

def verify_totp(secret: str, token: str, window: int = 1, time_step: int = 30) -> bool:
    """
    Verify TOTP with time window to handle clock drift.
    window=1 allows ±1 time step (±30 seconds).
    """
    if not token or len(token) != 6 or not token.isdigit():
        return False
    counter = int(time.time()) // time_step
    for delta in range(-window, window + 1):
        expected = str(_hotp(secret, counter + delta)).zfill(6)
        if hmac.compare_digest(expected.encode(), token.encode()):
            return True
    return False

def get_totp_uri(secret: str, username: str, issuer: str = "SecureAuth") -> str:
    """Generate otpauth URI for QR code generation."""
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"

# ─── Session Tokens ───────────────────────────────────────────────────────────

def generate_session_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(64)

def hash_token(token: str) -> str:
    """Hash a token for storage (tokens stored as hashes)."""
    return hashlib.sha256(token.encode()).hexdigest()

# ─── Replay Attack Prevention ─────────────────────────────────────────────────

def compute_request_hash(username: str, endpoint: str, timestamp: str, nonce: str) -> str:
    """Compute a unique hash for a request to detect replays."""
    payload = f"{username}:{endpoint}:{timestamp}:{nonce}"
    return hashlib.sha256(payload.encode()).hexdigest()

def is_timestamp_valid(timestamp: str, max_age_seconds: int = 300) -> bool:
    """Check if request timestamp is within acceptable window (5 minutes)."""
    try:
        req_time = float(timestamp)
        current_time = time.time()
        age = abs(current_time - req_time)
        return age <= max_age_seconds
    except (ValueError, TypeError):
        return False

# ─── Password Strength ────────────────────────────────────────────────────────

def check_password_strength(password: str) -> dict:
    """Check password strength and return details."""
    issues = []
    score = 0
    
    if len(password) >= 12:
        score += 25
    else:
        issues.append("At least 12 characters required")

    if any(c.isupper() for c in password):
        score += 25
    else:
        issues.append("Add uppercase letters")

    if any(c.islower() for c in password):
        score += 15
    else:
        issues.append("Add lowercase letters")

    if any(c.isdigit() for c in password):
        score += 20
    else:
        issues.append("Add numbers")

    special = set('!@#$%^&*()_+-=[]{}|;:,.<>?')
    if any(c in special for c in password):
        score += 15
    else:
        issues.append("Add special characters")

    if score >= 90:
        strength = "Strong"
    elif score >= 65:
        strength = "Moderate"
    else:
        strength = "Weak"

    return {"score": score, "strength": strength, "issues": issues, "valid": score >= 65}
