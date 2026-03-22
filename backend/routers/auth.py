from fastapi import APIRouter, HTTPException, Request, Depends
from datetime import datetime, timedelta
import time
import secrets
from database import get_db
from schemas import (
    RegisterRequest, RegisterResponse,
    ChallengeRequest, ChallengeResponse,
    LoginStep1Request, LoginStep1Response,
    OTPVerifyRequest, PasswordStrengthRequest
)
from security import (
    generate_salt, hash_password, verify_password,
    generate_challenge, verify_challenge_response,
    generate_otp_secret, generate_totp, verify_totp, get_totp_uri,
    generate_session_token, hash_token,
    compute_request_hash, is_timestamp_valid,
    check_password_strength
)

router = APIRouter()

# ─── Helpers ─────────────────────────────────────────────────────────────────

async def log_audit(cur, event_type: str, username: str, ip: str, details: str, success: bool):
    await cur.execute(
        "INSERT INTO audit_log (event_type, username, ip_address, details, success) VALUES (%s, %s, %s, %s, %s)",
        (event_type, username, ip, details, success)
    )

async def check_replay(cur, request_hash: str, username: str, endpoint: str, ip: str) -> bool:
    """Returns True if this is a replay (already seen), False if new."""
    result = await cur.execute(
        "SELECT id FROM replay_log WHERE request_hash = %s", (request_hash,)
    )
    row = await cur.fetchone()
    if row:
        return True  # Replay detected!
    
    # Store this request hash
    await cur.execute(
        "INSERT INTO replay_log (request_hash, username, endpoint, ip_address) VALUES (%s, %s, %s, %s)",
        (request_hash, username, endpoint, ip)
    )
    # Clean old entries (> 10 minutes)
    await cur.execute(
        "DELETE FROM replay_log WHERE created_at < DATE_SUB(NOW(), INTERVAL 10 MINUTE)"
    )
    return False

# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/register", response_model=RegisterResponse)
async def register(req: RegisterRequest, request: Request, cur=Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    
    # Check if username or email exists
    await cur.execute(
        "SELECT id FROM users WHERE username = %s OR email = %s",
        (req.username, req.email)
    )
    if await cur.fetchone():
        await log_audit(cur, "REGISTER_FAIL", req.username, ip, "Username or email already exists", False)
        raise HTTPException(status_code=409, detail="Username or email already exists")

    # Password strength check
    strength = check_password_strength(req.password)
    if not strength["valid"]:
        raise HTTPException(
            status_code=400,
            detail=f"Password too weak: {', '.join(strength['issues'])}"
        )

    # Generate salt and hash password
    salt = generate_salt()
    pw_hash = hash_password(req.password, salt)
    otp_secret = generate_otp_secret()
    otp_uri = get_totp_uri(otp_secret, req.username)

    await cur.execute(
        """INSERT INTO users (username, email, password_hash, salt, otp_secret, mfa_enabled)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (req.username, req.email, pw_hash, salt, otp_secret, True)
    )

    await log_audit(cur, "REGISTER_SUCCESS", req.username, ip, f"User registered: {req.email}", True)

    return RegisterResponse(
        success=True,
        message="Registration successful. Save your OTP secret for 2FA setup.",
        otp_secret=otp_secret,
        otp_uri=otp_uri,
        username=req.username
    )

@router.post("/challenge")
async def get_challenge(req: ChallengeRequest, request: Request, cur=Depends(get_db)):
    ip = request.client.host if request.client else "unknown"

    await cur.execute("SELECT id, salt FROM users WHERE username = %s AND is_active = 1", (req.username,))
    user = await cur.fetchone()

    challenge_id, nonce = generate_challenge()
    expires_at = datetime.now() + timedelta(minutes=5)

    if user:
        await cur.execute(
            "DELETE FROM auth_challenges WHERE username = %s AND expires_at < NOW()",
            (req.username,)
        )
        await cur.execute(
            """INSERT INTO auth_challenges (challenge_id, username, challenge_nonce, expires_at)
               VALUES (%s, %s, %s, %s)""",
            (challenge_id, req.username, nonce, expires_at)
        )

    await log_audit(cur, "CHALLENGE_ISSUED", req.username, ip, "Auth challenge issued", True)

    return {
        "challenge_id": challenge_id,
        "nonce": nonce,
        "salt": user["salt"] if user else generate_salt(),
        "expires_in": 300
    }

@router.post("/login/step1", response_model=LoginStep1Response)
async def login_step1(req: LoginStep1Request, request: Request, cur=Depends(get_db)):
    ip = request.client.host if request.client else "unknown"

    # Timestamp validation (replay prevention layer 1)
    if not is_timestamp_valid(req.timestamp):
        await log_audit(cur, "LOGIN_FAIL", req.username, ip, "Invalid or expired timestamp", False)
        raise HTTPException(status_code=400, detail="Request timestamp invalid or expired")

    # Replay attack detection (layer 2)
    req_hash = compute_request_hash(req.username, "/login/step1", req.timestamp, req.request_nonce)
    is_replay = await check_replay(cur, req_hash, req.username, "/login/step1", ip)
    if is_replay:
        await log_audit(cur, "REPLAY_DETECTED", req.username, ip, "Replay attack detected on login", False)
        raise HTTPException(status_code=400, detail="Replay attack detected. Request rejected.")

    # Fetch challenge
    await cur.execute(
        """SELECT challenge_nonce, expires_at, used FROM auth_challenges
           WHERE challenge_id = %s AND username = %s""",
        (req.challenge_id, req.username)
    )
    challenge = await cur.fetchone()

    if not challenge:
        await log_audit(cur, "LOGIN_FAIL", req.username, ip, "Invalid challenge ID", False)
        raise HTTPException(status_code=401, detail="Invalid or expired challenge")

    if challenge["used"]:
        await log_audit(cur, "REPLAY_DETECTED", req.username, ip, "Challenge reuse attempt", False)
        raise HTTPException(status_code=400, detail="Challenge already used (replay detected)")

    if datetime.now() > challenge["expires_at"]:
        raise HTTPException(status_code=401, detail="Challenge expired")

    # Mark challenge as used immediately (prevent replay)
    await cur.execute(
        "UPDATE auth_challenges SET used = 1 WHERE challenge_id = %s",
        (req.challenge_id,)
    )

    # Fetch user credentials
    await cur.execute(
        "SELECT id, username, password_hash, salt, mfa_enabled FROM users WHERE username = %s AND is_active = 1",
        (req.username,)
    )
    user = await cur.fetchone()

    if not user:
        await log_audit(cur, "LOGIN_FAIL", req.username, ip, "User not found", False)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Verify challenge response (never transmit password)
    nonce = challenge["challenge_nonce"]
    is_valid = verify_challenge_response(
        user["password_hash"], user["salt"], nonce, req.response
    )

    if not is_valid:
        await log_audit(cur, "LOGIN_FAIL", req.username, ip, "Challenge response mismatch", False)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Issue temporary token for OTP step
    temp_token = generate_session_token()
    temp_hash = hash_token(temp_token)
    expires_at = datetime.now() + timedelta(minutes=5)

    await cur.execute(
        """INSERT INTO sessions (session_token, username, user_id, expires_at, ip_address, is_valid)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (temp_hash, req.username, user["id"], expires_at, ip, False)  # is_valid=False until OTP
    )

    await log_audit(cur, "LOGIN_STEP1_SUCCESS", req.username, ip, "Challenge-response passed", True)

    return LoginStep1Response(
        success=True,
        message="Credentials verified. Please enter your OTP code.",
        temp_token=temp_token,
        requires_otp=user["mfa_enabled"]
    )

@router.post("/login/verify-otp")
async def verify_otp(req: OTPVerifyRequest, request: Request, cur=Depends(get_db)):
    ip = request.client.host if request.client else "unknown"

    # Timestamp validation
    if not is_timestamp_valid(req.timestamp):
        raise HTTPException(status_code=400, detail="Request timestamp invalid or expired")

    # Replay detection
    req_hash = compute_request_hash("otp", "/login/verify-otp", req.timestamp, req.request_nonce)
    is_replay = await check_replay(cur, req_hash, "otp_verify", "/verify-otp", ip)
    if is_replay:
        raise HTTPException(status_code=400, detail="Replay attack detected")

    # Validate temp token
    temp_hash = hash_token(req.temp_token)
    await cur.execute(
        """SELECT s.username, s.user_id, s.expires_at, u.otp_secret
           FROM sessions s
           JOIN users u ON u.id = s.user_id
           WHERE s.session_token = %s AND s.is_valid = 0""",
        (temp_hash,)
    )
    session = await cur.fetchone()

    if not session:
        await log_audit(cur, "OTP_FAIL", None, ip, "Invalid temp token", False)
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if datetime.now() > session["expires_at"]:
        raise HTTPException(status_code=401, detail="Token expired. Please start login again.")

    username = session["username"]

    # OTP replay prevention — hash the OTP + username + timestamp
    otp_hash = hash_token(f"{username}:{req.otp_code}:{int(time.time()) // 30}")
    await cur.execute(
        "SELECT id FROM otp_attempts WHERE otp_hash = %s AND username = %s",
        (otp_hash, username)
    )
    if await cur.fetchone():
        await log_audit(cur, "OTP_REPLAY", username, ip, "OTP reuse detected", False)
        raise HTTPException(status_code=400, detail="OTP already used (replay detected)")

    # Verify TOTP
    if not verify_totp(session["otp_secret"], req.otp_code):
        await log_audit(cur, "OTP_FAIL", username, ip, "Invalid OTP code", False)
        raise HTTPException(status_code=401, detail="Invalid OTP code")

    # Record OTP use to prevent replay
    await cur.execute(
        "INSERT INTO otp_attempts (username, otp_hash, ip_address) VALUES (%s, %s, %s)",
        (username, otp_hash, ip)
    )
    # Clean old OTP records
    await cur.execute(
        "DELETE FROM otp_attempts WHERE created_at < DATE_SUB(NOW(), INTERVAL 2 MINUTE)"
    )

    # Promote temp session to full session
    full_token = generate_session_token()
    full_hash = hash_token(full_token)
    full_expires = datetime.now() + timedelta(hours=8)

    # Invalidate old temp token
    await cur.execute("DELETE FROM sessions WHERE session_token = %s", (temp_hash,))

    # Create full session
    await cur.execute(
        """INSERT INTO sessions (session_token, username, user_id, expires_at, ip_address, is_valid)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (full_hash, username, session["user_id"], full_expires, ip, True)
    )

    # Update last login
    await cur.execute("UPDATE users SET last_login = NOW() WHERE username = %s", (username,))

    await log_audit(cur, "LOGIN_SUCCESS", username, ip, "Full MFA login completed", True)

    return {
        "success": True,
        "message": "Authentication successful",
        "session_token": full_token,
        "username": username,
        "expires_at": full_expires.isoformat()
    }

@router.post("/password-strength")
async def password_strength(req: PasswordStrengthRequest):
    return check_password_strength(req.password)

@router.get("/audit-log")
async def get_audit_log(session_token: str, request: Request, cur=Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    token_hash = hash_token(session_token)
    
    await cur.execute(
        "SELECT username FROM sessions WHERE session_token = %s AND is_valid = 1 AND expires_at > NOW()",
        (token_hash,)
    )
    session = await cur.fetchone()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    await cur.execute(
        """SELECT event_type, username, ip_address, details, success, created_at
           FROM audit_log WHERE username = %s ORDER BY created_at DESC LIMIT 20""",
        (session["username"],)
    )
    logs = await cur.fetchall()
    return {"logs": [dict(l) for l in logs]}