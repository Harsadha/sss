from fastapi import APIRouter, HTTPException, Request, Depends, Header
from datetime import datetime
from typing import Optional
from database import get_db
from security import hash_token
from schemas import LogoutRequest

router = APIRouter()

async def get_current_session(
    authorization: Optional[str] = Header(None),
    cur=Depends(get_db)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    token_hash = hash_token(token)
    
    await cur.execute(
        """SELECT s.*, u.email FROM sessions s
           JOIN users u ON u.username = s.username
           WHERE s.session_token = %s AND s.is_valid = 1 AND s.expires_at > NOW()""",
        (token_hash,)
    )
    session = await cur.fetchone()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    # Update last activity
    await cur.execute(
        "UPDATE sessions SET last_activity = NOW() WHERE session_token = %s",
        (token_hash,)
    )
    return dict(session)

@router.get("/me")
async def get_me(session=Depends(get_current_session)):
    return {
        "username": session["username"],
        "email": session["email"],
        "created_at": session["created_at"].isoformat() if session["created_at"] else None,
        "last_activity": session["last_activity"].isoformat() if session["last_activity"] else None,
        "ip_address": session["ip_address"],
        "session_expires": session["expires_at"].isoformat() if session["expires_at"] else None
    }

@router.post("/logout")
async def logout(req: LogoutRequest, cur=Depends(get_db)):
    token_hash = hash_token(req.session_token)
    await cur.execute(
        "UPDATE sessions SET is_valid = 0 WHERE session_token = %s",
        (token_hash,)
    )
    return {"success": True, "message": "Logged out successfully"}

@router.get("/validate")
async def validate_session(authorization: Optional[str] = Header(None), cur=Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        return {"valid": False}
    
    token = authorization.replace("Bearer ", "")
    token_hash = hash_token(token)
    
    await cur.execute(
        "SELECT username, expires_at FROM sessions WHERE session_token = %s AND is_valid = 1 AND expires_at > NOW()",
        (token_hash,)
    )
    session = await cur.fetchone()
    if not session:
        return {"valid": False}
    
    return {
        "valid": True,
        "username": session["username"],
        "expires_at": session["expires_at"].isoformat()
    }

@router.get("/stats")
async def get_security_stats(session=Depends(get_current_session), cur=Depends(get_db)):
    username = session["username"]
    
    # Login success count
    await cur.execute(
        "SELECT COUNT(*) as cnt FROM audit_log WHERE username = %s AND event_type = 'LOGIN_SUCCESS'",
        (username,)
    )
    logins = (await cur.fetchone())["cnt"]
    
    # Failed attempts
    await cur.execute(
        "SELECT COUNT(*) as cnt FROM audit_log WHERE username = %s AND success = 0 AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
        (username,)
    )
    failures = (await cur.fetchone())["cnt"]
    
    # Replay attempts
    await cur.execute(
        "SELECT COUNT(*) as cnt FROM audit_log WHERE username = %s AND event_type IN ('REPLAY_DETECTED', 'OTP_REPLAY')",
        (username,)
    )
    replays = (await cur.fetchone())["cnt"]

    # Recent audit
    await cur.execute(
        "SELECT event_type, success, created_at, ip_address FROM audit_log WHERE username = %s ORDER BY created_at DESC LIMIT 10",
        (username,)
    )
    recent = await cur.fetchall()

    return {
        "total_logins": logins,
        "failed_attempts_24h": failures,
        "replay_attempts_blocked": replays,
        "recent_events": [
            {**dict(r), "created_at": r["created_at"].isoformat()}
            for r in recent
        ]
    }
