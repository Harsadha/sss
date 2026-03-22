import aiomysql
import os
from typing import Optional
import asyncio

# Database configuration - update these with your MySQL credentials
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "password"),
    "db": os.getenv("DB_NAME", "secureauth_db"),
    "autocommit": True,
    "charset": "utf8mb4",
}

pool: Optional[aiomysql.Pool] = None

async def init_db():
    global pool
    # First connect without db to create it if needed
    conn_config = {k: v for k, v in DB_CONFIG.items() if k != "db"}
    conn = await aiomysql.connect(**conn_config)
    async with conn.cursor() as cur:
        await cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_CONFIG['db']}`")
    conn.close()

    pool = await aiomysql.create_pool(**DB_CONFIG, minsize=2, maxsize=10)
    await create_tables()
    print("✅ Database initialized successfully")

async def close_db():
    global pool
    if pool:
        pool.close()
        await pool.wait_closed()

async def get_db():
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            yield cur

async def create_tables():
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            # Disable strict mode for this session to avoid TIMESTAMP issues
            await cur.execute("SET SESSION sql_mode = ''")

            # Users table
            await cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    salt VARCHAR(64) NOT NULL,
                    otp_secret VARCHAR(64),
                    is_active TINYINT(1) DEFAULT 1,
                    mfa_enabled TINYINT(1) DEFAULT 1,
                    created_at DATETIME DEFAULT NOW(),
                    last_login DATETIME NULL DEFAULT NULL,
                    INDEX idx_username (username),
                    INDEX idx_email (email)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)

            # Challenges table (for challenge-response auth)
            await cur.execute("""
                CREATE TABLE IF NOT EXISTS auth_challenges (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    challenge_id VARCHAR(64) UNIQUE NOT NULL,
                    username VARCHAR(100) NOT NULL,
                    challenge_nonce VARCHAR(128) NOT NULL,
                    created_at DATETIME DEFAULT NOW(),
                    expires_at DATETIME NOT NULL,
                    used TINYINT(1) DEFAULT 0,
                    INDEX idx_challenge_id (challenge_id),
                    INDEX idx_username_challenge (username)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)

            # OTP attempts table
            await cur.execute("""
                CREATE TABLE IF NOT EXISTS otp_attempts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    otp_hash VARCHAR(128) NOT NULL,
                    created_at DATETIME DEFAULT NOW(),
                    ip_address VARCHAR(45),
                    INDEX idx_otp_username (username),
                    INDEX idx_otp_hash (otp_hash)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)

            # Sessions table
            await cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    session_token VARCHAR(256) UNIQUE NOT NULL,
                    username VARCHAR(100) NOT NULL,
                    user_id INT NOT NULL,
                    created_at DATETIME DEFAULT NOW(),
                    expires_at DATETIME NOT NULL,
                    last_activity DATETIME DEFAULT NOW(),
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    is_valid TINYINT(1) DEFAULT 1,
                    INDEX idx_token (session_token),
                    INDEX idx_session_user (username)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)

            # Replay attack log
            await cur.execute("""
                CREATE TABLE IF NOT EXISTS replay_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    request_hash VARCHAR(128) UNIQUE NOT NULL,
                    username VARCHAR(100),
                    endpoint VARCHAR(255),
                    created_at DATETIME DEFAULT NOW(),
                    ip_address VARCHAR(45),
                    INDEX idx_request_hash (request_hash),
                    INDEX idx_replay_time (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)

            # Audit log
            await cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    event_type VARCHAR(50) NOT NULL,
                    username VARCHAR(100),
                    ip_address VARCHAR(45),
                    details TEXT,
                    success TINYINT(1),
                    created_at DATETIME DEFAULT NOW(),
                    INDEX idx_audit_user (username),
                    INDEX idx_audit_event (event_type)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)

            await conn.commit()
            print("✅ All tables created/verified")