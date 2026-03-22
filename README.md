# SecureAuth — Multi-Factor Authentication System

A production-grade MFA system built with **FastAPI + MySQL** and a dark cyberpunk frontend.  
No Docker required — runs directly on your machine.

---

## Quick Start

### Prerequisites
- Python 3.10+
- MySQL 8.x running locally

### 1. Run the setup wizard
```bash
chmod +x setup.sh
./setup.sh
```
This will prompt for MySQL credentials, create the database, create a `.venv`, install dependencies, and write a `.env` file.

### 2. Start the server
```bash
source .venv/bin/activate
python run.py
```

### 3. Open in browser
```
http://localhost:8000          ← App
http://localhost:8000/docs     ← Swagger API docs
```

---

## Manual Setup (no wizard)

```bash
# 1. Create MySQL database
mysql -u root -p -e "CREATE DATABASE secureauth_db CHARACTER SET utf8mb4;"

# 2. Write .env
cat > .env <<EOF
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=secureauth_db
EOF

# 3. Install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

# 4. Run
python run.py
```

---

## Project Structure

```
mfa_app/
├── run.py               ← Start the server (loads .env, launches uvicorn)
├── setup.sh             ← One-time setup wizard
├── .env                 ← DB credentials (created by setup.sh)
├── backend/
│   ├── main.py          ← FastAPI app + static file serving
│   ├── database.py      ← MySQL connection pool + table creation
│   ├── security.py      ← All cryptography (PBKDF2, TOTP, HMAC, tokens)
│   ├── schemas.py       ← Pydantic request/response models
│   ├── requirements.txt
│   └── routers/
│       ├── auth.py      ← Register, challenge, login step1+2, OTP verify
│       └── session.py   ← Session validate, /me, stats, logout
└── frontend/
    └── index.html       ← Single-page app (no build step needed)
```

---

## Security Architecture

| Requirement | Implementation |
|---|---|
| Salted password storage | PBKDF2-HMAC-SHA256, 310,000 iterations, 32-byte random salt |
| Challenge-response auth | HMAC-SHA256(H(password), server_nonce) — password never transmitted |
| OTP second factor | RFC 6238 TOTP, 30s window, +-1 step drift tolerance |
| Session tokens | 64-byte secrets.token_urlsafe, stored as SHA-256 hashes |
| Replay prevention (requests) | Per-request nonce + Unix timestamp hash stored in replay_log |
| Replay prevention (challenges) | One-time use — marked used=1 before response verification |
| Replay prevention (OTP) | hash(username+code+time_window) stored; reuse blocked |
| Audit trail | Every auth event logged: type, username, IP, outcome, timestamp |

## OTP Setup

After registering, copy your TOTP secret into any authenticator app:
Google Authenticator, Authy, Microsoft Authenticator, Bitwarden, or 1Password.
Use the "enter key manually" option if no QR scanner is available.
# sss
