#!/usr/bin/env python3
"""
SecureAuth MFA — Local runner.
Loads .env then starts uvicorn. No Docker needed.
"""
import os, sys
from pathlib import Path

# ── Load .env ─────────────────────────────────────────────────────────────────
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())
    print("✅  Loaded .env")
else:
    print("⚠️   No .env found — using environment variables or defaults")
    print("    Run  setup.sh  first, or set DB_HOST / DB_USER / DB_PASSWORD / DB_NAME manually.\n")

# ── Add backend to path ───────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent / "backend"))

import uvicorn

if __name__ == "__main__":
    print("\n  SecureAuth MFA starting…")
    print("  Frontend → http://localhost:8000")
    print("  API docs → http://localhost:8000/docs\n")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["backend"],
    )
