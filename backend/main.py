from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
from pathlib import Path

from database import init_db, close_db
from routers import auth, session

BASE_DIR = Path(__file__).parent          # backend/
FRONTEND_DIR = BASE_DIR.parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await close_db()

app = FastAPI(
    title="SecureAuth MFA System",
    description="Multi-Factor Authentication with Challenge-Response, TOTP & Replay Prevention",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(session.router, prefix="/api/session", tags=["Session"])

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return HTMLResponse(content=(FRONTEND_DIR / "index.html").read_text(encoding="utf-8"))

@app.get("/simulator", response_class=HTMLResponse)
async def serve_simulator():
    return HTMLResponse(content=(FRONTEND_DIR / "simulator.html").read_text(encoding="utf-8"))

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "SecureAuth MFA"}