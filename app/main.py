from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import get_settings
from app.core.database import engine, Base, SessionLocal
from app.core.security import get_password_hash
from app.models.user import User
from app.api import auth, organizations, projects, scans, users

settings = get_settings()
BASE_DIR = Path(__file__).resolve().parent


def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin = User(
                email="admin@scanner.local",
                hashed_password=get_password_hash("admin123"),
                full_name="Super Admin",
                role="super_admin",
                is_active=True,
            )
            db.add(admin)
            db.commit()
            print("✅ Default Super Admin created: admin@scanner.local / admin123")
    finally:
        db.close()

    Path(settings.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Static Code Scanner",
    description=(
        "Static codebase scanning system – Language detection, System analysis, "
        "Secret/Variables detection, Static Security Audit. "
        "No AI. No external analysis libraries. Pure Python rules."
    ),
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

app.include_router(auth.router)
app.include_router(organizations.router)
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(users.router)


@app.get("/", response_class=HTMLResponse)
def home():
    """Browser UI – upload ZIP and see scan results."""
    html_path = BASE_DIR / "templates" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/api")
def api_info():
    return {
        "name": "Static Code Scanner API",
        "version": "1.0.0",
        "docs": "/docs",
        "ui": "/",
        "features": [
            "JWT Auth (Super Admin → Organization → Projects)",
            "ZIP upload of codebase",
            "Language detection",
            "System / structure analysis",
            "Secret & sensitive variable detection",
            "Static security audit (no AI, no external libs)",
        ],
    }


@app.get("/health")
def health():
    return {"status": "ok"}
