from pathlib import Path
import os

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = PROJECT_ROOT / "frontend"
STORAGE_DIR = Path(os.getenv("SECURESIGN_STORAGE_DIR", str(PROJECT_ROOT / "storage"))).resolve()
DOCUMENT_STORAGE_DIR = STORAGE_DIR / "documents"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{(STORAGE_DIR / 'securesign.db').as_posix()}")
MAX_UPLOAD_BYTES = int(os.getenv("SECURESIGN_MAX_UPLOAD_BYTES", 25 * 1024 * 1024))
SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "12"))
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "securesign_session")
CSRF_COOKIE_NAME = os.getenv("CSRF_COOKIE_NAME", "securesign_csrf")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").lower()
APP_ENV = os.getenv("APP_ENV", "development").lower()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
ALLOWED_ORIGINS = [x.strip().rstrip("/") for x in os.getenv("ALLOWED_ORIGINS", "").split(",") if x.strip()]
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
ADMIN_RESET_PASSWORD = os.getenv("ADMIN_RESET_PASSWORD", "false").lower() == "true"
ADMIN_NAME = os.getenv("ADMIN_NAME", "SecureSign Administrator").strip()
REQUIRE_EMAIL_VERIFICATION = os.getenv("REQUIRE_EMAIL_VERIFICATION", "true" if APP_ENV == "production" else "false").lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "").strip()
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "true").lower() == "true"

STORAGE_DIR.mkdir(parents=True, exist_ok=True)
DOCUMENT_STORAGE_DIR.mkdir(parents=True, exist_ok=True)

if COOKIE_SAMESITE not in {"lax", "strict", "none"}:
    COOKIE_SAMESITE = "lax"
if COOKIE_SAMESITE == "none" and not COOKIE_SECURE:
    raise RuntimeError("COOKIE_SAMESITE=none requires COOKIE_SECURE=true")
if APP_ENV == "production" and not COOKIE_SECURE:
    raise RuntimeError("COOKIE_SECURE must be true when APP_ENV=production")
if APP_ENV == "production" and len(ADMIN_PASSWORD) < 16:
    raise RuntimeError("ADMIN_PASSWORD must contain at least 16 characters in production")
if APP_ENV == "production" and not REQUIRE_EMAIL_VERIFICATION:
    raise RuntimeError("REQUIRE_EMAIL_VERIFICATION must be true in production")
if REQUIRE_EMAIL_VERIFICATION and (not SMTP_HOST or not SMTP_FROM or not PUBLIC_BASE_URL):
    raise RuntimeError("Email verification is required but SMTP_HOST, SMTP_FROM and PUBLIC_BASE_URL are not configured")
if APP_ENV == "production" and not PUBLIC_BASE_URL.startswith("https://"):
    raise RuntimeError("PUBLIC_BASE_URL must use HTTPS in production")
if APP_ENV == "production" and not SMTP_STARTTLS:
    raise RuntimeError("SMTP_STARTTLS must be true in production")
