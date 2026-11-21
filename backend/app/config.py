from pathlib import Path
import os

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = PROJECT_ROOT / "frontend"
STORAGE_DIR = Path(os.getenv("SECURESIGN_STORAGE_DIR", str(PROJECT_ROOT / "storage"))).resolve()
DOCUMENT_STORAGE_DIR = STORAGE_DIR / "documents"

APP_ENV = os.getenv("APP_ENV", "development").lower()
IS_VERCEL = os.getenv("VERCEL", "").lower() in {"1", "true"}
STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "vercel_blob" if IS_VERCEL else "local").lower()
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{(STORAGE_DIR / 'securesign.db').as_posix()}")
# Vercel Functions accept at most 4.5 MiB for the complete request body.
# Keep PDF uploads at 4 MiB to leave room for multipart boundaries and metadata.
MAX_UPLOAD_BYTES = int(os.getenv("SECURESIGN_MAX_UPLOAD_BYTES", 4 * 1024 * 1024))
if MAX_UPLOAD_BYTES <= 0:
    raise RuntimeError("SECURESIGN_MAX_UPLOAD_BYTES must be a positive integer")
if (IS_VERCEL or STORAGE_BACKEND == "vercel_blob") and MAX_UPLOAD_BYTES > 4 * 1024 * 1024:
    raise RuntimeError("Vercel upload limit cannot exceed 4 MiB with the current server-upload flow")
SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "12"))
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "securesign_session")
CSRF_COOKIE_NAME = os.getenv("CSRF_COOKIE_NAME", "securesign_csrf")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").lower()
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
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
# Only trust X-Forwarded-For when a reverse proxy that overwrites it sits in front
# of the app (Vercel, or Caddy in docker-compose). Otherwise clients can spoof it.
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "true" if IS_VERCEL else "false").lower() == "true"
# Security Lab: the attack/defense demonstration used in the course report.
# On by default for local development, off by default in production.
LAB_ENABLED = os.getenv("SECURESIGN_LAB_ENABLED", "false" if APP_ENV == "production" else "true").lower() == "true"
# Demo accounts (admin/alice/bob/charlie, see README) so the app can be tested without registering.
# Their passwords are public, so they are on by default only outside production.
DEMO_ACCOUNTS = os.getenv("SECURESIGN_DEMO_ACCOUNTS", "false" if APP_ENV == "production" else "true").lower() == "true"
UPSTASH_REDIS_REST_URL = os.getenv("UPSTASH_REDIS_REST_URL", "").strip().rstrip("/")
UPSTASH_REDIS_REST_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "").strip()

# Vercel's function filesystem is ephemeral/read-only. Never create storage
# directories there; document bytes live in a private Vercel Blob store.
if STORAGE_BACKEND == "local":
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    DOCUMENT_STORAGE_DIR.mkdir(parents=True, exist_ok=True)

if STORAGE_BACKEND not in {"local", "vercel_blob"}:
    raise RuntimeError("STORAGE_BACKEND must be 'local' or 'vercel_blob'.")
if COOKIE_SAMESITE not in {"lax", "strict", "none"}:
    COOKIE_SAMESITE = "lax"
if COOKIE_SAMESITE == "none" and not COOKIE_SECURE:
    raise RuntimeError("COOKIE_SAMESITE=none requires COOKIE_SECURE=true")
if APP_ENV == "production" and not COOKIE_SECURE:
    raise RuntimeError("COOKIE_SECURE must be true when APP_ENV=production")
if APP_ENV == "production" and DEMO_ACCOUNTS:
    raise RuntimeError("Demo accounts have public passwords and must not be enabled in production")
if APP_ENV == "production" and len(ADMIN_PASSWORD) < 16:
    raise RuntimeError("ADMIN_PASSWORD must contain at least 16 characters in production")
if APP_ENV == "production" and not REQUIRE_EMAIL_VERIFICATION:
    raise RuntimeError("REQUIRE_EMAIL_VERIFICATION must be true in production")
if REQUIRE_EMAIL_VERIFICATION and (not SMTP_FROM or not (RESEND_API_KEY or SMTP_HOST) or not PUBLIC_BASE_URL):
    raise RuntimeError("Email verification requires SMTP_FROM, RESEND_API_KEY or SMTP_HOST, and PUBLIC_BASE_URL")
if APP_ENV == "production" and not PUBLIC_BASE_URL.startswith("https://"):
    raise RuntimeError("PUBLIC_BASE_URL must use HTTPS in production")
if APP_ENV == "production" and SMTP_HOST and not RESEND_API_KEY and not SMTP_STARTTLS:
    raise RuntimeError("SMTP_STARTTLS must be true in production when using SMTP")
if APP_ENV == "production" and DATABASE_URL.startswith("sqlite"):
    raise RuntimeError("Production requires a persistent PostgreSQL DATABASE_URL")
if APP_ENV == "production" and IS_VERCEL and STORAGE_BACKEND != "vercel_blob":
    raise RuntimeError("Vercel production requires STORAGE_BACKEND=vercel_blob")
if APP_ENV == "production" and STORAGE_BACKEND == "vercel_blob":
    if not (os.getenv("BLOB_STORE_ID") or os.getenv("BLOB_READ_WRITE_TOKEN") or os.getenv("VERCEL_BLOB_READ_WRITE_TOKEN")):
        raise RuntimeError("Connect a private Vercel Blob store or configure its read-write token")
if APP_ENV == "production" and STORAGE_BACKEND == "vercel_blob" and not (UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN):
    raise RuntimeError("Production requires UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN for shared rate limiting")
