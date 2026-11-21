from pathlib import Path
from contextlib import asynccontextmanager
from datetime import timedelta
import base64
import hashlib
import secrets
import time
import uuid
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, or_, select, text, update
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import (
    ALLOWED_ORIGINS, APP_ENV, COOKIE_SECURE, CSRF_COOKIE_NAME,
    FRONTEND_DIR, MAX_UPLOAD_BYTES, PUBLIC_BASE_URL, REQUIRE_EMAIL_VERIFICATION,
    RESEND_API_KEY, SMTP_FROM, SMTP_HOST,
    UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN,
)
from .crypto_service import load_public_key, public_key_fingerprint, verify_signature
from .database import (
    AuditLog, Document, EmailToken, KeyChallenge, PublicKey, TrustedKey, User, UserSession,
    add_audit, get_db, init_db, utc_now,
)
from .schemas import (
    AdminUserUpdate, ForgotPasswordRequest, LoginRequest, RegisterKeyRequest,
    RegisterRequest, ResendVerificationRequest, ResetPasswordRequest,
)
from .email_service import send_email
from .storage_service import delete_file, read_file, save_file, storage_status
from .security import (
    clear_session_cookies, get_current_user, hash_password, issue_session,
    require_admin, require_csrf, user_payload, verify_password,
)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="SecureSign Cloud API",
    description="Multi-user PDF digital signature platform using RSA-PSS and SHA-256.",
    version="2.1.0",
    docs_url=None if APP_ENV == "production" else "/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)

# Shared Upstash rate limits are used on Vercel; the in-memory fallback is local-only.
_RATE_RULES = {
    "/api/auth/login": (10, 15 * 60),
    "/api/auth/register": (5, 60 * 60),
    "/api/verify": (30, 60),
    "/api/documents/send": (20, 60 * 60),
    "/api/keys/challenge": (20, 60 * 60),
    "/api/auth/resend-verification": (5, 60 * 60),
    "/api/auth/forgot-password": (5, 15 * 60),
}
_RATE_BUCKETS: dict[str, tuple[float, int]] = {}


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    rule = _RATE_RULES.get(request.url.path)
    if rule and request.method == "POST":
        limit, window = rule
        forwarded = request.headers.get("x-forwarded-for", "")
        # The left-most X-Forwarded-For entry is the original client address.
        client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
        bucket_key = f"{request.url.path}:{hashlib.sha256(client_ip.encode()).hexdigest()[:24]}"
        retry_after = window
        if UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN:
            try:
                import httpx
                redis_key = f"securesign:rate:{hashlib.sha256(bucket_key.encode()).hexdigest()}"
                async with httpx.AsyncClient(timeout=3.0) as client:
                    redis_response = await client.post(
                        f"{UPSTASH_REDIS_REST_URL}/pipeline",
                        headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"},
                        json=[["INCR", redis_key], ["EXPIRE", redis_key, window, "NX"], ["TTL", redis_key]],
                    )
                redis_response.raise_for_status()
                redis_results = redis_response.json()
                if any(item.get("error") for item in redis_results):
                    raise RuntimeError("Upstash rate-limit command failed")
                count = int(redis_results[0]["result"])
                ttl = redis_results[2].get("result")
                if ttl is None or int(ttl) < 0:
                    raise RuntimeError("Upstash rate-limit TTL was not set")
                retry_after = max(1, int(ttl))
            except Exception:
                # Fail closed: an unavailable shared limiter must not silently
                # turn public authentication endpoints into unlimited endpoints.
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=503, content={"detail": "Dịch vụ kiểm soát tần suất tạm thời không khả dụng. Vui lòng thử lại."})
        else:
            # Local-development fallback only. Production config requires Upstash.
            now = time.monotonic()
            started, count = _RATE_BUCKETS.get(bucket_key, (now, 0))
            if now - started >= window:
                started, count = now, 0
            count += 1
            retry_after = max(1, int(window - (now - started)))
            _RATE_BUCKETS[bucket_key] = (started, count)
            if len(_RATE_BUCKETS) > 10000:
                expired = [k for k, (t, _) in _RATE_BUCKETS.items() if now - t > 3600]
                for key in expired:
                    _RATE_BUCKETS.pop(key, None)
        if count > limit:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=429, content={"detail": "Bạn thao tác quá nhanh. Vui lòng thử lại sau."}, headers={"Retry-After": str(retry_after)})
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        if origin:
            allowed = set(ALLOWED_ORIGINS)
            if PUBLIC_BASE_URL:
                allowed.add(PUBLIC_BASE_URL)
            if not allowed:
                host = request.headers.get("host", "")
                expected = f"{request.url.scheme}://{host}".rstrip("/")
                allowed.add(expected)
            if origin.rstrip("/") not in allowed:
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=403, content={"detail": "Origin không được phép."})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    if request.url.path == "/api/docs" and APP_ENV != "production":
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    response.headers["Content-Security-Policy"] = csp
    if COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def home():
    return FileResponse(FRONTEND_DIR / "index.html")


def _iso(value):
    return value.isoformat() + "Z" if value else None


def _create_email_token(db: Session, user: User, purpose: str, ttl: timedelta) -> str:
    token = secrets.token_urlsafe(36)
    db.add(EmailToken(
        user_id=user.id,
        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        purpose=purpose,
        expires_at=utc_now() + ttl,
    ))
    return token


def _send_verification_email(user: User, token: str):
    link = f"{PUBLIC_BASE_URL}/api/auth/verify-email?token={quote(token)}"
    send_email(
        user.email,
        "Xác minh tài khoản SecureSign",
        f"Xin chào {user.full_name},\n\nVui lòng mở liên kết sau để xác minh email và kích hoạt tài khoản SecureSign (liên kết có hiệu lực 24 giờ):\n{link}\n\nNếu bạn không tạo tài khoản này, hãy bỏ qua email.",
    )


def _send_password_reset_email(user: User, token: str):
    link = f"{PUBLIC_BASE_URL}/?reset_token={quote(token)}"
    send_email(
        user.email,
        "Đặt lại mật khẩu SecureSign",
        f"Xin chào {user.full_name},\n\nMở liên kết sau để đặt lại mật khẩu (liên kết có hiệu lực 30 phút):\n{link}\n\nNếu bạn không yêu cầu thao tác này, hãy bỏ qua email.",
    )


def _validate_pdf(filename: str | None, data: bytes):
    safe_name = Path(filename or "document.pdf").name
    if not safe_name.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Tệp tài liệu phải có đuôi .pdf.")
    if not data:
        raise HTTPException(status_code=400, detail="Tệp PDF rỗng.")
    if len(data) > MAX_UPLOAD_BYTES:
        limit_mib = max(1, MAX_UPLOAD_BYTES // (1024 * 1024))
        raise HTTPException(status_code=413, detail=f"PDF vượt quá giới hạn {limit_mib} MiB.")
    if not data.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="Tệp tải lên không có chữ ký định dạng PDF hợp lệ.")
    return safe_name


async def _read_pdf(upload: UploadFile):
    data = await upload.read(MAX_UPLOAD_BYTES + 1)
    name = _validate_pdf(upload.filename, data)
    return name, data


async def _read_signature(upload: UploadFile):
    data = await upload.read(4097)
    if len(data) < 256 or len(data) > 4096:
        raise HTTPException(status_code=400, detail="Tệp chữ ký có kích thước không hợp lệ.")
    return data


def _key_payload(key: PublicKey, owner: User, trusted: bool = False):
    return {
        "id": key.id,
        "name": key.name,
        "fingerprint": key.fingerprint,
        "key_size": key.key_size,
        "status": key.status,
        "created_at": _iso(key.created_at),
        "owner_id": owner.id,
        "owner_name": owner.full_name,
        "owner_email": owner.email,
        "is_mine": key.owner_id == owner.id,
        "trusted": trusted,
    }


def _document_payload(db: Session, document: Document, viewer_id: str):
    sender = db.get(User, document.sender_id)
    recipient = db.get(User, document.recipient_id)
    key = db.get(PublicKey, document.key_id)
    return {
        "id": document.id,
        "file_name": document.file_name,
        "sha256": document.sha256,
        "message": document.message,
        "verification_status": document.verification_status,
        "created_at": _iso(document.created_at),
        "verified_at": _iso(document.verified_at),
        "sender": {"id": sender.id, "name": sender.full_name, "email": sender.email} if sender else None,
        "recipient": {"id": recipient.id, "name": recipient.full_name, "email": recipient.email} if recipient else None,
        "key": {"id": key.id, "name": key.name, "fingerprint": key.fingerprint, "status": key.status} if key else None,
        "direction": "sent" if document.sender_id == viewer_id else "received",
    }


def _require_document_access(db: Session, document_id: str, user_id: str):
    document = db.get(Document, document_id)
    if not document or user_id not in {document.sender_id, document.recipient_id}:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài liệu hoặc bạn không có quyền truy cập.")
    return document


@app.get("/api/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(status_code=503, detail="Database chưa sẵn sàng.")
    return {
        "status": "ok",
        "database": "ok",
        "storage": storage_status(),
        "rate_limit": "upstash" if UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN else "local-dev-only",
        "service": "SecureSign Cloud",
        "version": "2.1.0",
    }


# --------------------------- Authentication ---------------------------

@app.post("/api/auth/register")
def register(payload: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    email = str(payload.email).lower().strip()
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email này đã được đăng ký.")
    status_value = "pending_verification" if REQUIRE_EMAIL_VERIFICATION else "active"
    user = User(email=email, full_name=payload.full_name, password_hash=hash_password(payload.password), role="user", status=status_value)
    db.add(user)
    try:
        db.flush()
        add_audit(db, user.id, "ACCOUNT_REGISTERED", "user", user.id, details="Tài khoản tự đăng ký.")
        if REQUIRE_EMAIL_VERIFICATION:
            verification_token = _create_email_token(db, user, "verify_email", timedelta(hours=24))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email này đã được đăng ký.")
    if REQUIRE_EMAIL_VERIFICATION:
        try:
            _send_verification_email(user, verification_token)
        except Exception:
            raise HTTPException(status_code=503, detail="Tài khoản đã được tạo nhưng chưa gửi được email xác minh. Hãy thử gửi lại email sau.")
        return {"message": "Tài khoản đã được tạo. Hãy mở email để xác minh trước khi đăng nhập.", "requires_email_verification": True}
    csrf = issue_session(response, db, user, request)
    return {"message": "Đăng ký thành công.", "user": user_payload(user), "csrf_token": csrf}


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    email = str(payload.email).lower().strip()
    user = db.scalar(select(User).where(User.email == email))
    if not user or not verify_password(user.password_hash, payload.password):
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không chính xác.")
    if user.status == "pending_verification":
        raise HTTPException(status_code=403, detail="Email chưa được xác minh. Hãy mở email xác minh hoặc yêu cầu gửi lại.")
    if user.status != "active":
        raise HTTPException(status_code=403, detail="Tài khoản đã bị tạm khóa. Hãy liên hệ quản trị viên.")
    user.last_login_at = utc_now()
    add_audit(db, user.id, "LOGIN", "user", user.id)
    db.commit()
    csrf = issue_session(response, db, user, request)
    return {"message": "Đăng nhập thành công.", "user": user_payload(user), "csrf_token": csrf}


@app.get("/api/auth/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    record = db.scalar(select(EmailToken).where(
        EmailToken.token_hash == digest,
        EmailToken.purpose == "verify_email",
        EmailToken.used_at.is_(None),
        EmailToken.expires_at > utc_now(),
    ))
    if not record:
        return RedirectResponse(url="/?verify_error=1", status_code=303)
    user = db.get(User, record.user_id)
    if not user or user.status != "pending_verification":
        return RedirectResponse(url="/?verify_error=1", status_code=303)
    record.used_at = utc_now()
    db.execute(update(EmailToken).where(EmailToken.user_id == user.id, EmailToken.purpose == "verify_email", EmailToken.used_at.is_(None)).values(used_at=utc_now()))
    user.status = "active"
    user.email_verified_at = utc_now()
    add_audit(db, user.id, "EMAIL_VERIFIED", "user", user.id)
    db.commit()
    return RedirectResponse(url="/?verified=1", status_code=303)


@app.post("/api/auth/resend-verification")
def resend_verification(payload: ResendVerificationRequest, db: Session = Depends(get_db)):
    email = str(payload.email).lower().strip()
    user = db.scalar(select(User).where(User.email == email))
    if user and user.status == "pending_verification":
        db.execute(update(EmailToken).where(EmailToken.user_id == user.id, EmailToken.purpose == "verify_email", EmailToken.used_at.is_(None)).values(used_at=utc_now()))
        token = _create_email_token(db, user, "verify_email", timedelta(hours=24))
        db.commit()
        try:
            _send_verification_email(user, token)
        except Exception:
            raise HTTPException(status_code=503, detail="Chưa gửi được email. Vui lòng thử lại sau.")
    return {"message": "Nếu tài khoản cần xác minh, email hướng dẫn sẽ được gửi đến hộp thư đã đăng ký."}


@app.post("/api/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    email = str(payload.email).lower().strip()
    user = db.scalar(select(User).where(User.email == email, User.status == "active"))
    if user and (SMTP_HOST or RESEND_API_KEY) and SMTP_FROM and PUBLIC_BASE_URL:
        db.execute(update(EmailToken).where(EmailToken.user_id == user.id, EmailToken.purpose == "password_reset", EmailToken.used_at.is_(None)).values(used_at=utc_now()))
        token = _create_email_token(db, user, "password_reset", timedelta(minutes=30))
        db.commit()
        try:
            _send_password_reset_email(user, token)
        except Exception:
            raise HTTPException(status_code=503, detail="Chưa gửi được email đặt lại mật khẩu. Vui lòng thử lại sau.")
    return {"message": "Nếu email tồn tại và tài khoản đang hoạt động, hướng dẫn đặt lại mật khẩu sẽ được gửi đến hộp thư."}


@app.post("/api/auth/reset-password")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    digest = hashlib.sha256(payload.token.encode("utf-8")).hexdigest()
    record = db.scalar(select(EmailToken).where(
        EmailToken.token_hash == digest,
        EmailToken.purpose == "password_reset",
        EmailToken.used_at.is_(None),
        EmailToken.expires_at > utc_now(),
    ))
    if not record:
        raise HTTPException(status_code=400, detail="Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.")
    user = db.get(User, record.user_id)
    if not user or user.status != "active":
        raise HTTPException(status_code=400, detail="Không thể đặt lại mật khẩu cho tài khoản này.")
    user.password_hash = hash_password(payload.new_password)
    record.used_at = utc_now()
    sessions = db.scalars(select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))).all()
    for session in sessions:
        session.revoked_at = utc_now()
    add_audit(db, user.id, "PASSWORD_RESET", "user", user.id)
    db.commit()
    return {"message": "Đã đặt lại mật khẩu. Hãy đăng nhập bằng mật khẩu mới."}


@app.get("/api/auth/me")
def auth_me(user: User = Depends(get_current_user)):
    return {"user": user_payload(user)}


@app.get("/api/auth/csrf")
def auth_csrf(request: Request, user: User = Depends(get_current_user)):
    token = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not token:
        raise HTTPException(status_code=403, detail="Không tìm thấy CSRF token. Hãy đăng nhập lại.")
    return {"csrf_token": token}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, user: User = Depends(require_csrf), db: Session = Depends(get_db)):
    session = getattr(request.state, "auth_session", None)
    if session:
        session.revoked_at = utc_now()
        add_audit(db, user.id, "LOGOUT", "user", user.id)
        db.commit()
    clear_session_cookies(response)
    return {"message": "Đã đăng xuất."}


@app.post("/api/auth/logout-all")
def logout_all(response: Response, user: User = Depends(require_csrf), db: Session = Depends(get_db)):
    sessions = db.scalars(select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))).all()
    now = utc_now()
    for item in sessions:
        item.revoked_at = now
    add_audit(db, user.id, "LOGOUT_ALL", "user", user.id)
    db.commit()
    clear_session_cookies(response)
    return {"message": "Đã đăng xuất khỏi tất cả thiết bị."}


# --------------------------- Dashboard ---------------------------

@app.get("/api/dashboard")
def dashboard(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sign_count = db.scalar(select(func.count(AuditLog.id)).where(AuditLog.actor_id == user.id, AuditLog.event_type == "SIGN")) or 0
    verify_count = db.scalar(select(func.count(AuditLog.id)).where(AuditLog.actor_id == user.id, AuditLog.event_type == "VERIFY", AuditLog.result == "VALID")) or 0
    key_count = db.scalar(select(func.count(PublicKey.id)).where(PublicKey.owner_id == user.id, PublicKey.status == "active")) or 0
    inbox_count = db.scalar(select(func.count(Document.id)).where(Document.recipient_id == user.id)) or 0
    sent_count = db.scalar(select(func.count(Document.id)).where(Document.sender_id == user.id)) or 0
    return {"sign_count": sign_count, "valid_count": verify_count, "key_count": key_count, "inbox_count": inbox_count, "sent_count": sent_count}


# --------------------------- Public key management ---------------------------

@app.post("/api/keys/challenge")
def create_key_challenge(user: User = Depends(require_csrf), db: Session = Depends(get_db)):
    challenge = secrets.token_urlsafe(32)
    record = KeyChallenge(
        user_id=user.id,
        challenge_hash=hashlib.sha256(challenge.encode("utf-8")).hexdigest(),
        challenge_value=challenge,
        expires_at=utc_now() + timedelta(minutes=5),
    )
    db.add(record)
    db.commit()
    return {"challenge_id": record.id, "challenge": challenge, "expires_in_seconds": 300}


@app.post("/api/keys")
def register_key(payload: RegisterKeyRequest, user: User = Depends(require_csrf), db: Session = Depends(get_db)):
    try:
        public_key = load_public_key(payload.public_key_pem.encode("utf-8"))
        fingerprint = public_key_fingerprint(public_key)
        challenge = db.scalar(select(KeyChallenge).where(
            KeyChallenge.id == payload.challenge_id,
            KeyChallenge.user_id == user.id,
            KeyChallenge.used_at.is_(None),
            KeyChallenge.expires_at > utc_now(),
        ))
        if not challenge:
            raise HTTPException(status_code=400, detail="Challenge không hợp lệ, đã hết hạn hoặc đã được sử dụng.")
        if hashlib.sha256(challenge.challenge_value.encode("utf-8")).hexdigest() != challenge.challenge_hash:
            raise HTTPException(status_code=400, detail="Challenge không hợp lệ.")
        try:
            proof = base64.b64decode(payload.proof_signature, validate=True)
            public_key.verify(
                proof,
                challenge.challenge_value.encode("utf-8"),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        except (ValueError, InvalidSignature):
            raise HTTPException(status_code=400, detail="Không chứng minh được quyền sở hữu Private Key.")
        challenge.used_at = utc_now()
        existing = db.scalar(select(PublicKey).where(PublicKey.fingerprint == fingerprint))
        if existing and existing.owner_id != user.id:
            raise HTTPException(status_code=409, detail="Khóa này đã được đăng ký bởi một tài khoản khác.")
        if existing:
            if existing.status == "revoked":
                raise HTTPException(status_code=409, detail="Khóa này đã bị thu hồi. Hãy tạo cặp khóa mới.")
            existing.name = payload.name.strip()
            existing.public_key_pem = payload.public_key_pem
            db.commit()
            key = existing
        else:
            key = PublicKey(owner_id=user.id, name=payload.name.strip(), fingerprint=fingerprint, public_key_pem=payload.public_key_pem, key_size=public_key.key_size, status="active")
            db.add(key)
            add_audit(db, user.id, "KEY_REGISTERED", "public_key", key.id, fingerprint=fingerprint)
            db.commit()
        return {"message": "Đã đăng ký Public Key vào tài khoản.", "item": {"id": key.id, "name": key.name, "fingerprint": key.fingerprint, "key_size": key.key_size, "status": key.status}}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Public Key không hợp lệ: {exc}")


@app.get("/api/keys/mine")
def list_my_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    keys = db.scalars(select(PublicKey).where(PublicKey.owner_id == user.id).order_by(PublicKey.created_at.desc())).all()
    return {"items": [{"id": k.id, "name": k.name, "fingerprint": k.fingerprint, "key_size": k.key_size, "status": k.status, "created_at": _iso(k.created_at)} for k in keys]}


@app.get("/api/keys/directory")
def key_directory(user: User = Depends(get_current_user), db: Session = Depends(get_db), q: str = ""):
    stmt = select(PublicKey, User).join(User, PublicKey.owner_id == User.id).where(PublicKey.status == "active", User.status == "active")
    if q.strip():
        needle = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(func.lower(User.email).like(needle), func.lower(User.full_name).like(needle), func.lower(PublicKey.name).like(needle)))
    rows = db.execute(stmt.order_by(PublicKey.created_at.desc()).limit(100)).all()
    trusted_ids = set(db.scalars(select(TrustedKey.key_id).where(TrustedKey.user_id == user.id)).all())
    items = []
    for key, owner in rows:
        items.append({
            "id": key.id, "name": key.name, "fingerprint": key.fingerprint,
            "key_size": key.key_size, "created_at": _iso(key.created_at),
            "owner_id": owner.id, "owner_name": owner.full_name,
            "is_mine": key.owner_id == user.id,
            "trusted": key.id in trusted_ids,
        })
    return {"items": items}


@app.get("/api/keys/{key_id}/pem")
def download_public_key(key_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    key = db.get(PublicKey, key_id)
    owner = db.get(User, key.owner_id) if key else None
    if not key or key.status != "active" or not owner or owner.status != "active":
        raise HTTPException(status_code=404, detail="Không tìm thấy Public Key đang hoạt động.")
    filename = f"public-key-{key.fingerprint[:12]}.pem"
    from fastapi.responses import Response as RawResponse
    return RawResponse(
        content=key.public_key_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "private, no-store"},
    )


@app.post("/api/keys/{key_id}/trust")
def trust_key(key_id: str, user: User = Depends(require_csrf), db: Session = Depends(get_db)):
    key = db.get(PublicKey, key_id)
    if not key or key.status != "active":
        raise HTTPException(status_code=404, detail="Không tìm thấy khóa công khai đang hoạt động.")
    if key.owner_id == user.id:
        raise HTTPException(status_code=400, detail="Không cần tự đánh dấu khóa của chính mình là khóa tin cậy.")
    existing = db.scalar(select(TrustedKey).where(TrustedKey.user_id == user.id, TrustedKey.key_id == key_id))
    if not existing:
        db.add(TrustedKey(user_id=user.id, key_id=key_id))
        add_audit(db, user.id, "KEY_TRUSTED", "public_key", key_id, fingerprint=key.fingerprint)
        db.commit()
    return {"message": "Đã thêm khóa vào danh sách tin cậy."}


@app.delete("/api/keys/{key_id}/trust")
def untrust_key(key_id: str, user: User = Depends(require_csrf), db: Session = Depends(get_db)):
    trust = db.scalar(select(TrustedKey).where(TrustedKey.user_id == user.id, TrustedKey.key_id == key_id))
    if trust:
        db.delete(trust)
        add_audit(db, user.id, "KEY_UNTRUSTED", "public_key", key_id)
        db.commit()
    return {"message": "Đã bỏ khóa khỏi danh sách tin cậy."}


@app.delete("/api/keys/{key_id}")
def revoke_key(key_id: str, user: User = Depends(require_csrf), db: Session = Depends(get_db)):
    key = db.get(PublicKey, key_id)
    if not key or key.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Không tìm thấy khóa thuộc tài khoản của bạn.")
    if key.status != "revoked":
        key.status = "revoked"
        key.revoked_at = utc_now()
        add_audit(db, user.id, "KEY_REVOKED", "public_key", key.id, fingerprint=key.fingerprint)
        db.commit()
    return {"message": "Đã thu hồi khóa. Khóa không còn được dùng để gửi tài liệu mới."}


# --------------------------- Signing history and verification ---------------------------

@app.post("/api/history/sign")
async def record_signature(
    pdf: UploadFile = File(...), signature: UploadFile = File(...), key_id: str = Form(...),
    user: User = Depends(require_csrf), db: Session = Depends(get_db),
):
    file_name, pdf_bytes = await _read_pdf(pdf)
    signature_bytes = await _read_signature(signature)
    key = db.get(PublicKey, key_id)
    if not key or key.owner_id != user.id or key.status != "active":
        raise HTTPException(status_code=403, detail="Khóa ký không thuộc tài khoản hoặc đã bị thu hồi.")
    result = verify_signature(pdf_bytes, signature_bytes, key.public_key_pem.encode("utf-8"))
    if not result["valid"]:
        raise HTTPException(status_code=400, detail="Chữ ký không khớp với PDF và Public Key đã đăng ký.")
    add_audit(db, user.id, "SIGN", "document", "", file_name, result["sha256"], key.fingerprint, "CREATED", "Chữ ký được tạo trong trình duyệt; máy chủ chỉ xác minh và ghi nhận.")
    db.commit()
    return {"message": "Đã xác minh và ghi nhận sự kiện ký.", "sha256": result["sha256"], "fingerprint": key.fingerprint}


@app.post("/api/verify")
async def verify_pdf(
    pdf: UploadFile = File(...), signature: UploadFile = File(...),
    key_id: str | None = Form(default=None), public_key: UploadFile | None = File(default=None),
    user: User = Depends(require_csrf), db: Session = Depends(get_db),
):
    file_name, pdf_bytes = await _read_pdf(pdf)
    signature_bytes = await _read_signature(signature)
    key_record = None
    if key_id:
        key_record = db.get(PublicKey, key_id)
        if not key_record or key_record.status != "active":
            raise HTTPException(status_code=404, detail="Không tìm thấy Public Key đang hoạt động.")
        public_key_pem = key_record.public_key_pem.encode("utf-8")
    elif public_key is not None:
        public_key_pem = await public_key.read(16 * 1024 + 1)
        if len(public_key_pem) > 16 * 1024:
            raise HTTPException(status_code=400, detail="Tệp Public Key quá lớn.")
    else:
        raise HTTPException(status_code=400, detail="Hãy chọn Public Key trong danh bạ hoặc tải lên tệp PEM.")
    try:
        result = verify_signature(pdf_bytes, signature_bytes, public_key_pem)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Không thể xác thực: {exc}")
    if key_record is None:
        key_record = db.scalar(select(PublicKey).where(PublicKey.fingerprint == result["fingerprint"]))
    owner = db.get(User, key_record.owner_id) if key_record else None
    trusted = False
    if key_record and key_record.status == "active":
        trusted = db.scalar(select(TrustedKey.id).where(TrustedKey.user_id == user.id, TrustedKey.key_id == key_record.id)) is not None
    result.update({
        "trusted": trusted,
        "key_id": key_record.id if key_record else None,
        "key_owner_name": owner.full_name if owner else None,
        "file_name": file_name,
    })
    add_audit(db, user.id, "VERIFY", "document", "", file_name, result["sha256"], result["fingerprint"], "VALID" if result["valid"] else "INVALID", "Xác thực bằng khóa trong danh bạ." if key_record else "Xác thực bằng Public Key tải lên.")
    db.commit()
    return result


@app.get("/api/history")
def list_history(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditLog).where(AuditLog.actor_id == user.id).order_by(AuditLog.created_at.desc()).limit(200)).all()
    return {"items": [{
        "id": r.id, "event_type": r.event_type, "file_name": r.file_name,
        "sha256": r.sha256, "key_fingerprint": r.key_fingerprint,
        "result": r.result, "details": r.details, "created_at": _iso(r.created_at),
    } for r in rows]}


# --------------------------- Document exchange ---------------------------

@app.post("/api/documents/send")
async def send_document(
    recipient_email: str = Form(...), key_id: str = Form(...), message: str = Form(default=""),
    pdf: UploadFile = File(...), signature: UploadFile = File(...),
    user: User = Depends(require_csrf), db: Session = Depends(get_db),
):
    email = recipient_email.strip().lower()
    recipient = db.scalar(select(User).where(User.email == email, User.status == "active"))
    if not recipient:
        raise HTTPException(status_code=404, detail="Không tìm thấy người nhận đang hoạt động với email này.")
    if recipient.id == user.id:
        raise HTTPException(status_code=400, detail="Bạn không thể gửi tài liệu cho chính mình.")
    key = db.get(PublicKey, key_id)
    if not key or key.owner_id != user.id or key.status != "active":
        raise HTTPException(status_code=403, detail="Hãy chọn Public Key đang hoạt động thuộc tài khoản của bạn.")
    file_name, pdf_bytes = await _read_pdf(pdf)
    signature_bytes = await _read_signature(signature)
    result = verify_signature(pdf_bytes, signature_bytes, key.public_key_pem.encode("utf-8"))
    if not result["valid"]:
        raise HTTPException(status_code=400, detail="Chữ ký không hợp lệ với PDF hoặc không được tạo bởi khóa đã chọn.")
    document_id = str(uuid.uuid4())
    # Storage references are generated by the server; clients never choose Blob
    # pathnames. Vercel mode writes to a private per-sender prefix.
    pdf_reference = f"documents/{user.id}/{document_id}.pdf"
    signature_reference = f"documents/{user.id}/{document_id}.sig"
    pdf_saved = False
    signature_saved = False
    try:
        pdf_reference = await save_file(pdf_reference, pdf_bytes, "application/pdf")
        pdf_saved = True
        signature_reference = await save_file(signature_reference, signature_bytes, "application/octet-stream")
        signature_saved = True
        document = Document(
            id=document_id, sender_id=user.id, recipient_id=recipient.id, key_id=key.id,
            file_name=file_name, pdf_path=pdf_reference, signature_path=signature_reference,
            sha256=result["sha256"], message=message.strip()[:1000], verification_status="pending",
        )
        db.add(document)
        add_audit(db, user.id, "DOCUMENT_SENT", "document", document_id, file_name, result["sha256"], key.fingerprint, "SENT", f"Gửi cho {recipient.email}")
        db.commit()
    except Exception:
        db.rollback()
        if signature_saved:
            await delete_file(signature_reference)
        if pdf_saved:
            await delete_file(pdf_reference)
        raise
    return {"message": "Đã gửi tài liệu thành công.", "item": _document_payload(db, document, user.id)}


@app.get("/api/documents/inbox")
def inbox(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Document).where(Document.recipient_id == user.id).order_by(Document.created_at.desc()).limit(200)).all()
    return {"items": [_document_payload(db, item, user.id) for item in rows]}


@app.get("/api/documents/sent")
def sent_documents(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Document).where(Document.sender_id == user.id).order_by(Document.created_at.desc()).limit(200)).all()
    return {"items": [_document_payload(db, item, user.id) for item in rows]}


@app.post("/api/documents/{document_id}/verify")
async def verify_received_document(document_id: str, user: User = Depends(require_csrf), db: Session = Depends(get_db)):
    document = _require_document_access(db, document_id, user.id)
    key = db.get(PublicKey, document.key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Không tìm thấy khóa công khai của người gửi.")
    try:
        pdf_bytes = await read_file(document.pdf_path)
        signature_bytes = await read_file(document.signature_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Không tìm thấy tệp tài liệu trên bộ lưu trữ.")
    result = verify_signature(pdf_bytes, signature_bytes, key.public_key_pem.encode("utf-8"))
    trusted = key.status == "active" and db.scalar(select(TrustedKey.id).where(TrustedKey.user_id == user.id, TrustedKey.key_id == key.id)) is not None
    document.verification_status = "valid" if result["valid"] else "invalid"
    document.verified_at = utc_now()
    add_audit(db, user.id, "DOCUMENT_VERIFY", "document", document.id, document.file_name, result["sha256"], key.fingerprint, "VALID" if result["valid"] else "INVALID", "Khóa đã được người nhận đánh dấu tin cậy." if trusted else "Chữ ký hợp lệ không đồng nghĩa danh tính đã được người nhận tin cậy.")
    db.commit()
    return {"valid": result["valid"], "trusted": trusted, "message": result["message"], "sha256": result["sha256"], "fingerprint": key.fingerprint, "sender_name": db.get(User, document.sender_id).full_name}


@app.get("/api/documents/{document_id}/pdf")
async def download_document_pdf(document_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    document = _require_document_access(db, document_id, user.id)
    try:
        content = await read_file(document.pdf_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Không tìm thấy PDF.")
    filename = Path(document.file_name).name
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=\"document.pdf\"; filename*=UTF-8''" + quote(filename),
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/documents/{document_id}/signature")
async def download_document_signature(document_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    document = _require_document_access(db, document_id, user.id)
    try:
        content = await read_file(document.signature_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Không tìm thấy tệp chữ ký.")
    name = Path(document.file_name).stem + ".sig"
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": "attachment; filename=\"signature.sig\"; filename*=UTF-8''" + quote(name),
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


# --------------------------- Administration ---------------------------

@app.get("/api/admin/users")
def admin_users(admin: User = Depends(require_admin), db: Session = Depends(get_db), q: str = ""):
    stmt = select(User)
    if q.strip():
        needle = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(func.lower(User.email).like(needle), func.lower(User.full_name).like(needle)))
    users = db.scalars(stmt.order_by(User.created_at.desc()).limit(250)).all()
    return {"items": [{
        **user_payload(u),
        "key_count": db.scalar(select(func.count(PublicKey.id)).where(PublicKey.owner_id == u.id, PublicKey.status == "active")) or 0,
        "document_count": db.scalar(select(func.count(Document.id)).where(or_(Document.sender_id == u.id, Document.recipient_id == u.id))) or 0,
    } for u in users]}


@app.patch("/api/admin/users/{user_id}")
def admin_update_user(user_id: str, payload: AdminUserUpdate, admin: User = Depends(require_csrf), db: Session = Depends(get_db)):
    if admin.role != "admin":
        raise HTTPException(status_code=403, detail="Bạn không có quyền quản trị.")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản.")
    if payload.status == "suspended" and target.id == admin.id:
        raise HTTPException(status_code=400, detail="Bạn không thể tự khóa tài khoản quản trị đang sử dụng.")
    next_role = payload.role or target.role
    next_status = payload.status or target.status
    if target.role == "admin" and (next_role != "admin" or next_status != "active"):
        admin_count = db.scalar(select(func.count(User.id)).where(User.role == "admin", User.status == "active")) or 0
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Không thể vô hiệu hóa hoặc hạ quyền quản trị viên cuối cùng.")
    old_role, old_status = target.role, target.status
    target.role, target.status = next_role, next_status
    if next_status == "suspended" and old_status != "suspended":
        active_sessions = db.scalars(select(UserSession).where(UserSession.user_id == target.id, UserSession.revoked_at.is_(None))).all()
        for session in active_sessions:
            session.revoked_at = utc_now()
    add_audit(db, admin.id, "ADMIN_USER_UPDATED", "user", target.id, result="UPDATED", details=f"role {old_role}->{next_role}; status {old_status}->{next_status}")
    db.commit()
    return {"message": "Đã cập nhật tài khoản.", "user": user_payload(target)}


@app.get("/api/admin/overview")
def admin_overview(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return {
        "users": db.scalar(select(func.count(User.id))) or 0,
        "active_users": db.scalar(select(func.count(User.id)).where(User.status == "active")) or 0,
        "keys": db.scalar(select(func.count(PublicKey.id)).where(PublicKey.status == "active")) or 0,
        "documents": db.scalar(select(func.count(Document.id))) or 0,
    }
