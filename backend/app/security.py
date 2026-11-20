import hashlib
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import (
    COOKIE_SAMESITE, COOKIE_SECURE, CSRF_COOKIE_NAME, SESSION_COOKIE_NAME,
    SESSION_TTL_HOURS,
)
from .database import User, UserSession, get_db, utc_now

_password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_session(response: Response, db: Session, user: User, request: Request):
    session_token = secrets.token_urlsafe(48)
    csrf_token = secrets.token_urlsafe(32)
    now = utc_now()
    record = UserSession(
        user_id=user.id,
        token_hash=token_hash(session_token),
        csrf_hash=token_hash(csrf_token),
        created_at=now,
        expires_at=now + timedelta(hours=SESSION_TTL_HOURS),
        user_agent=(request.headers.get("user-agent") or "")[:500],
    )
    db.add(record)
    db.commit()
    max_age = SESSION_TTL_HOURS * 3600
    response.set_cookie(
        SESSION_COOKIE_NAME, session_token, max_age=max_age, httponly=True,
        secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE, path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME, csrf_token, max_age=max_age, httponly=False,
        secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE, path="/",
    )
    return csrf_token


def clear_session_cookies(response: Response):
    response.delete_cookie(SESSION_COOKIE_NAME, path="/", secure=COOKIE_SECURE, httponly=True, samesite=COOKIE_SAMESITE)
    response.delete_cookie(CSRF_COOKIE_NAME, path="/", secure=COOKIE_SECURE, httponly=False, samesite=COOKIE_SAMESITE)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Vui lòng đăng nhập.")
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash(raw_token)))
    now = utc_now()
    if not session or session.revoked_at is not None or session.expires_at <= now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.")
    user = db.get(User, session.user_id)
    if not user or user.status != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tài khoản đã bị khóa hoặc không còn hoạt động.")
    request.state.auth_session = session
    return user


def require_csrf(request: Request, user: User = Depends(get_current_user)):
    session = getattr(request.state, "auth_session", None)
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME, "")
    header_token = request.headers.get("x-csrf-token", "")
    if not session or not cookie_token or not header_token:
        raise HTTPException(status_code=403, detail="Thiếu CSRF token. Hãy tải lại trang và thử lại.")
    if not secrets.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=403, detail="CSRF token không khớp.")
    if not secrets.compare_digest(token_hash(cookie_token), session.csrf_hash):
        raise HTTPException(status_code=403, detail="CSRF token không hợp lệ hoặc đã hết hạn.")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Bạn không có quyền quản trị.")
    return user


def user_payload(user: User):
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "status": user.status,
        "created_at": user.created_at.isoformat() + "Z",
        "email_verified_at": user.email_verified_at.isoformat() + "Z" if user.email_verified_at else None,
    }
