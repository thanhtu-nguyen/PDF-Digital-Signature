from contextlib import contextmanager
from datetime import datetime, timezone
import uuid

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
    create_engine, event, select
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import DATABASE_URL, ADMIN_EMAIL, ADMIN_NAME, ADMIN_PASSWORD, ADMIN_RESET_PASSWORD


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_id() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="user", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    keys = relationship("PublicKey", back_populates="owner", cascade="all, delete-orphan")


class EmailToken(Base):
    __tablename__ = "email_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    purpose: Mapped[str] = mapped_column(String(30), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class UserSession(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    csrf_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    user_agent: Mapped[str] = mapped_column(String(500), default="", nullable=False)


class PublicKey(Base):
    __tablename__ = "public_keys"
    __table_args__ = (UniqueConstraint("fingerprint", name="uq_public_keys_fingerprint"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    key_size: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    owner = relationship("User", back_populates="keys")


class KeyChallenge(Base):
    __tablename__ = "key_challenges"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    challenge_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    challenge_value: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class TrustedKey(Base):
    __tablename__ = "trusted_keys"
    __table_args__ = (UniqueConstraint("user_id", "key_id", name="uq_trusted_key_user_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    key_id: Mapped[str] = mapped_column(ForeignKey("public_keys.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sender_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False)
    recipient_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False)
    key_id: Mapped[str] = mapped_column(ForeignKey("public_keys.id", ondelete="RESTRICT"), index=True, nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    pdf_path: Mapped[str] = mapped_column(String(500), nullable=False)
    signature_path: Mapped[str] = mapped_column(String(500), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    message: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    verification_status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    target_type: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    target_id: Mapped[str] = mapped_column(String(36), default="", nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    key_fingerprint: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    result: Mapped[str] = mapped_column(String(30), default="OK", nullable=False)
    details: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)


Index("ix_documents_inbox", Document.recipient_id, Document.created_at)
Index("ix_documents_sent", Document.sender_id, Document.created_at)
Index("ix_audit_actor_created", AuditLog.actor_id, AuditLog.created_at)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db():
    Base.metadata.create_all(bind=engine)
    if ADMIN_EMAIL and ADMIN_PASSWORD:
        from .security import hash_password
        with SessionLocal() as db:
            admin = db.scalar(select(User).where(User.email == ADMIN_EMAIL))
            if admin is None:
                admin = User(email=ADMIN_EMAIL, full_name=ADMIN_NAME or "Administrator", password_hash=hash_password(ADMIN_PASSWORD), role="admin", status="active", email_verified_at=utc_now())
                db.add(admin)
            else:
                admin.role = "admin"
                admin.status = "active"
                admin.email_verified_at = utc_now()
                if ADMIN_NAME:
                    admin.full_name = ADMIN_NAME
                if ADMIN_RESET_PASSWORD:
                    admin.password_hash = hash_password(ADMIN_PASSWORD)
            db.commit()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def add_audit(db, actor_id, event_type, target_type="", target_id="", file_name="", sha256="", fingerprint="", result="OK", details=""):
    entry = AuditLog(
        actor_id=actor_id, event_type=event_type, target_type=target_type,
        target_id=target_id, file_name=file_name[:255], sha256=sha256[:64],
        key_fingerprint=fingerprint[:64], result=result[:30], details=details[:1000]
    )
    db.add(entry)
    db.flush()
    return entry
