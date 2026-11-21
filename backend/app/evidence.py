"""Non-repudiation evidence: signed receipts in a hash-chained, append-only log.

A valid PDF signature proves WHO signed, but not WHEN, and an application log can
be edited by whoever controls the database. SecureSign therefore records every
security-relevant event (key registered/revoked, PDF signed, document sent,
document verified by the recipient) as an evidence entry:

    body_n       = canonical JSON {seq, time, event, actor, details, prev_hash = entry_hash_(n-1)}
    entry_hash_n = SHA-256(body_n)
    signature_n  = ECDSA-P256-SHA256(server receipt key, body_n)

  * The server signature makes each receipt a timestamped statement that the
    user can keep and verify offline (a minimal time-stamping authority, in the
    spirit of RFC 3161). Alice cannot later claim she signed at another time or
    never sent the document; the server cannot deny having issued the receipt.
  * The hash chain makes the log tamper-evident: editing, deleting or
    reordering any entry breaks every later link, and recomputing the hashes
    does not help without the server's private key.

The pure functions (canonical, build_entry, verify_entries, verify_receipt_bundle)
do not touch the database, so the Security Lab reuses them.
"""
import base64
import hashlib
import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

GENESIS_HASH = "0" * 64
RECEIPT_ALGORITHM = "ECDSA-P256-SHA256"
RECEIPT_TYPE = "SecureSign evidence receipt"
_APPEND_LOCK = threading.Lock()


# --------------------------------------------------------------------------- pure functions
def canonical(obj) -> bytes:
    """Deterministic JSON encoding: the exact bytes that are hashed and signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def key_fingerprint(public_key) -> str:
    return sha256_hex(public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def build_entry(private_key, seq: int, prev_hash: str, event: str, actor: dict, details: dict, time_iso: str | None = None) -> dict:
    """Create one chained, signed evidence entry."""
    body = {
        "type": RECEIPT_TYPE, "version": 1, "seq": seq,
        "time": time_iso or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "event": event, "actor": actor, "details": details, "prev_hash": prev_hash,
    }
    body_bytes = canonical(body)
    signature = private_key.sign(body_bytes, ec.ECDSA(hashes.SHA256()))
    return {"seq": seq, "body": body_bytes.decode("utf-8"), "entry_hash": sha256_hex(body_bytes),
            "signature": base64.b64encode(signature).decode()}


def _signature_ok(public_key, body: str, signature_b64: str) -> bool:
    try:
        public_key.verify(base64.b64decode(signature_b64, validate=True), body.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False


def verify_entries(entries, public_key) -> dict:
    """Check a whole chain (ordered by seq). Returns where and why it breaks, if it does."""
    prev_hash, expected_seq = GENESIS_HASH, 1
    for entry in entries:
        seq = entry["seq"]
        try:
            body = json.loads(entry["body"])
        except ValueError:
            return {"ok": False, "count": seq - 1, "broken_at": seq, "reason": "Nội dung mục không phải JSON hợp lệ."}
        if seq != expected_seq or body.get("seq") != seq:
            return {"ok": False, "count": expected_seq - 1, "broken_at": seq, "reason": f"Thiếu hoặc đảo thứ tự mục: mong đợi #{expected_seq}."}
        if body.get("prev_hash") != prev_hash:
            return {"ok": False, "count": seq - 1, "broken_at": seq, "reason": "prev_hash không khớp với mục trước: chuỗi bị cắt hoặc bị chèn."}
        if sha256_hex(entry["body"].encode("utf-8")) != entry["entry_hash"]:
            return {"ok": False, "count": seq - 1, "broken_at": seq, "reason": "Nội dung đã bị sửa: SHA-256 không khớp entry_hash."}
        if not _signature_ok(public_key, entry["body"], entry["signature"]):
            return {"ok": False, "count": seq - 1, "broken_at": seq, "reason": "Chữ ký của máy chủ không hợp lệ: mục đã bị làm giả."}
        prev_hash, expected_seq = entry["entry_hash"], seq + 1
    return {"ok": True, "count": expected_seq - 1, "broken_at": None, "reason": "Toàn bộ chuỗi bằng chứng nguyên vẹn.",
            "head_hash": prev_hash}


def receipt_bundle(entry: dict, public_key_pem: str) -> dict:
    """The file a user downloads: everything needed to verify the receipt offline."""
    return {
        "receipt": json.loads(entry["body"]),
        "signed_body": entry["body"],
        "entry_hash": entry["entry_hash"],
        "signature": entry["signature"],
        "signature_algorithm": RECEIPT_ALGORITHM,
        "server_public_key_pem": public_key_pem,
    }


def verify_receipt_bundle(bundle: dict, trusted_public_key=None) -> dict:
    """Verify a downloaded receipt. If `trusted_public_key` is given, the key embedded
    in the file is ignored for trust and must match it (otherwise anyone could
    sign a fake receipt with their own key and embed that key)."""
    try:
        body = bundle["signed_body"]
        embedded = serialization.load_pem_public_key(bundle["server_public_key_pem"].encode())
        if json.loads(body) != bundle["receipt"]:
            return {"valid": False, "reason": "Phần 'receipt' không khớp với nội dung đã ký."}
    except (KeyError, ValueError, TypeError):
        return {"valid": False, "reason": "Tệp biên nhận không đúng định dạng."}
    key = trusted_public_key or embedded
    if trusted_public_key is not None and key_fingerprint(embedded) != key_fingerprint(trusted_public_key):
        return {"valid": False, "reason": "Biên nhận không được ký bởi khóa của máy chủ SecureSign này."}
    if sha256_hex(body.encode("utf-8")) != bundle.get("entry_hash"):
        return {"valid": False, "reason": "entry_hash không khớp với nội dung."}
    if not _signature_ok(key, body, bundle.get("signature", "")):
        return {"valid": False, "reason": "Chữ ký của máy chủ trên biên nhận không hợp lệ."}
    return {"valid": True, "reason": "Biên nhận hợp lệ, do máy chủ SecureSign ký.", "receipt": bundle["receipt"],
            "server_key_fingerprint": key_fingerprint(key)}


# --------------------------------------------------------------------------- database layer
def _load_or_create_server_key(db):
    """Receipt signing key: SECURESIGN_RECEIPT_KEY_PEM if set, otherwise generated once and stored in the database."""
    from .database import ServerKey
    env_pem = os.getenv("SECURESIGN_RECEIPT_KEY_PEM", "").strip()
    if env_pem:
        private_key = serialization.load_pem_private_key(env_pem.replace("\\n", "\n").encode(), None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
            raise RuntimeError("SECURESIGN_RECEIPT_KEY_PEM must be an EC P-256 private key")
        return private_key
    record = db.query(ServerKey).filter(ServerKey.purpose == "receipt").order_by(ServerKey.created_at).first()
    if record is None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        record = ServerKey(purpose="receipt", private_key_pem=pem, fingerprint=key_fingerprint(private_key.public_key()))
        db.add(record)
        db.flush()
    return serialization.load_pem_private_key(record.private_key_pem.encode(), None)


def server_private_key(db):
    return _load_or_create_server_key(db)


def server_public_key_pem(db) -> str:
    return server_private_key(db).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def append_evidence(db, event: str, actor, details: dict, document_id: str = "", audit_id: str = ""):
    """Add the next chained entry. The caller must hold evidence_lock() until it commits."""
    from sqlalchemy import select
    from .database import EvidenceEntry
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy import text
        db.execute(text("SELECT pg_advisory_xact_lock(73519022)"))   # serialise appends across instances
    last = db.scalar(select(EvidenceEntry).order_by(EvidenceEntry.seq.desc()).limit(1))
    seq, prev_hash = (last.seq + 1, last.entry_hash) if last else (1, GENESIS_HASH)
    actor_info = {"id": actor.id, "email": actor.email, "name": actor.full_name} if actor is not None else {"id": None}
    key = server_private_key(db)
    entry = build_entry(key, seq, prev_hash, event, actor_info, details)
    record = EvidenceEntry(seq=seq, event_type=event, actor_id=actor.id if actor is not None else None,
                           document_id=document_id, audit_id=audit_id, body=entry["body"], entry_hash=entry["entry_hash"],
                           signature=entry["signature"], server_key_fingerprint=key_fingerprint(key.public_key()))
    db.add(record)
    db.flush()
    return record


@contextmanager
def evidence_lock():
    """Serialise append + commit inside one process (SQLite); PostgreSQL also uses an advisory lock."""
    with _APPEND_LOCK:
        yield


def record_evidence_and_commit(db, event: str, actor, details: dict, document_id: str = "", audit_id: str = ""):
    with evidence_lock():
        record = append_evidence(db, event, actor, details, document_id, audit_id)
        db.commit()
    return record


def entry_dict(record) -> dict:
    return {"seq": record.seq, "body": record.body, "entry_hash": record.entry_hash, "signature": record.signature}


def verify_chain(db) -> dict:
    from sqlalchemy import select
    from .database import EvidenceEntry
    records = db.scalars(select(EvidenceEntry).order_by(EvidenceEntry.seq)).all()
    return verify_entries([entry_dict(r) for r in records], server_private_key(db).public_key())
