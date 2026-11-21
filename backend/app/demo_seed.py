"""Demo accounts for local testing and the live presentation.

When SECURESIGN_DEMO_ACCOUNTS is enabled (the default outside production), the
server creates these accounts at start-up so nobody has to register first.
Alice (RSA-PSS 2048) and Bob (ECDSA P-256) also get a registered public key whose encrypted private key
ships in demo_data/<name>.key.json (key password: DEMO_KEY_PASSWORD).

The credentials are PUBLIC (they are printed in the README). config.py refuses
to start with demo accounts when APP_ENV=production.
"""
import json
from pathlib import Path

from sqlalchemy import select

DEMO_DIR = Path(__file__).resolve().parents[2] / "demo_data"
DEMO_KEY_PASSWORD = "DemoKey@2026"

DEMO_USERS = [
    {"email": "admin@securesign-demo.com", "full_name": "Demo Admin", "password": "Admin@Demo2026", "role": "admin"},
    {"email": "alice@securesign-demo.com", "full_name": "Alice Nguyen", "password": "Alice@Demo2026", "role": "user",
     "key_file": "alice.key.json", "key_name": "Alice - demo signing key"},
    {"email": "bob@securesign-demo.com", "full_name": "Bob Tran", "password": "Bob@Demo2026", "role": "user",
     "key_file": "bob.key.json", "key_name": "Bob - demo ECDSA key", "key_algorithm": "ECDSA-P256"},
    {"email": "charlie@securesign-demo.com", "full_name": "Charlie Le", "password": "Charlie@Demo2026", "role": "user"},
]


def seed_demo_accounts(db) -> int:
    """Create missing demo users and their public keys. Idempotent: existing
    accounts keep their current password, role changes and data."""
    from .crypto_service import key_algorithm, load_public_key, public_key_fingerprint
    from .evidence import append_evidence
    from .database import PublicKey, User, add_audit, utc_now
    from .security import hash_password

    created = 0
    for spec in DEMO_USERS:
        user = db.scalar(select(User).where(User.email == spec["email"]))
        if user is None:
            user = User(email=spec["email"], full_name=spec["full_name"], password_hash=hash_password(spec["password"]),
                        role=spec["role"], status="active", email_verified_at=utc_now())
            db.add(user)
            db.flush()
            add_audit(db, user.id, "ACCOUNT_REGISTERED", "user", user.id, details="Tài khoản mẫu (demo).")
            created += 1
        key_file = DEMO_DIR / spec.get("key_file", "")
        if spec.get("key_file") and key_file.is_file():
            pem = json.loads(key_file.read_text())["publicKeyPem"]
            public_key = load_public_key(pem.encode())
            fingerprint = public_key_fingerprint(public_key)
            if db.scalar(select(PublicKey.id).where(PublicKey.fingerprint == fingerprint)) is None:
                key = PublicKey(owner_id=user.id, name=spec["key_name"], fingerprint=fingerprint, public_key_pem=pem,
                                key_size=public_key.key_size, status="active")
                db.add(key)
                db.flush()
                audit = add_audit(db, user.id, "KEY_REGISTERED", "public_key", key.id, fingerprint=fingerprint,
                                  details="Khóa mẫu (demo_data).")
                append_evidence(db, "KEY_REGISTERED", user, {
                    "key_id": key.id, "key_name": key.name, "fingerprint": fingerprint,
                    "algorithm": key_algorithm(public_key), "proof_of_possession": "demo seed"}, audit_id=audit.id)
    return created
