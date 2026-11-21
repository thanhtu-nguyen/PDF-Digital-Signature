"""Demo accounts: they can log in, and the shipped demo key files work end to end."""
import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi.testclient import TestClient

from backend.app.database import SessionLocal
from backend.app.demo_seed import DEMO_DIR, DEMO_KEY_PASSWORD, DEMO_USERS, seed_demo_accounts
from backend.app.main import app

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
SPEC = {u["email"].split("@")[0]: u for u in DEMO_USERS}


def decrypt_demo_key(path):
    """Decrypt a .key.json exactly like the browser does (PBKDF2-SHA256 -> AES-256-GCM)."""
    bundle = json.loads(path.read_text())
    aes = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=base64.b64decode(bundle["salt"]),
                     iterations=bundle["iterations"]).derive(DEMO_KEY_PASSWORD.encode())
    pkcs8 = AESGCM(aes).decrypt(base64.b64decode(bundle["iv"]), base64.b64decode(bundle["ciphertext"]), None)
    return serialization.load_der_private_key(pkcs8, None), bundle


def login(client, name):
    r = client.post("/api/auth/login", json={"email": SPEC[name]["email"], "password": SPEC[name]["password"]})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf_token"]}


def test_demo_accounts_seed_and_work_end_to_end():
    with TestClient(app) as client:                    # lifespan creates the tables
        with SessionLocal.begin() as db:
            seed_demo_accounts(db)
        with SessionLocal.begin() as db:
            assert seed_demo_accounts(db) == 0         # idempotent: nothing created the second time

    with TestClient(app) as admin, TestClient(app) as alice, TestClient(app) as bob, TestClient(app) as charlie:
        login(admin, "admin")
        assert admin.get("/api/auth/me").json()["user"]["role"] == "admin"
        token = login(alice, "alice")
        login(bob, "bob")
        login(charlie, "charlie")
        assert alice.get("/api/auth/me").json()["user"]["role"] == "user"

        # The shipped key file decrypts with the published password and matches Alice's registered key.
        private_key, bundle = decrypt_demo_key(DEMO_DIR / "alice.key.json")
        mine = alice.get("/api/keys/mine").json()["items"]
        assert [k["fingerprint"] for k in mine] == [bundle["fingerprint"]]

        pdf = (DEMO_DIR / "contract-demo.pdf").read_bytes()
        sig = private_key.sign(pdf, PSS, hashes.SHA256())
        sent = alice.post("/api/documents/send", headers=token,
                          data={"recipient_email": SPEC["bob"]["email"], "key_id": mine[0]["id"], "message": "demo"},
                          files={"pdf": ("contract-demo.pdf", pdf, "application/pdf"),
                                 "signature": ("contract-demo.sig", sig, "application/octet-stream")})
        assert sent.status_code == 200, sent.text
        assert len(bob.get("/api/documents/inbox").json()["items"]) == 1
        assert charlie.get("/api/documents/inbox").json()["items"] == []

        # The tampered sample PDF does not verify with Alice's signature.
        tampered = (DEMO_DIR / "contract-demo-tampered.pdf").read_bytes()
        check = alice.post("/api/verify", headers=token, data={"key_id": mine[0]["id"]},
                           files={"pdf": ("t.pdf", tampered, "application/pdf"), "signature": ("s.sig", sig, "application/octet-stream")})
        assert check.status_code == 200 and check.json()["valid"] is False


def test_demo_accounts_refused_in_production(monkeypatch):
    import importlib
    import pytest
    from backend.app import config
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("COOKIE_SECURE", "true")
    monkeypatch.setenv("SECURESIGN_DEMO_ACCOUNTS", "true")
    with pytest.raises(RuntimeError, match="Demo accounts"):
        importlib.reload(config)
    monkeypatch.undo()
    importlib.reload(config)
