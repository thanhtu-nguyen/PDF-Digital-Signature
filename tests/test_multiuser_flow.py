import os
import shutil
import sys
from pathlib import Path

# Isolate the integration-test database before importing the application.
TEST_ROOT = Path(f"/tmp/securesign-tests-{os.getpid()}")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_ROOT / 'test.db'}"
os.environ["SECURESIGN_STORAGE_DIR"] = str(TEST_ROOT / "storage")
os.environ["ADMIN_EMAIL"] = "root@example.com"
os.environ["ADMIN_PASSWORD"] = "test-admin-password-very-long"
os.environ["ADMIN_NAME"] = "Test Admin"
os.environ["COOKIE_SECURE"] = "false"
os.environ["APP_ENV"] = "development"
os.environ["REQUIRE_EMAIL_VERIFICATION"] = "false"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from backend.app.database import Base, engine
from backend.app.main import app

PDF = b"%PDF-1.4\n% SecureSign test document\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF"


def csrf(client):
    response = client.get("/api/auth/csrf")
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def register(client, email, name):
    response = client.post("/api/auth/register", json={
        "email": email,
        "full_name": name,
        "password": "a-strong-test-password-2026",
        "role": "admin",  # Must be ignored; public registration cannot grant roles.
    })
    assert response.status_code == 200, response.text
    return response.json()["user"]


def create_key(client, name):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    challenge = client.post("/api/keys/challenge", headers=csrf(client)).json()
    proof = private_key.sign(
        challenge["challenge"].encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    import base64
    response = client.post("/api/keys", headers=csrf(client), json={
        "name": name,
        "public_key_pem": public_pem,
        "challenge_id": challenge["challenge_id"],
        "proof_signature": base64.b64encode(proof).decode("ascii"),
    })
    assert response.status_code == 200, response.text
    return private_key, response.json()["item"]


def sign(private_key, data=PDF):
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def test_multi_user_isolation_and_document_exchange():
    TEST_ROOT.mkdir(parents=True, exist_ok=True)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    shutil.rmtree(TEST_ROOT / "storage", ignore_errors=True)

    with TestClient(app) as admin_client, TestClient(app) as alice, TestClient(app) as bob, TestClient(app) as stranger:
        # Admin bootstrap is not exposed through public registration.
        admin_login = admin_client.post("/api/auth/login", json={
            "email": "root@example.com", "password": "test-admin-password-very-long"
        })
        assert admin_login.status_code == 200
        alice_user = register(alice, "alice@example.com", "Alice Nguyen")
        bob_user = register(bob, "bob@example.com", "Bob Tran")
        charlie_user = register(stranger, "charlie@example.com", "Charlie Le")
        assert alice_user["role"] == "user"
        assert bob_user["role"] == "user"
        assert alice.get("/api/admin/users").status_code == 403

        # A challenge cannot be registered without proof of possession of its matching private key.
        proof_challenge = alice.post("/api/keys/challenge", headers=csrf(alice)).json()
        impostor = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        impostor_proof = impostor.sign(
            proof_challenge["challenge"].encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        import base64
        alice_candidate = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        candidate_pem = alice_candidate.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        failed_registration = alice.post("/api/keys", headers=csrf(alice), json={
            "name": "Not owned", "public_key_pem": candidate_pem,
            "challenge_id": proof_challenge["challenge_id"],
            "proof_signature": base64.b64encode(impostor_proof).decode("ascii"),
        })
        assert failed_registration.status_code == 400

        # Alice registers a public key; the private key never goes to the API.
        alice_private, alice_key = create_key(alice, "Alice signing key")
        signature = sign(alice_private)

        # A signed document is sent only after server-side signature verification.
        sent = alice.post(
            "/api/documents/send",
            headers=csrf(alice),
            data={"recipient_email": "bob@example.com", "key_id": alice_key["id"], "message": "Please review."},
            files={
                "pdf": ("agreement.pdf", PDF, "application/pdf"),
                "signature": ("agreement.sig", signature, "application/octet-stream"),
            },
        )
        assert sent.status_code == 200, sent.text
        document_id = sent.json()["item"]["id"]

        # Bob sees the inbox item and can verify it, but a third user cannot read it.
        inbox = bob.get("/api/documents/inbox")
        assert inbox.status_code == 200
        assert len(inbox.json()["items"]) == 1
        assert stranger.get(f"/api/documents/{document_id}/pdf").status_code == 404
        assert stranger.delete(f"/api/keys/{alice_key['id']}", headers=csrf(stranger)).status_code == 404
        assert bob.get(f"/api/documents/{document_id}/pdf").content == PDF
        assert alice.get(f"/api/documents/{document_id}/pdf").content == PDF

        verification = bob.post(f"/api/documents/{document_id}/verify", headers=csrf(bob))
        assert verification.status_code == 200
        assert verification.json()["valid"] is True
        assert verification.json()["trusted"] is False

        # Trust is a per-recipient relationship, not a global property.
        directory = bob.get("/api/keys/directory").json()["items"]
        alice_public = next(item for item in directory if item["id"] == alice_key["id"])
        assert bob.post(f"/api/keys/{alice_key['id']}/trust").status_code == 403
        trust = bob.post(f"/api/keys/{alice_key['id']}/trust", headers=csrf(bob))
        assert trust.status_code == 200
        verification = bob.post(f"/api/documents/{document_id}/verify", headers=csrf(bob))
        assert verification.json()["trusted"] is True
        assert alice.get("/api/keys/directory").json()["items"]

        # Tampering with one byte makes the detached signature invalid.
        tampered = PDF.replace(b"review", b"change") if b"review" in PDF else PDF + b"tampered"
        verify = bob.post(
            "/api/verify",
            headers=csrf(bob),
            data={"key_id": alice_key["id"]},
            files={
                "pdf": ("tampered.pdf", tampered, "application/pdf"),
                "signature": ("agreement.sig", signature, "application/octet-stream"),
            },
        )
        assert verify.status_code == 200
        assert verify.json()["valid"] is False

        # Personal history is isolated.
        alice_history = alice.get("/api/history").json()["items"]
        bob_history = bob.get("/api/history").json()["items"]
        assert any(item["event_type"] == "DOCUMENT_SENT" for item in alice_history)
        assert any(item["event_type"] == "DOCUMENT_VERIFY" for item in bob_history)
        assert all(item["event_type"] != "DOCUMENT_SENT" for item in bob_history)

        # Admin can suspend an account; the suspended user loses access.
        admin_headers = csrf(admin_client)
        suspended = admin_client.patch(
            f"/api/admin/users/{alice_user['id']}",
            headers=admin_headers,
            json={"status": "suspended"},
        )
        assert suspended.status_code == 200, suspended.text
        assert alice.get("/api/auth/me").status_code == 401


def test_email_verification_gate(monkeypatch):
    import re
    import backend.app.main as main_module

    # Reinitialize the test DB for this isolated flow.
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    sent_messages = []
    monkeypatch.setattr(main_module, "REQUIRE_EMAIL_VERIFICATION", True)
    monkeypatch.setattr(main_module, "PUBLIC_BASE_URL", "https://securesign.example.com")
    monkeypatch.setattr(main_module, "send_email", lambda to, subject, body: sent_messages.append((to, subject, body)))

    with TestClient(app) as client:
        registered = client.post("/api/auth/register", json={
            "email": "verify-me@example.com",
            "full_name": "Verify Me",
            "password": "another-strong-password-2026",
        })
        assert registered.status_code == 200, registered.text
        assert registered.json()["requires_email_verification"] is True
        assert len(sent_messages) == 1

        login_before = client.post("/api/auth/login", json={
            "email": "verify-me@example.com",
            "password": "another-strong-password-2026",
        })
        assert login_before.status_code == 403

        link = re.search(r"https://securesign\.example\.com/api/auth/verify-email\?token=([^\s]+)", sent_messages[0][2])
        assert link
        verified = client.get(f"/api/auth/verify-email?token={link.group(1)}", follow_redirects=False)
        assert verified.status_code == 303
        assert verified.headers["location"] == "/?verified=1"

        login_after = client.post("/api/auth/login", json={
            "email": "verify-me@example.com",
            "password": "another-strong-password-2026",
        })
        assert login_after.status_code == 200

        # Password reset uses a one-time, expiring email token and revokes active sessions.
        monkeypatch.setattr(main_module, "SMTP_HOST", "smtp.test")
        monkeypatch.setattr(main_module, "SMTP_FROM", "SecureSign <no-reply@example.com>")
        reset_request = client.post("/api/auth/forgot-password", json={"email": "verify-me@example.com"})
        assert reset_request.status_code == 200
        reset_link = re.search(r"https://securesign\.example\.com/\?reset_token=([^\s]+)", sent_messages[-1][2])
        assert reset_link
        reset = client.post("/api/auth/reset-password", json={
            "token": reset_link.group(1),
            "new_password": "brand-new-password-2026-strong",
        })
        assert reset.status_code == 200
        assert client.get("/api/auth/me").status_code == 401
        old_login = client.post("/api/auth/login", json={
            "email": "verify-me@example.com", "password": "another-strong-password-2026"
        })
        new_login = client.post("/api/auth/login", json={
            "email": "verify-me@example.com", "password": "brand-new-password-2026-strong"
        })
        assert old_login.status_code == 401
        assert new_login.status_code == 200
