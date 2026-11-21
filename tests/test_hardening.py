"""Regression tests for the security fixes made while integrating SecureSign into the final project."""
import base64
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from backend.app import main
from backend.app.crypto_service import verify_proof_of_possession
from backend.app.main import app

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def test_spoofed_x_forwarded_for_cannot_bypass_login_rate_limit():
    """Before the fix, a new fake X-Forwarded-For per request gave unlimited password guesses."""
    with TestClient(app) as client:
        codes = []
        for i in range(12):
            response = client.post(
                "/api/auth/login",
                json={"email": "nobody@example.com", "password": "wrong-password"},
                headers={"X-Forwarded-For": f"203.0.113.{i}"},
            )
            codes.append(response.status_code)
        assert codes[:10] == [401] * 10
        assert codes[10:] == [429, 429]


def test_x_forwarded_for_is_used_only_behind_a_trusted_proxy(monkeypatch):
    class Req:
        headers = {"x-forwarded-for": "198.51.100.7, 10.0.0.1"}
        client = type("C", (), {"host": "10.0.0.1"})()
    monkeypatch.setattr(main, "TRUST_PROXY_HEADERS", False)
    assert main.client_address(Req()) == "10.0.0.1"
    monkeypatch.setattr(main, "TRUST_PROXY_HEADERS", True)
    assert main.client_address(Req()) == "198.51.100.7"


def test_login_runs_password_hash_for_unknown_email(monkeypatch):
    """Unknown emails must cost one Argon2 verification too (no timing oracle for account enumeration)."""
    calls = []
    real = main.verify_password
    monkeypatch.setattr(main, "verify_password", lambda h, p: calls.append(h) or real(h, p))
    with TestClient(app) as client:
        response = client.post("/api/auth/login", json={"email": f"ghost-{uuid.uuid4().hex[:6]}@example.com", "password": "x"})
    assert response.status_code == 401
    assert calls == [main.DUMMY_PASSWORD_HASH]


def test_proof_of_possession_rejects_wrong_key_and_garbage():
    alice = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    eve = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    challenge = "one-time-challenge"
    good = base64.b64encode(alice.sign(challenge.encode(), PSS, hashes.SHA256())).decode()
    wrong = base64.b64encode(eve.sign(challenge.encode(), PSS, hashes.SHA256())).decode()
    assert verify_proof_of_possession(alice.public_key(), challenge, good)
    assert not verify_proof_of_possession(alice.public_key(), challenge, wrong)
    assert not verify_proof_of_possession(alice.public_key(), "another-challenge", good)   # no replay
    assert not verify_proof_of_possession(alice.public_key(), challenge, "not base64!!")


def test_registering_someone_elses_public_key_is_rejected():
    """Key substitution through the real API: Eve uploads Alice's public key with a proof made by her own key."""
    alice_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    eve_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alice_pem = alice_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with TestClient(app) as eve:
        assert eve.post("/api/auth/register", json={
            "email": f"eve-{uuid.uuid4().hex[:6]}@example.com", "full_name": "Eve",
            "password": "eve-strong-password-2026"}).status_code == 200
        token = {"X-CSRF-Token": eve.get("/api/auth/csrf").json()["csrf_token"]}
        challenge = eve.post("/api/keys/challenge", headers=token).json()
        proof = base64.b64encode(eve_key.sign(challenge["challenge"].encode(), PSS, hashes.SHA256())).decode()
        response = eve.post("/api/keys", headers=token, json={
            "name": "Alice (stolen)", "public_key_pem": alice_pem,
            "challenge_id": challenge["challenge_id"], "proof_signature": proof})
        assert response.status_code == 400
        assert eve.get("/api/keys/mine").json()["items"] == []


def test_security_headers_and_lab_csp():
    with TestClient(app) as client:
        home = client.get("/")
        assert "script-src 'self';" in home.headers["content-security-policy"]
        assert "'unsafe-inline'" not in home.headers["content-security-policy"]
        page = client.get("/lab")
        csp = page.headers["content-security-policy"]
        assert "script-src 'self';" in csp and "style-src 'self' 'unsafe-inline'" in csp
        assert page.headers["x-frame-options"] == "DENY"
