"""Security Lab API: the attack succeeds against the vulnerable signer and fails after each patch.

These are the automated versions of the live demonstration (report Chapters 4 and 5).
"""
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.lab.pdf_tools import make_pdf

CONTRACT = "CONTRACT #2026-11: Alice agrees to pay Bob 1,000 USD on 30/11/2026."
INV1 = "Invoice #1001: pay 100 USD to Supplier A"
INV2 = "Invoice #1002: pay 250 USD to Supplier B"
EVIL = "Invoice #6666: pay 1,000,000 USD to Eve's account"


def logged_in_client():
    client = TestClient(app)
    client.__enter__()
    response = client.post("/api/auth/register", json={
        "email": f"lab-{uuid.uuid4().hex[:10]}@example.com",
        "full_name": "Lab User",
        "password": "lab-user-strong-password-2026",
    })
    assert response.status_code == 200, response.text
    return client


def lab(client, action, body=None, status=200):
    token = client.get("/api/auth/csrf").json()["csrf_token"]
    response = client.post(f"/api/lab/{action}", json=body or {}, headers={"X-CSRF-Token": token})
    assert response.status_code == status, response.text
    return response.json()


def test_lab_requires_login_and_csrf():
    with TestClient(app) as anonymous:
        assert anonymous.post("/api/lab/ecdsa/start", json={}).status_code == 401
        assert anonymous.get("/lab").status_code == 200          # page loads, then asks to sign in
    client = logged_in_client()
    assert client.post("/api/lab/ecdsa/start", json={}).status_code == 403   # no CSRF header
    assert lab(client, "unknown/action", status=404)


def test_make_pdf_is_valid_and_deterministic():
    pdf = make_pdf(INV1)
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    assert pdf == make_pdf(INV1) and pdf != make_pdf(INV2)


def test_scene1_correct_use_detects_tampering_and_impostor():
    client = logged_in_client()
    lab(client, "demo1/keygen")
    lab(client, "demo1/sign", {"message": CONTRACT})
    genuine = lab(client, "demo1/verify", {"message": CONTRACT})
    assert genuine["rsa_ok"] and genuine["ec_ok"]
    tampered = lab(client, "demo1/verify", {"message": CONTRACT.replace("1,000", "9,000")})
    assert not tampered["rsa_ok"] and not tampered["ec_ok"] and tampered["bits_changed"] > 60
    impostor = lab(client, "demo1/eve_sign", {"message": CONTRACT})
    assert not impostor["rsa_ok"] and not impostor["ec_ok"]


def test_scene2_nonce_reuse_attack_forges_a_pdf_signature():
    client = logged_in_client()
    lab(client, "ecdsa/start", {"mode": "vulnerable"})
    s1 = lab(client, "ecdsa/sign", {"message": INV1})
    s2 = lab(client, "ecdsa/sign", {"message": INV2})
    assert s1["valid"] and s2["valid"] and s1["r"] == s2["r"]
    attack = lab(client, "ecdsa/attack")
    assert attack["reused"] and attack["matches"] and attack["d"] == attack["real_d"]
    forged = lab(client, "ecdsa/forge", {"message": EVIL})
    assert forged["accepted"] is True

    # The downloaded forgery verifies offline with an independent verifier.
    pdf = client.get("/api/lab/ecdsa/files/forged.pdf").content
    sig = client.get("/api/lab/ecdsa/files/forged.sig").content
    pem = client.get("/api/lab/ecdsa/files/public.pem").content
    assert pdf == make_pdf(EVIL, title="SecureSign Invoice")
    serialization.load_pem_public_key(pem).verify(sig, pdf, ec.ECDSA(hashes.SHA256()))


def test_scene3_rfc6979_defeats_the_same_attack():
    client = logged_in_client()
    lab(client, "ecdsa/start", {"mode": "patched"})
    s1 = lab(client, "ecdsa/sign", {"message": INV1})
    s2 = lab(client, "ecdsa/sign", {"message": INV2})
    assert s1["r"] != s2["r"]
    attack = lab(client, "ecdsa/attack")
    assert not attack["reused"] and not attack["matches"] and "refused" in attack
    assert lab(client, "ecdsa/forge", {"message": EVIL})["accepted"] is False
    cross = lab(client, "ecdsa/crosscheck", {"message": INV1})
    assert not cross["supported"] or cross["identical"]


def test_scene4_textbook_rsa_forgeable_pss_not():
    client = logged_in_client()
    result = lab(client, "rsa/run", {"m1": 100, "m2": 50})
    assert result["forged_m"] == 5000 and result["textbook_ok"] is True and result["pss_ok"] is False


def test_scene5_key_substitution_blocked_by_proof_of_possession():
    client = logged_in_client()
    setup = lab(client, "keysub/setup", {"message": CONTRACT})
    assert setup["alice_proof_ok"] is True
    legacy = lab(client, "keysub/legacy")
    assert legacy["registered"] and legacy["owner"] == "Eve" and legacy["signature_valid"]
    secure = lab(client, "keysub/secure")
    assert secure["accepted"] is False


def test_lab_state_is_isolated_per_user():
    alice, eve = logged_in_client(), logged_in_client()
    lab(alice, "ecdsa/start", {"mode": "vulnerable"})
    lab(alice, "ecdsa/sign", {"message": INV1})
    lab(alice, "ecdsa/sign", {"message": INV2})
    # Eve's lab is empty: she cannot run an attack on Alice's lab session.
    assert "Start" in lab(eve, "ecdsa/attack", status=400)["detail"]


def test_scene6_receipts_defeat_repudiation_and_log_tampering():
    client = logged_in_client()
    setup = lab(client, "evidence/setup", {"message": CONTRACT})
    assert setup["chain"]["ok"] and len(setup["entries"]) == 3
    deny = lab(client, "evidence/deny")
    assert deny["receipt_valid"] is True and deny["fake_valid"] is False
    edited = lab(client, "evidence/tamper", {"recompute": False})
    assert edited["check"]["ok"] is False and edited["check"]["broken_at"] == 2
    rehashed = lab(client, "evidence/tamper", {"recompute": True})
    assert rehashed["check"]["ok"] is False and "ký" in rehashed["check"]["reason"]
    assert rehashed["receipt_matches_log"] is False
