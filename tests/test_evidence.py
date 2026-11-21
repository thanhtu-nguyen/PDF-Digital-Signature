"""ECDSA P-256 keys in SecureSign, signed receipts and the hash-chained evidence log."""
import base64
import json
import subprocess
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.app.database import EvidenceEntry, SessionLocal
from backend.app.evidence import GENESIS_HASH, build_entry, verify_entries, verify_receipt_bundle
from backend.app.main import app
from backend.lab.pdf_tools import make_pdf

ROOT = Path(__file__).resolve().parents[1]
PDF = make_pdf("CONTRACT #2026-11: Alice pays Bob 1,000 USD", title="SecureSign Contract")


def new_user(prefix):
    client = TestClient(app); client.__enter__()
    email = f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"
    r = client.post("/api/auth/register", json={"email": email, "full_name": prefix.title(), "password": "strong-password-2026-x"})
    assert r.status_code == 200, r.text
    return client, email, {"X-CSRF-Token": r.json()["csrf_token"]}


def register_ec_key(client, csrf):
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    challenge = client.post("/api/keys/challenge", headers=csrf).json()
    proof = key.sign(challenge["challenge"].encode(), ec.ECDSA(hashes.SHA256()))     # DER, like the browser after conversion
    r = client.post("/api/keys", headers=csrf, json={"name": "EC key", "public_key_pem": pem,
                                                    "challenge_id": challenge["challenge_id"],
                                                    "proof_signature": base64.b64encode(proof).decode()})
    assert r.status_code == 200, r.text
    assert r.json()["item"]["algorithm"] == "ECDSA-P256"
    return key, r.json()["item"]


def test_ecdsa_key_signing_receipts_and_chain(tmp_path):
    alice, alice_email, a_csrf = new_user("alice")
    bob, bob_email, b_csrf = new_user("bob")
    charlie, _, _ = new_user("charlie")
    key, item = register_ec_key(alice, a_csrf)

    # ECDSA signature on a PDF: ~70 bytes, verified by the server, receipt issued.
    sig = key.sign(PDF, ec.ECDSA(hashes.SHA256()))
    assert len(sig) < 80
    files = {"pdf": ("c.pdf", PDF, "application/pdf"), "signature": ("c.sig", sig, "application/octet-stream")}
    signed = alice.post("/api/history/sign", headers=a_csrf, data={"key_id": item["id"]}, files=files)
    assert signed.status_code == 200, signed.text
    assert signed.json()["algorithm"] == "ECDSA-P256"
    seq = signed.json()["receipt_seq"]

    # A wrong (RSA-sized garbage) signature is rejected for the EC key.
    bad = alice.post("/api/history/sign", headers=a_csrf, data={"key_id": item["id"]},
                     files={"pdf": ("c.pdf", PDF, "application/pdf"), "signature": ("c.sig", b"\x00" * 256, "application/octet-stream")})
    assert bad.status_code == 400

    # Receipt: downloadable by Alice, verifiable through the API and offline with the published key.
    bundle = alice.get(f"/api/receipts/{seq}").json()
    assert bundle["receipt"]["event"] == "PDF_SIGNED" and bundle["receipt"]["details"]["document_sha256"]
    assert alice.post("/api/receipts/verify", headers=a_csrf, json=bundle).json()["valid"] is True
    server_key = alice.get("/api/receipts/server-key").json()
    trusted = serialization.load_pem_public_key(server_key["public_key_pem"].encode())
    assert verify_receipt_bundle(bundle, trusted)["valid"] is True

    # Changing the time in a receipt breaks it; a receipt signed by another key is rejected.
    forged = json.loads(json.dumps(bundle)); forged["receipt"]["time"] = "2030-01-01T00:00:00Z"
    forged["signed_body"] = json.dumps(forged["receipt"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert alice.post("/api/receipts/verify", headers=a_csrf, json=forged).json()["valid"] is False
    other = ec.generate_private_key(ec.SECP256R1())
    fake = build_entry(other, seq, bundle["receipt"]["prev_hash"], "PDF_SIGNED", bundle["receipt"]["actor"], bundle["receipt"]["details"])
    fake_bundle = dict(bundle, signed_body=fake["body"], receipt=json.loads(fake["body"]), entry_hash=fake["entry_hash"], signature=fake["signature"],
                       server_public_key_pem=other.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())
    assert verify_receipt_bundle(fake_bundle, trusted)["valid"] is False

    # Offline verifier used in the report.
    (tmp_path / "r.json").write_text(json.dumps(bundle)); (tmp_path / "s.pem").write_text(server_key["public_key_pem"])
    (tmp_path / "c.pdf").write_bytes(PDF)
    run = subprocess.run([sys.executable, "demos/verify_receipt.py", str(tmp_path / "r.json"), "--server-key", str(tmp_path / "s.pem"),
                          "--pdf", str(tmp_path / "c.pdf")], cwd=ROOT, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr

    # Send to Bob: both parties can fetch the DOCUMENT_SENT receipt, an outsider cannot.
    sent = alice.post("/api/documents/send", headers=a_csrf, data={"recipient_email": bob_email, "key_id": item["id"]}, files=files)
    assert sent.status_code == 200, sent.text
    doc_seq = sent.json()["item"]["receipt_seq"]
    assert bob.get(f"/api/receipts/{doc_seq}").status_code == 200
    assert charlie.get(f"/api/receipts/{doc_seq}").status_code == 404
    assert charlie.get(f"/api/receipts/{seq}").status_code == 404
    history = alice.get("/api/history").json()["items"]
    assert any(h["receipt_seq"] == seq for h in history)


def test_admin_integrity_check_detects_database_tampering():
    admin = TestClient(app); admin.__enter__()
    assert admin.post("/api/auth/login", json={"email": "root@example.com", "password": "test-admin-password-very-long"}).status_code == 200
    alice, _, csrf = new_user("alice")
    register_ec_key(alice, csrf)                       # guarantees at least one entry
    assert admin.get("/api/admin/evidence").json()["check"]["ok"] is True
    with SessionLocal.begin() as db:
        entry = db.scalar(select(EvidenceEntry).order_by(EvidenceEntry.seq.desc()).limit(1))
        original, seq = entry.body, entry.seq
        entry.body = original.replace('"KEY_REGISTERED"', '"KEY_REVOKED"')
    try:
        check = admin.get("/api/admin/evidence").json()["check"]
        assert check["ok"] is False and check["broken_at"] == seq
    finally:
        with SessionLocal.begin() as db:
            db.get(EvidenceEntry, seq).body = original
    assert admin.get("/api/admin/evidence").json()["check"]["ok"] is True
    # Non-admins cannot read the log.
    assert alice.get("/api/admin/evidence").status_code == 403


def test_verify_entries_pure_chain():
    key = ec.generate_private_key(ec.SECP256R1())
    chain, prev = [], GENESIS_HASH
    for i in range(1, 4):
        e = build_entry(key, i, prev, "PDF_SIGNED", {"id": "a"}, {"n": i}); chain.append(e); prev = e["entry_hash"]
    assert verify_entries(chain, key.public_key())["ok"]
    assert verify_entries(chain[:1] + chain[2:], key.public_key())["broken_at"] == 3       # deleted entry
    assert verify_entries(list(reversed(chain)), key.public_key())["ok"] is False           # reordered
