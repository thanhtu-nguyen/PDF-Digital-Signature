"""Regenerate the demo key files and sample PDFs in this folder.

    python demo_data/make_demo_data.py

The key files use exactly the format the SecureSign browser app produces
(RSA-2048 or ECDSA P-256 PKCS#8, encrypted with PBKDF2-HMAC-SHA256 + AES-256-GCM), so they can be
selected on the "Ký tài liệu" page with the demo key password. The server seeds
the matching public keys for the demo accounts (backend/app/demo_seed.py).

DEMO ONLY: these keys and passwords are published in the README. Never use them
for real documents; demo accounts are disabled when APP_ENV=production.
"""
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from backend.app.demo_seed import DEMO_KEY_PASSWORD, DEMO_USERS  # noqa: E402
from pdf_tools import make_pdf  # noqa: E402  (demo_data/pdf_tools.py)

ITERATIONS = 310_000
b64 = lambda data: base64.b64encode(data).decode()


def pem(label: str, der: bytes) -> str:
    body = base64.b64encode(der).decode()
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


def make_key_bundle(owner: str, algorithm: str = "RSA-PSS") -> dict:
    if algorithm == "ECDSA-P256":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pkcs8 = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    salt, iv = os.urandom(16), os.urandom(12)
    aes_key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(DEMO_KEY_PASSWORD.encode())
    ciphertext = AESGCM(aes_key).encrypt(iv, pkcs8, None)       # ciphertext || tag, same as Web Crypto
    return {
        "version": 1, "algorithm": algorithm, "hash": "SHA-256",
        **({"curve": "P-256"} if algorithm == "ECDSA-P256" else {"modulusLength": 2048}),
        "cipher": "AES-256-GCM", "kdf": "PBKDF2-SHA256", "iterations": ITERATIONS,
        "salt": b64(salt), "iv": b64(iv), "ciphertext": b64(ciphertext),
        "publicKeyPem": pem("PUBLIC KEY", spki), "fingerprint": hashlib.sha256(spki).hexdigest(),
        "owner": owner, "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def main():
    for user in DEMO_USERS:
        if user.get("key_file"):
            bundle = make_key_bundle(user["key_name"], user.get("key_algorithm", "RSA-PSS"))
            (HERE / user["key_file"]).write_text(json.dumps(bundle, indent=2) + "\n")
            print("wrote", user["key_file"], bundle["fingerprint"][:16])
    contract = ("CONTRACT #2026-11\nAlice Nguyen agrees to pay Bob Tran 1,000 USD on 30/11/2026\n"
                "for the delivery of 20 laptops (order SO-7781).")
    (HERE / "contract-demo.pdf").write_bytes(make_pdf(contract, title="SecureSign Contract"))
    (HERE / "contract-demo-tampered.pdf").write_bytes(
        make_pdf(contract.replace("1,000 USD", "9,000 USD"), title="SecureSign Contract"))
    print("wrote contract-demo.pdf, contract-demo-tampered.pdf")


if __name__ == "__main__":
    main()
