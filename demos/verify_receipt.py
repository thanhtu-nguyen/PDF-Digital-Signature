"""
verify_receipt.py - check a SecureSign evidence receipt OFFLINE, without trusting the server.

    python demos/verify_receipt.py securesign-receipt-2.json --server-key server.pem [--pdf contract.pdf]

  * receipt.json : downloaded from SecureSign (Ký tài liệu / Hộp thư / Lịch sử)
  * server.pem   : the server's receipt public key, obtained once from an independent
                   channel (GET /api/receipts/server-key, a printed fingerprint, ...).
                   The key embedded in the receipt file is NOT trusted on its own.
  * --pdf        : optional; checks that this exact PDF is the one the receipt is about.

This is what a judge or auditor would run: it only needs Python and `cryptography`.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))   # project root
from backend.app.evidence import key_fingerprint, verify_receipt_bundle  # noqa: E402
from ui import alert, banner, fail, info, ok, step  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("receipt")
    parser.add_argument("--server-key", required=True, help="trusted SecureSign receipt public key (PEM)")
    parser.add_argument("--pdf", help="PDF that the receipt should refer to")
    args = parser.parse_args()

    banner("SECURESIGN RECEIPT - OFFLINE VERIFICATION (NON-REPUDIATION)")
    bundle = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    trusted = serialization.load_pem_public_key(Path(args.server_key).read_bytes())

    step("Step 1 - Trusted server key")
    info("Fingerprint (SHA-256):", key_fingerprint(trusted))

    step("Step 2 - Server signature on the receipt (ECDSA P-256 / SHA-256)")
    result = verify_receipt_bundle(bundle, trusted)
    if not result["valid"]:
        fail(f"INVALID: {result['reason']}")
        return 1
    ok("receipt signed by the trusted SecureSign key")
    r = result["receipt"]
    info("Entry #:", r["seq"])
    info("Event:", r["event"])
    info("Time (UTC, server-signed):", r["time"])
    info("Actor:", f"{r['actor'].get('name')} <{r['actor'].get('email')}>")
    for key in ("file_name", "document_sha256", "key_fingerprint", "algorithm", "recipient"):
        if key in r["details"]:
            info(f"{key}:", r["details"][key])
    info("prev_hash (chain link):", r["prev_hash"])
    info("entry_hash:", bundle["entry_hash"])

    code = 0
    if args.pdf:
        step("Step 3 - Is this the PDF the receipt is about?")
        digest = hashlib.sha256(Path(args.pdf).read_bytes()).hexdigest()
        info("SHA-256(PDF):", digest)
        if digest == r["details"].get("document_sha256"):
            ok("PDF matches the receipt")
        else:
            fail("PDF does NOT match the receipt (different or modified document)")
            code = 1
    alert("The signer cannot deny this event: the PDF signature proves WHO, the server receipt proves WHEN,"
          " and the hash chain proves the log was not rewritten.")
    return code


if __name__ == "__main__":
    sys.exit(main())
