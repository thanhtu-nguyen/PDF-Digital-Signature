"""
DEMO 1 - Correct use of digital signatures (RSA-PSS and ECDSA P-256).

Goal: show integrity, authentication and non-repudiation when signatures are
implemented with an audited library (`cryptography`):
  1. Generate an RSA-2048 key pair and an ECDSA P-256 key pair.
  2. Sign a contract message with each private key.
  3. Verify with the public keys        -> ACCEPTED
  4. Change ONE character of the message -> REJECTED (integrity)
  5. Verify with someone else's key     -> REJECTED (authentication)

Run:  python demo1_correct_use.py [--pause]
"""

import hashlib
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from ui import banner, step, info, ok, fail, alert, short_hex, pause

OUT = Path(__file__).parent / "output"
PAUSE = "--pause" in sys.argv

MESSAGE = b"CONTRACT #2026-11: Alice agrees to pay Bob 1,000 USD on 30/11/2026."
TAMPERED = b"CONTRACT #2026-11: Alice agrees to pay Bob 9,000 USD on 30/11/2026."

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def save_pem(name, private_key):
    OUT.mkdir(exist_ok=True)
    (OUT / f"{name}_private.pem").write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (OUT / f"{name}_public.pem").write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def verify(label, public_key, signature, message, algo, expect_valid=True):
    """Return True if the signature verifies. Prints OK when the outcome is the expected one."""
    try:
        if algo == "rsa":
            public_key.verify(signature, message, PSS, hashes.SHA256())
        else:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        (ok if expect_valid else fail)(f"{label}: signature VALID")
        return True
    except InvalidSignature:
        (fail if expect_valid else ok)(f"{label}: signature INVALID -> rejected")
        return False


def main():
    banner("DEMO 1 - CORRECT USE OF DIGITAL SIGNATURES (RSA-PSS & ECDSA P-256)")

    step("Step 1 - SHA-256 avalanche effect (why we sign the hash)")
    h1 = hashlib.sha256(MESSAGE).hexdigest()
    h2 = hashlib.sha256(TAMPERED).hexdigest()
    diff = sum(bin(int(a, 16) ^ int(b, 16)).count("1") for a, b in zip(h1, h2))
    info("Original message:", MESSAGE.decode())
    info("Tampered message:", TAMPERED.decode())
    info("SHA-256(original):", h1)
    info("SHA-256(tampered):", h2)
    info("Bits changed:", f"{diff}/256  (only 1 character was modified)")
    pause(PAUSE)

    step("Step 2 - Key generation")
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    save_pem("rsa2048", rsa_key)
    save_pem("ecdsa_p256", ec_key)
    info("RSA modulus n:", f"{rsa_key.key_size} bits, e = {rsa_key.public_key().public_numbers().e}")
    info("ECDSA curve:", "NIST P-256 (secp256r1)")
    info("ECDSA public key Qx:", short_hex(ec_key.public_key().public_numbers().x))
    info("Keys saved to:", str(OUT))
    pause(PAUSE)

    step("Step 3 - Signing the contract")
    rsa_sig = rsa_key.sign(MESSAGE, PSS, hashes.SHA256())
    ec_sig = ec_key.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))
    (OUT / "message.txt").write_bytes(MESSAGE)
    (OUT / "message.rsa.sig").write_bytes(rsa_sig)
    (OUT / "message.ecdsa.sig").write_bytes(ec_sig)
    info("RSA-PSS signature:", f"{len(rsa_sig)} bytes  {short_hex(rsa_sig, 16)}")
    info("ECDSA signature (DER):", f"{len(ec_sig)} bytes  {short_hex(ec_sig, 16)}")
    alert("ECDSA signature is ~4x smaller than RSA at higher security level")
    pause(PAUSE)

    step("Step 4 - Verification of the ORIGINAL message")
    r1 = verify("RSA-PSS  ", rsa_key.public_key(), rsa_sig, MESSAGE, "rsa")
    r2 = verify("ECDSA    ", ec_key.public_key(), ec_sig, MESSAGE, "ec")

    step("Step 5 - Integrity test: attacker changes 1,000 USD -> 9,000 USD")
    r3 = verify("RSA-PSS  ", rsa_key.public_key(), rsa_sig, TAMPERED, "rsa", False)
    r4 = verify("ECDSA    ", ec_key.public_key(), ec_sig, TAMPERED, "ec", False)

    step("Step 6 - Authentication test: verify with an impostor's public key")
    impostor_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    impostor_ec = ec.generate_private_key(ec.SECP256R1())
    r5 = verify("RSA-PSS  ", impostor_rsa.public_key(), rsa_sig, MESSAGE, "rsa", False)
    r6 = verify("ECDSA    ", impostor_ec.public_key(), ec_sig, MESSAGE, "ec", False)

    step("Step 7 - Randomized signatures (PSS salt / ECDSA nonce)")
    rsa_sig_b = rsa_key.sign(MESSAGE, PSS, hashes.SHA256())
    ec_sig_b = ec_key.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))
    info("RSA, same msg twice:", "different bytes" if rsa_sig != rsa_sig_b else "identical")
    info("ECDSA, same msg twice:", "different bytes" if ec_sig != ec_sig_b else "identical")
    alert("The library draws a FRESH random nonce k for every ECDSA signature")

    passed = r1 and r2 and not (r3 or r4 or r5 or r6)
    banner("RESULT: " + ("SUCCESS - valid accepted, tampered/impostor rejected"
                         if passed else "UNEXPECTED RESULT"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
