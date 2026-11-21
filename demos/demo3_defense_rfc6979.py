"""
DEMO 3 - DEFENSE: patch the signer with RFC 6979 deterministic nonces.

The patch replaces the "generate k once" bug with k = HMAC-DRBG(d, H(m))
(RFC 6979). Every different message gets a different, unpredictable k, so
r values never repeat and the Demo 2 attack has nothing to work with.

We then re-run the exact same attack pipeline against the patched signer and
show that (a) no reused r is found, (b) forcing the formulas anyway gives a
wrong key, (c) the forged signature is REJECTED by the victim.

We also cross-check our RFC 6979 implementation against the audited
`cryptography` library (deterministic_signing=True): both must produce the
byte-identical signature.

Run:  python demo3_defense_rfc6979.py [--pause]
"""

import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # project root
from backend.lab import ecc_core as E
from backend.lab.attack import find_reused_nonce, recover_nonce, recover_private_key
from ui import banner, step, info, ok, fail, alert, short_hex, pause

PAUSE = "--pause" in sys.argv


class PatchedSigner:
    """FIX: a fresh deterministic nonce per message (RFC 6979)."""

    def __init__(self):
        self.d, self.Q = E.generate_keypair()

    def sign(self, message: bytes):
        k = E.rfc6979_nonce(self.d, message)       # k depends on (d, H(m))
        return E.ecdsa_sign(message, self.d, k)


def victim_verify(public_key, message, sig):
    try:
        public_key.verify(E.sig_to_der(sig), message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def main():
    banner("DEMO 3 - DEFENSE: RFC 6979 DETERMINISTIC NONCES")

    step("Step 1 - Patched signing service starts")
    signer = PatchedSigner()
    pub = E.to_crypto_public_key(signer.Q)
    info("Public key Qx:", short_hex(signer.Q[0]))

    step("Step 2 - Service signs the same two invoices as in Demo 2")
    m1 = b"Invoice #1001: pay 100 USD to Supplier A"
    m2 = b"Invoice #1002: pay 250 USD to Supplier B"
    sig1, sig2 = signer.sign(m1), signer.sign(m2)
    info("r1 =", short_hex(sig1[0]))
    info("r2 =", short_hex(sig2[0]))
    ok("r1 != r2 -> a different nonce was used for each message") if sig1[0] != sig2[0] \
        else fail("r1 == r2 !")
    sig1_again = signer.sign(m1)
    info("Re-sign m1:", "identical signature (deterministic, safe: same message)"
         if sig1_again == sig1 else "different")
    pause(PAUSE)

    step("Step 3 - Attacker re-runs the Demo 2 attack pipeline")
    pair = find_reused_nonce([(m1, sig1), (m2, sig2)])
    info("Repeated r found?", "YES" if pair else "NO")
    try:
        recover_nonce(m1, sig1, m2, sig2)
    except ValueError as exc:
        ok(f"recover_nonce() refused: {exc}")
    # Force the formulas anyway (pretend r1 == r2) to show the result is garbage
    k_guess = recover_nonce(m1, sig1, m2, (sig1[0], sig2[1]))
    d_guess = recover_private_key(m1, sig1, k_guess)
    match = E.scalar_mult(d_guess) == signer.Q
    info("Forced guess of d:", short_hex(d_guess))
    (fail if match else ok)("d_guess * G == Q ?  " + ("YES" if match else "NO -> key NOT recovered"))
    pause(PAUSE)

    step("Step 4 - Attacker tries to forge with the wrong key")
    evil = b"Invoice #6666: pay 1,000,000 USD to Attacker's account"
    forged = E.der_to_sig(E.to_crypto_private_key(d_guess).sign(evil, ec.ECDSA(hashes.SHA256())))
    rejected = not victim_verify(pub, evil, forged)
    (ok if rejected else fail)("Victim verification of forged invoice: "
                               + ("REJECTED" if rejected else "ACCEPTED"))

    step("Step 5 - Cross-check: our RFC 6979 vs cryptography (deterministic_signing=True)")
    lib_key = E.to_crypto_private_key(signer.d)
    try:
        lib_der = lib_key.sign(m1, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        same = E.der_to_sig(lib_der) == sig1
        (ok if same else fail)("Byte-identical signature: " + ("YES" if same else "NO"))
    except TypeError:
        same = True
        info("(cryptography < 44 has no deterministic_signing; cross-check skipped)")

    success = (not pair) and (not match) and rejected and same
    banner("RESULT: " + ("DEFENSE EFFECTIVE - nonce-reuse attack no longer works"
                         if success else "DEFENSE CHECK FAILED"))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
