"""
DEMO 2 - ATTACK: ECDSA nonce reuse -> private key recovery -> signature forgery.

Scenario
  * "SecureSign Corp" runs a signing service with a buggy ECDSA implementation:
    the developer seeded the nonce once at start-up, so every signature reuses k
    (the same class of bug as the 2010 Sony PS3 firmware-signing key leak).
  * The attacker only observes PUBLIC data: two signed messages + public key.
  * The attacker recovers k, then the private key d, forges a signature on a
    malicious message, and the VICTIM verifies it with the audited
    `cryptography` library -> signature ACCEPTED.

Run:  python demo2_nonce_reuse_attack.py [--pause]
"""

import json
import secrets
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # project root
from backend.lab import ecc_core as E
from backend.lab.attack import find_reused_nonce, recover_nonce, recover_private_key
from ui import banner, step, info, ok, fail, alert, short_hex, pause

OUT = Path(__file__).parent / "output"
PAUSE = "--pause" in sys.argv


class VulnerableSigner:
    """The victim's signing service. BUG: the nonce is generated ONCE and reused."""

    def __init__(self):
        self.d, self.Q = E.generate_keypair()
        self._k = secrets.randbelow(E.N - 1) + 1   # random... but only ONCE  <-- BUG

    def sign(self, message: bytes):
        return E.ecdsa_sign(message, self.d, self._k)   # same k every call


def victim_verify(public_key, message: bytes, sig) -> bool:
    """The relying party uses the AUDITED library to verify. It still gets fooled."""
    try:
        public_key.verify(E.sig_to_der(sig), message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def main():
    banner("DEMO 2 - ECDSA NONCE-REUSE ATTACK (PRIVATE KEY RECOVERY)")

    # ------------------------------------------------------------------ #
    step("Step 1 - Initialization: the victim's vulnerable signing service starts")
    signer = VulnerableSigner()
    pub = E.to_crypto_public_key(signer.Q)
    info("Curve:", "NIST P-256")
    info("Public key Qx (public):", short_hex(signer.Q[0]))
    info("Public key Qy (public):", short_hex(signer.Q[1]))
    info("Private key d (SECRET):", short_hex(signer.d))
    pause(PAUSE)

    # ------------------------------------------------------------------ #
    step("Step 2 - The service signs two ordinary documents (published on the network)")
    m1 = b"Invoice #1001: pay 100 USD to Supplier A"
    m2 = b"Invoice #1002: pay 250 USD to Supplier B"
    sig1 = signer.sign(m1)
    sig2 = signer.sign(m2)
    for m, (r, s) in ((m1, sig1), (m2, sig2)):
        info("message:", m.decode())
        info("   r =", short_hex(r))
        info("   s =", short_hex(s))
        info("   victim verifies:", "VALID" if victim_verify(pub, m, (r, s)) else "INVALID")
    OUT.mkdir(exist_ok=True)
    (OUT / "intercepted_signatures.json").write_text(json.dumps({
        "public_key": {"x": hex(signer.Q[0]), "y": hex(signer.Q[1])},
        "signatures": [{"message": m1.decode(), "r": hex(sig1[0]), "s": hex(sig1[1])},
                       {"message": m2.decode(), "r": hex(sig2[0]), "s": hex(sig2[1])}]},
        indent=2))
    pause(PAUSE)

    # ------------------------------------------------------------------ #
    step("Step 3 - ATTACK: attacker scans intercepted signatures for a repeated r")
    pair = find_reused_nonce([(m1, sig1), (m2, sig2)])
    if not pair:
        fail("No repeated r found - attack not possible")
        return 1
    (ma, sa), (mb, sb) = pair
    alert(f"r1 == r2 -> the SAME nonce k was used twice!")
    info("k = (h1 - h2) / (s1 - s2) mod n")
    k = recover_nonce(ma, sa, mb, sb)
    info("recovered k:", short_hex(k))
    info("d = (s1*k - h1) / r mod n")
    d_rec = recover_private_key(ma, sa, k)
    info("recovered d:", short_hex(d_rec))
    pause(PAUSE)

    step("Step 4 - Check the recovered key against the PUBLIC key (d*G == Q ?)")
    if E.scalar_mult(d_rec) == signer.Q:
        info("victim's real d (hidden):", short_hex(signer.d))
        alert("d_recovered * G == Q  ->  PRIVATE KEY FULLY RECOVERED")
    else:
        fail("Recovered key does not match")
        return 1
    pause(PAUSE)

    # ------------------------------------------------------------------ #
    step("Step 5 - Forgery: attacker signs a malicious message with the stolen key")
    evil = b"Invoice #6666: pay 1,000,000 USD to Attacker's account"
    stolen = E.to_crypto_private_key(d_rec)               # import into a normal library
    forged_der = stolen.sign(evil, ec.ECDSA(hashes.SHA256()))
    forged = E.der_to_sig(forged_der)
    info("malicious message:", evil.decode())
    info("forged r:", short_hex(forged[0]))
    info("forged s:", short_hex(forged[1]))
    (OUT / "forged_signature.json").write_text(json.dumps(
        {"message": evil.decode(), "r": hex(forged[0]), "s": hex(forged[1])}, indent=2))

    step("Step 6 - Verification: victim checks the forged message with the REAL public key")
    accepted = victim_verify(pub, evil, forged)
    if accepted:
        alert("cryptography.verify() -> VALID. The forged invoice is ACCEPTED as genuine!")
        alert("Integrity, authentication and NON-REPUDIATION are broken.")
    else:
        fail("Forged signature rejected")

    banner("RESULT: " + ("ATTACK SUCCESSFUL - private key recovered from 2 public signatures"
                         if accepted else "ATTACK FAILED"))
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
