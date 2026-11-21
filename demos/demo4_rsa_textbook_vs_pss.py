"""
DEMO 4 (bonus) - Textbook RSA malleability forgery vs. RSASSA-PSS.

Textbook RSA signs a number directly: s = m^d mod n. It is multiplicative:
    s1 * s2 = m1^d * m2^d = (m1*m2)^d  (mod n)
so an attacker holding signatures on m1 and m2 can produce a valid signature
on m1*m2 WITHOUT the private key. RSASSA-PSS (RFC 8017) hashes and randomly
pads the message first, which destroys this algebraic structure.

Run:  python demo4_rsa_textbook_vs_pss.py [--pause]
"""

import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ui import banner, step, info, ok, fail, alert, short_hex, pause

PAUSE = "--pause" in sys.argv


def main():
    banner("DEMO 4 - TEXTBOOK RSA FORGERY vs. RSASSA-PSS")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_numbers()
    n, e, d = priv.public_numbers.n, priv.public_numbers.e, priv.d

    def textbook_sign(m: int) -> int:
        return pow(m, d, n)

    def textbook_verify(m: int, s: int) -> bool:
        return pow(s, e, n) == m % n

    step("Step 1 - Victim signs two harmless amounts with TEXTBOOK RSA (no padding)")
    m1, m2 = 100, 50
    s1, s2 = textbook_sign(m1), textbook_sign(m2)
    info("sign(100) =", short_hex(s1.to_bytes(256, "big"), 12))
    info("sign(50)  =", short_hex(s2.to_bytes(256, "big"), 12))
    pause(PAUSE)

    step("Step 2 - Attacker multiplies the signatures (no private key used)")
    forged_m = m1 * m2
    forged_s = s1 * s2 % n
    info("forged message:", f"{forged_m}  (= 100 * 50)")
    if textbook_verify(forged_m, forged_s):
        alert("Textbook verify(5000, s1*s2) -> VALID. Forgery succeeded!")
    else:
        fail("Forgery rejected")
    pause(PAUSE)

    step("Step 3 - Same attack against RSASSA-PSS")
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    b1, b2, bf = b"100", b"50", b"5000"
    p1 = int.from_bytes(key.sign(b1, pss, hashes.SHA256()), "big")
    p2 = int.from_bytes(key.sign(b2, pss, hashes.SHA256()), "big")
    pf = (p1 * p2 % n).to_bytes(256, "big")
    try:
        key.public_key().verify(pf, bf, pss, hashes.SHA256())
        fail("PSS accepted the forged signature")
        pss_safe = False
    except InvalidSignature:
        ok("PSS verify('5000', s1*s2) -> INVALID. Padding blocks the forgery.")
        pss_safe = True

    banner("RESULT: textbook RSA forgeable, RSA-PSS secure" if pss_safe else "UNEXPECTED")
    return 0 if pss_safe else 1


if __name__ == "__main__":
    sys.exit(main())
