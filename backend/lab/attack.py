"""
attack.py - ECDSA nonce-reuse private key recovery.

Given two signatures (r, s1) on m1 and (r, s2) on m2 produced with the SAME
private key d and the SAME nonce k:

    s1 = k^-1 (h1 + r*d)  mod n
    s2 = k^-1 (h2 + r*d)  mod n

Subtracting removes the unknown r*d term:

    s1 - s2 = k^-1 (h1 - h2)          =>  k = (h1 - h2) / (s1 - s2)  mod n
    s1*k    = h1 + r*d                =>  d = (s1*k - h1) / r        mod n

The attacker only needs PUBLIC data: the two messages and the two signatures.
"""

from .ecc_core import N, inv, hash_to_int


def find_reused_nonce(signatures):
    """Scan a list of (message, (r, s)) and return the first pair that shares r."""
    seen = {}
    for msg, (r, s) in signatures:
        if r in seen and seen[r][0] != msg:
            return seen[r], (msg, (r, s))
        seen[r] = (msg, (r, s))
    return None


def recover_nonce(m1: bytes, sig1, m2: bytes, sig2) -> int:
    r1, s1 = sig1
    r2, s2 = sig2
    if r1 != r2:
        raise ValueError("r values differ: the nonce was NOT reused, attack impossible")
    h1, h2 = hash_to_int(m1), hash_to_int(m2)
    if (s1 - s2) % N == 0:
        raise ValueError("s1 == s2: messages hash to the same value")
    return (h1 - h2) * inv(s1 - s2, N) % N


def recover_private_key(m1: bytes, sig1, k: int) -> int:
    r, s1 = sig1
    h1 = hash_to_int(m1)
    return (s1 * k - h1) * inv(r, N) % N
