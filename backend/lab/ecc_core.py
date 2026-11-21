"""
ecc_core.py - Minimal, educational ECDSA implementation over NIST P-256.

WARNING: This module exists ONLY to make the nonce-reuse vulnerability visible.
Audited libraries (e.g. `cryptography`) never let the caller choose the nonce k,
so to reproduce the bug we need our own signer that does. Do NOT use this code
to protect real data: it is not constant-time and has no side-channel hardening.

Contents
  * P-256 domain parameters (FIPS 186-5 / SEC 2)
  * Affine point arithmetic (add, double, scalar multiply)
  * ecdsa_sign(msg, d, k)        -> signer that accepts an explicit nonce k
  * ecdsa_verify(msg, sig, Q)    -> textbook verification
  * rfc6979_nonce(d, h)          -> deterministic nonce (the fix, RFC 6979)
  * Conversion helpers to/from the `cryptography` library key objects
"""

import hashlib
import hmac
import secrets

# --------------------------------------------------------------------------- #
# NIST P-256 (secp256r1) domain parameters: y^2 = x^3 + a*x + b  (mod p)
# --------------------------------------------------------------------------- #
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (GX, GY)
INF = None  # point at infinity


def inv(x: int, m: int) -> int:
    """Modular inverse (Python 3.8+ supports pow(x, -1, m))."""
    return pow(x, -1, m)


def is_on_curve(pt) -> bool:
    if pt is INF:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1, p2):
    if p1 is INF:
        return p2
    if p2 is INF:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return INF
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k: int, pt=G):
    """Double-and-add scalar multiplication k*pt."""
    result = INF
    addend = pt
    k %= N
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# --------------------------------------------------------------------------- #
# Hashing helper
# --------------------------------------------------------------------------- #
def hash_to_int(message: bytes) -> int:
    """h = SHA-256(message) interpreted as an integer (256 bits = bit length of N)."""
    return int.from_bytes(hashlib.sha256(message).digest(), "big")


# --------------------------------------------------------------------------- #
# Key generation, signing, verification
# --------------------------------------------------------------------------- #
def generate_keypair():
    d = secrets.randbelow(N - 1) + 1          # private scalar in [1, N-1] from a CSPRNG
    Q = scalar_mult(d, G)                     # public point Q = d*G
    return d, Q


def ecdsa_sign(message: bytes, d: int, k: int):
    """
    ECDSA signing with a CALLER-SUPPLIED nonce k.
    Security depends entirely on k being secret, unpredictable and NEVER reused.
    """
    h = hash_to_int(message)
    R = scalar_mult(k, G)
    r = R[0] % N
    if r == 0:
        raise ValueError("bad nonce: r == 0")
    s = inv(k, N) * (h + r * d) % N
    if s == 0:
        raise ValueError("bad nonce: s == 0")
    return r, s


def ecdsa_verify(message: bytes, sig, Q) -> bool:
    r, s = sig
    if not (1 <= r < N and 1 <= s < N):
        return False
    h = hash_to_int(message)
    w = inv(s, N)
    u1 = h * w % N
    u2 = r * w % N
    X = point_add(scalar_mult(u1, G), scalar_mult(u2, Q))
    if X is INF:
        return False
    return X[0] % N == r


# --------------------------------------------------------------------------- #
# RFC 6979 deterministic nonce generation (HMAC-DRBG with SHA-256)
# --------------------------------------------------------------------------- #
def _int2octets(x: int) -> bytes:
    return x.to_bytes(32, "big")


def _bits2octets(h: bytes) -> bytes:
    z = int.from_bytes(h, "big") % N
    return _int2octets(z)


def rfc6979_nonce(d: int, message: bytes) -> int:
    """k = HMAC_DRBG(private key, H(message)) as specified in RFC 6979 section 3.2.
    Same (d, message) -> same k; different message -> unrelated k."""
    h1 = hashlib.sha256(message).digest()
    V = b"\x01" * 32
    K = b"\x00" * 32
    seed = _int2octets(d) + _bits2octets(h1)
    K = hmac.new(K, V + b"\x00" + seed, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + seed, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, "big")
        if 1 <= k < N:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def ecdsa_sign_rfc6979(message: bytes, d: int):
    return ecdsa_sign(message, d, rfc6979_nonce(d, message))


# --------------------------------------------------------------------------- #
# Interoperability with the audited `cryptography` library
# --------------------------------------------------------------------------- #
def to_crypto_public_key(Q):
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.EllipticCurvePublicNumbers(Q[0], Q[1], ec.SECP256R1()).public_key()


def to_crypto_private_key(d: int):
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.derive_private_key(d, ec.SECP256R1())


def sig_to_der(sig) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    return encode_dss_signature(sig[0], sig[1])


def der_to_sig(der: bytes):
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    return decode_dss_signature(der)
