"""Signature verification used by every SecureSign endpoint.

Two signature algorithms are accepted, matching the midterm topic (RSA and ECC):
  * RSA-PSS   : RSA 2048-4096 bit, e = 65537, SHA-256, MGF1-SHA256, 32-byte salt
  * ECDSA-P256: NIST P-256 (secp256r1) with SHA-256, DER-encoded (r, s)
The algorithm is taken from the registered public key, never from the client,
so an attacker cannot downgrade a key to a weaker scheme.
"""
import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


RSA_BITS = 2048
PSS_SALT_LENGTH = 32
RSA_PSS = "RSA-PSS"
ECDSA_P256 = "ECDSA-P256"
ALGORITHM_LABELS = {RSA_PSS: "RSA-PSS · SHA-256", ECDSA_P256: "ECDSA P-256 · SHA-256"}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_public_key(public_key_pem: bytes):
    key = serialization.load_pem_public_key(public_key_pem)
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048 or key.key_size > 4096:
            raise ValueError("Khóa RSA phải có độ dài từ 2048 đến 4096 bit.")
        if key.public_numbers().e != 65537:
            raise ValueError("RSA Public Exponent phải bằng 65537.")
        return key
    if isinstance(key, ec.EllipticCurvePublicKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("Khóa ECC phải dùng đường cong NIST P-256 (secp256r1).")
        return key
    raise ValueError("Chỉ hỗ trợ khóa RSA (RSA-PSS) hoặc ECC P-256 (ECDSA).")


def key_algorithm(public_key) -> str:
    return ECDSA_P256 if isinstance(public_key, ec.EllipticCurvePublicKey) else RSA_PSS


def algorithm_of_pem(public_key_pem: str) -> str:
    try:
        return key_algorithm(serialization.load_pem_public_key(public_key_pem.encode("utf-8")))
    except Exception:
        return RSA_PSS


def public_key_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def verify_detached_signature(pdf_bytes: bytes, signature: bytes, public_key):
    """Raise InvalidSignature unless `signature` is valid for `pdf_bytes` under `public_key`."""
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        # Browsers produce raw r||s (IEEE P1363); SecureSign converts it to DER before saving,
        # which is also the format OpenSSL expects. Anything else is rejected by the library.
        public_key.verify(signature, pdf_bytes, ec.ECDSA(hashes.SHA256()))
        return
    public_key.verify(
        signature,
        pdf_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=PSS_SALT_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(pdf_bytes: bytes, signature: bytes, public_key_pem: bytes):
    public_key = load_public_key(public_key_pem)
    fingerprint = public_key_fingerprint(public_key)
    digest = sha256_hex(pdf_bytes)
    algorithm = key_algorithm(public_key)
    try:
        verify_detached_signature(pdf_bytes, signature, public_key)
        return {
            "valid": True,
            "sha256": digest,
            "fingerprint": fingerprint,
            "algorithm": algorithm,
            "message": "Chữ ký hợp lệ. Nội dung PDF khớp với chữ ký.",
        }
    except (InvalidSignature, ValueError):
        return {
            "valid": False,
            "sha256": digest,
            "fingerprint": fingerprint,
            "algorithm": algorithm,
            "message": "Chữ ký không hợp lệ hoặc tài liệu đã bị thay đổi.",
        }


def verify_proof_of_possession(public_key, challenge: str, proof_b64: str) -> bool:
    """Return True only if `proof_b64` is a signature (RSA-PSS or ECDSA, depending on
    the key) on the one-time server challenge made with the matching private key.

    This is what stops a key-substitution attack: anyone can copy a public key
    from the directory, but only the holder of the private key can sign a fresh
    random challenge, so nobody can register someone else's key as their own.
    """
    try:
        proof = base64.b64decode(proof_b64, validate=True)
        verify_detached_signature(challenge.encode("utf-8"), proof, public_key)
        return True
    except (ValueError, InvalidSignature):
        return False
