import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


RSA_BITS = 2048
PSS_SALT_LENGTH = 32


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_public_key(public_key_pem: bytes):
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Tệp khóa công khai không phải khóa RSA.")
    if key.key_size < 2048 or key.key_size > 4096:
        raise ValueError("Khóa RSA phải có độ dài từ 2048 đến 4096 bit.")
    if key.public_numbers().e != 65537:
        raise ValueError("RSA Public Exponent phải bằng 65537.")
    return key


def public_key_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def verify_detached_signature(pdf_bytes: bytes, signature: bytes, public_key):
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
    try:
        verify_detached_signature(pdf_bytes, signature, public_key)
        return {
            "valid": True,
            "sha256": digest,
            "fingerprint": fingerprint,
            "message": "Chữ ký hợp lệ. Nội dung PDF khớp với chữ ký.",
        }
    except InvalidSignature:
        return {
            "valid": False,
            "sha256": digest,
            "fingerprint": fingerprint,
            "message": "Chữ ký không hợp lệ hoặc tài liệu đã bị thay đổi.",
        }
