import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

from backend.app.crypto_service import verify_signature


def make_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


def sign(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def test_valid_signature():
    private_key, public_pem = make_pair()
    pdf = b"%PDF-1.7\\nexample PDF bytes"
    signature = sign(private_key, pdf)
    result = verify_signature(pdf, signature, public_pem)
    assert result["valid"] is True


def test_modified_pdf_fails():
    private_key, public_pem = make_pair()
    pdf = b"%PDF-1.7\\noriginal"
    signature = sign(private_key, pdf)
    result = verify_signature(b"%PDF-1.7\\nmodified", signature, public_pem)
    assert result["valid"] is False


def test_wrong_public_key_fails():
    private_key, _ = make_pair()
    _, wrong_public_pem = make_pair()
    pdf = b"%PDF-1.7\\nexample"
    signature = sign(private_key, pdf)
    result = verify_signature(pdf, signature, wrong_public_pem)
    assert result["valid"] is False
