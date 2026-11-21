"""Security Lab crypto: P-256 core, RFC 6979 vector, nonce-reuse attack and defense."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from backend.lab import ecc_core as E
from backend.lab.attack import recover_nonce, recover_private_key


class TestCurve(unittest.TestCase):
    def test_generator_on_curve(self):
        self.assertTrue(E.is_on_curve(E.G))

    def test_order_of_generator(self):
        # (N-1)*G + G must be the point at infinity, i.e. G has order N
        self.assertIsNone(E.point_add(E.scalar_mult(E.N - 1), E.G))

    def test_public_key_matches_library(self):
        d, Q = E.generate_keypair()
        nums = E.to_crypto_private_key(d).public_key().public_numbers()
        self.assertEqual((nums.x, nums.y), Q)


class TestECDSA(unittest.TestCase):
    def test_sign_verify_and_tamper(self):
        d, Q = E.generate_keypair()
        sig = E.ecdsa_sign_rfc6979(b"hello", d)
        self.assertTrue(E.ecdsa_verify(b"hello", sig, Q))
        self.assertFalse(E.ecdsa_verify(b"hellO", sig, Q))

    def test_our_signature_verified_by_library(self):
        d, Q = E.generate_keypair()
        sig = E.ecdsa_sign_rfc6979(b"interop", d)
        E.to_crypto_public_key(Q).verify(E.sig_to_der(sig), b"interop", ec.ECDSA(hashes.SHA256()))

    def test_rfc6979_official_vector(self):
        # RFC 6979 Appendix A.2.5, P-256, SHA-256, message "sample"
        d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        self.assertEqual(E.rfc6979_nonce(d, b"sample"),
                         0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60)
        r, s = E.ecdsa_sign_rfc6979(b"sample", d)
        self.assertEqual(r, 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716)
        self.assertEqual(s, 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8)


class TestAttack(unittest.TestCase):
    def test_nonce_reuse_recovers_key(self):
        d, Q = E.generate_keypair()
        k = 123456789
        s1 = E.ecdsa_sign(b"m1", d, k)
        s2 = E.ecdsa_sign(b"m2", d, k)
        k_rec = recover_nonce(b"m1", s1, b"m2", s2)
        self.assertEqual(k_rec, k)
        self.assertEqual(recover_private_key(b"m1", s1, k_rec), d)

    def test_rfc6979_prevents_attack(self):
        d, _ = E.generate_keypair()
        s1 = E.ecdsa_sign_rfc6979(b"m1", d)
        s2 = E.ecdsa_sign_rfc6979(b"m2", d)
        self.assertNotEqual(s1[0], s2[0])
        with self.assertRaises(ValueError):
            recover_nonce(b"m1", s1, b"m2", s2)


if __name__ == "__main__":
    unittest.main()
