"""
lab.py - SecureSign Security Lab (attack and defense demonstration).

The lab is the part of the project that shows, step by step, how digital
signatures fail when they are implemented badly and how SecureSign prevents
each failure. Every endpoint runs real code: the educational P-256 module
(backend/lab/ecc_core.py), the attack (backend/lab/attack.py), the audited
`cryptography` library and SecureSign's own production checks
(crypto_service.verify_signature / verify_proof_of_possession). Nothing is
pre-recorded.

Scenes
  1. correct   RSA-PSS and ECDSA sign a contract PDF; tampering and impersonation are rejected.
  2. attack    A signing service reuses the ECDSA nonce k. Eve recovers the private key from two
               signed invoice PDFs and forges a third one that the bank accepts.
  3. defense   Same attack against the RFC 6979 signer: it fails.
  4. rsa       Textbook RSA is multiplicatively forgeable; RSA-PSS is not.
  5. keysub    Key substitution: Eve registers Alice's public key under her own account.
               A registry without proof-of-possession accepts it; SecureSign rejects it.
  6. evidence  Non-repudiation: Alice signs, SecureSign issues a signed, timestamped receipt in a
               hash-chained log; Alice later denies it, and an insider edits the log. The receipt
               and the chain (evidence.py, the same code as production) expose both.

State is kept in memory per logged-in user, so two people can run the lab at
the same time without seeing each other's keys. All POST endpoints require the
same session + CSRF protection as the rest of the API.
"""

import base64
import hashlib
import json
import secrets
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from fastapi import APIRouter, Body, Depends, HTTPException, Response

from ..lab import ecc_core as E
from ..lab.attack import find_reused_nonce, recover_nonce, recover_private_key
from ..lab.pdf_tools import make_pdf
from .crypto_service import (
    PSS_SALT_LENGTH, public_key_fingerprint, verify_proof_of_possession, verify_signature,
)
from .database import User
from .evidence import GENESIS_HASH, build_entry, receipt_bundle, verify_entries, verify_receipt_bundle
from .security import get_current_user, require_csrf

router = APIRouter(prefix="/api/lab", tags=["security-lab"])

# Same RSA-PSS parameters as the SecureSign signing page (Web Crypto, salt = 32 bytes).
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT_LENGTH)
MAX_TEXT = 300


def hx(x: int) -> str:
    return f"{x:064x}"


def _text(req: dict, key: str = "message") -> str:
    value = str(req.get(key, "")).strip()
    if not value or len(value) > MAX_TEXT:
        raise ValueError(f"'{key}' must contain 1 to {MAX_TEXT} characters.")
    return value


def lib_verify_ecdsa(public_key, data: bytes, sig) -> bool:
    """Relying party: verification with the audited `cryptography` library."""
    try:
        public_key.verify(E.sig_to_der(sig), data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _rsa_ok(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data, PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def _pem(public_key) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


# --------------------------------------------------------------------------- #
# Scene 1 - correct use (RSA-PSS and ECDSA P-256 with the audited library)
# --------------------------------------------------------------------------- #
class CorrectUse:
    def __init__(self):
        self.rsa_key = self.ec_key = self.rsa_imp = self.ec_imp = None
        self.signed_pdf = self.rsa_sig = self.ec_sig = None

    def keygen(self, _):
        t = time.perf_counter()
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec_key = ec.generate_private_key(ec.SECP256R1())
        self.rsa_imp = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec_imp = ec.generate_private_key(ec.SECP256R1())
        self.signed_pdf = self.rsa_sig = self.ec_sig = None
        pn = self.ec_key.public_key().public_numbers()
        return {"rsa_n": f"{self.rsa_key.public_key().public_numbers().n:x}",
                "rsa_fingerprint": public_key_fingerprint(self.rsa_key.public_key()),
                "ec_d": hx(self.ec_key.private_numbers().private_value),
                "rsa_e": 65537, "rsa_bits": 2048, "ec_qx": hx(pn.x), "ec_qy": hx(pn.y),
                "ms": round((time.perf_counter() - t) * 1000)}

    def sign(self, req):
        if self.rsa_key is None:
            self.keygen(None)
        pdf = make_pdf(_text(req), title="SecureSign Contract")
        self.signed_pdf = pdf
        self.rsa_sig = self.rsa_key.sign(pdf, PSS, hashes.SHA256())
        self.ec_sig = self.ec_key.sign(pdf, ec.ECDSA(hashes.SHA256()))
        return {"hash": hashlib.sha256(pdf).hexdigest(), "pdf_bytes": len(pdf),
                "rsa_sig": self.rsa_sig.hex(), "ec_sig": self.ec_sig.hex(),
                "rsa_len": len(self.rsa_sig), "ec_len": len(self.ec_sig)}

    def verify(self, req):
        if self.signed_pdf is None:
            raise ValueError("Sign the contract first.")
        pdf = make_pdf(_text(req), title="SecureSign Contract")
        # The RSA check is the exact function the SecureSign server uses for uploaded PDFs.
        rsa_result = verify_signature(pdf, self.rsa_sig, _pem(self.rsa_key.public_key()).encode())
        try:
            self.ec_key.public_key().verify(self.ec_sig, pdf, ec.ECDSA(hashes.SHA256()))
            ec_ok = True
        except InvalidSignature:
            ec_ok = False
        h_signed = hashlib.sha256(self.signed_pdf).hexdigest()
        h_now = rsa_result["sha256"]
        bits = bin(int(h_signed, 16) ^ int(h_now, 16)).count("1")
        return {"rsa_ok": rsa_result["valid"], "ec_ok": ec_ok, "server_message": rsa_result["message"],
                "hash_signed": h_signed, "hash_now": h_now, "bits_changed": bits,
                "modified": pdf != self.signed_pdf}

    def eve_sign(self, req):
        """Eve signs with HER OWN keys, pretending to be Alice; Bob checks with Alice's public key."""
        if self.rsa_key is None:
            raise ValueError("Generate the keys first.")
        pdf = make_pdf(_text(req), title="SecureSign Contract")
        rsa_sig = self.rsa_imp.sign(pdf, PSS, hashes.SHA256())
        ec_sig = self.ec_imp.sign(pdf, ec.ECDSA(hashes.SHA256()))
        try:
            self.ec_key.public_key().verify(ec_sig, pdf, ec.ECDSA(hashes.SHA256()))
            ec_ok = True
        except InvalidSignature:
            ec_ok = False
        return {"rsa_ok": _rsa_ok(self.rsa_key.public_key(), rsa_sig, pdf), "ec_ok": ec_ok,
                "rsa_sig": rsa_sig.hex(), "ec_sig": ec_sig.hex()}


# --------------------------------------------------------------------------- #
# Scenes 2 + 3 - the ECDSA invoice-signing service, attacker and bank
# --------------------------------------------------------------------------- #
class EcdsaLab:
    def __init__(self):
        self.mode = None
        self.d = self.Q = self._k = None
        self.channel = []          # public channel: (pdf bytes, (r, s)) that the attacker can see
        self.d_rec = None
        self.forged = None         # (pdf bytes, DER signature) produced by the attacker

    def start(self, req):
        mode = req.get("mode", "vulnerable")
        if mode not in ("vulnerable", "patched"):
            raise ValueError("unknown mode")
        self.mode = mode
        self.d, self.Q = E.generate_keypair()
        # BUG (vulnerable mode): one random nonce for the whole lifetime of the service.
        self._k = secrets.randbelow(E.N - 1) + 1 if mode == "vulnerable" else None
        self.channel, self.d_rec, self.forged = [], None, None
        return {"mode": mode, "qx": hx(self.Q[0]), "qy": hx(self.Q[1]), "d": hx(self.d)}

    def _require(self):
        if self.mode is None:
            raise ValueError("Start the signing service first.")

    def sign(self, req):
        self._require()
        text = _text(req)
        pdf = make_pdf(text, title="SecureSign Invoice")
        if self.mode == "vulnerable":
            k = self._k                                   # BUG: same k every call
        else:
            k = E.rfc6979_nonce(self.d, pdf)              # FIX: RFC 6979, k = f(d, H(pdf))
        r, s = E.ecdsa_sign(pdf, self.d, k)
        valid = lib_verify_ecdsa(E.to_crypto_public_key(self.Q), pdf, (r, s))
        self.channel.append((pdf, (r, s)))
        return {"message": text, "r": hx(r), "s": hx(s), "valid": valid,
                "pdf_sha256": hashlib.sha256(pdf).hexdigest(), "pdf_bytes": len(pdf),
                "index": len(self.channel)}

    def attack(self, _):
        self._require()
        if len(self.channel) < 2:
            raise ValueError("The attacker needs at least two signed invoices on the public channel.")
        t = time.perf_counter()
        pair = find_reused_nonce(self.channel)
        out = {"scanned": len(self.channel), "reused": pair is not None}
        if pair:
            (m1, s1), (m2, s2) = pair
            k = recover_nonce(m1, s1, m2, s2)
            d = recover_private_key(m1, s1, k)
            out.update({"r": hx(s1[0]), "s1": hx(s1[1]), "s2": hx(s2[1]),
                        "h1": hx(E.hash_to_int(m1)), "h2": hx(E.hash_to_int(m2)),
                        "k": hx(k), "d": hx(d)})
        else:
            (m1, s1), (m2, s2) = self.channel[0], self.channel[1]
            try:
                recover_nonce(m1, s1, m2, s2)
            except ValueError as exc:
                out["refused"] = str(exc)
            # Force the formulas anyway, pretending r1 == r2
            k = recover_nonce(m1, s1, m2, (s1[0], s2[1]))
            d = recover_private_key(m1, s1, k)
            out.update({"r1": hx(s1[0]), "r2": hx(s2[0]), "k": hx(k), "d": hx(d)})
        matches = E.scalar_mult(d) == self.Q
        self.d_rec = d
        out.update({"matches": matches, "real_d": hx(self.d),
                    "ms": round((time.perf_counter() - t) * 1000)})
        return out

    def forge(self, req):
        self._require()
        if self.d_rec is None:
            raise ValueError("Run the attack first to obtain a key.")
        text = _text(req)
        pdf = make_pdf(text, title="SecureSign Invoice")
        stolen = E.to_crypto_private_key(self.d_rec)          # import into a normal library
        der = stolen.sign(pdf, ec.ECDSA(hashes.SHA256()))
        r, s = E.der_to_sig(der)
        accepted = lib_verify_ecdsa(E.to_crypto_public_key(self.Q), pdf, (r, s))
        self.forged = (pdf, der)
        return {"message": text, "r": hx(r), "s": hx(s), "accepted": accepted,
                "pdf_sha256": hashlib.sha256(pdf).hexdigest()}

    def crosscheck(self, req):
        self._require()
        pdf = make_pdf(_text(req), title="SecureSign Invoice")
        ours = E.ecdsa_sign_rfc6979(pdf, self.d)
        try:
            lib = E.der_to_sig(E.to_crypto_private_key(self.d).sign(
                pdf, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
        except TypeError:
            return {"supported": False}
        return {"supported": True, "ours_r": hx(ours[0]), "ours_s": hx(ours[1]),
                "lib_r": hx(lib[0]), "lib_s": hx(lib[1]), "identical": ours == lib}

    def artifact(self, kind: str):
        """Files that let anyone re-check the forgery offline, e.g. with OpenSSL."""
        if kind == "public.pem":
            self._require()
            return _pem(E.to_crypto_public_key(self.Q)).encode(), "application/x-pem-file"
        if self.forged is None:
            raise ValueError("Forge an invoice first.")
        if kind == "forged.pdf":
            return self.forged[0], "application/pdf"
        if kind == "forged.sig":
            return self.forged[1], "application/octet-stream"
        raise ValueError("unknown file")


# --------------------------------------------------------------------------- #
# Scene 4 - textbook RSA vs RSA-PSS
# --------------------------------------------------------------------------- #
class RsaLab:
    def __init__(self):
        self.key = None

    def run(self, req):
        m1, m2 = int(req.get("m1", 0)), int(req.get("m2", 0))
        if not (1 < m1 < 10**12 and 1 < m2 < 10**12):
            raise ValueError("Use integers between 2 and 10^12.")
        if self.key is None:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv = self.key.private_numbers()
        n, e, d = priv.public_numbers.n, priv.public_numbers.e, priv.d
        s1, s2 = pow(m1, d, n), pow(m2, d, n)
        fm, fs = m1 * m2, s1 * s2 % n
        textbook_ok = pow(fs, e, n) == fm % n
        b1, b2, bf = str(m1).encode(), str(m2).encode(), str(fm).encode()
        p1 = int.from_bytes(self.key.sign(b1, PSS, hashes.SHA256()), "big")
        p2 = int.from_bytes(self.key.sign(b2, PSS, hashes.SHA256()), "big")
        pf = (p1 * p2 % n).to_bytes(256, "big")
        return {"m1": m1, "m2": m2, "forged_m": fm,
                "s1": f"{s1:x}", "s2": f"{s2:x}", "forged_s": f"{fs:x}",
                "textbook_ok": textbook_ok, "pss_ok": _rsa_ok(self.key.public_key(), pf, bf),
                "p1": f"{p1:x}", "p2": f"{p2:x}", "pss_forged": pf.hex()}


# --------------------------------------------------------------------------- #
# Scene 5 - key substitution vs proof-of-possession
# --------------------------------------------------------------------------- #
class KeySubLab:
    """Eve copies Alice's PUBLIC key from the directory and registers it as her own.

    Without proof-of-possession the registry links Alice's key to Eve, so every
    PDF Alice signs now verifies as "signed by Eve": authentication and
    non-repudiation are broken although no private key leaked. SecureSign
    (main.register_key) asks for an RSA-PSS signature on a fresh random challenge,
    which Eve cannot produce without Alice's private key.
    """

    def __init__(self):
        self.alice = self.eve = None
        self.pdf = self.sig = None

    def setup(self, req):
        self.alice = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.eve = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pdf = make_pdf(_text(req), title="SecureSign Contract")
        self.sig = self.alice.sign(self.pdf, PSS, hashes.SHA256())
        # Alice registers her own key: she CAN sign the challenge.
        challenge = secrets.token_urlsafe(32)
        proof = base64.b64encode(self.alice.sign(challenge.encode(), PSS, hashes.SHA256())).decode()
        alice_ok = verify_proof_of_possession(self.alice.public_key(), challenge, proof)
        return {"fingerprint": public_key_fingerprint(self.alice.public_key()),
                "eve_fingerprint": public_key_fingerprint(self.eve.public_key()),
                "pdf_sha256": hashlib.sha256(self.pdf).hexdigest(), "sig": self.sig.hex(),
                "challenge": challenge, "alice_proof_ok": alice_ok}

    def _require(self):
        if self.alice is None:
            raise ValueError("Run the first step first.")

    def legacy(self, _):
        """Registry WITHOUT proof-of-possession (the vulnerable design)."""
        self._require()
        registry = {}                               # fingerprint -> owner, first come first served
        fp = public_key_fingerprint(self.alice.public_key())
        registry[fp] = "Eve"                        # Eve uploads Alice's public key first
        valid = _rsa_ok(self.alice.public_key(), self.sig, self.pdf)
        return {"registered": True, "owner": registry[fp], "signature_valid": valid,
                "fingerprint": fp}

    def secure(self, _):
        """SecureSign registry: one-time challenge + RSA-PSS proof (crypto_service)."""
        self._require()
        challenge = secrets.token_urlsafe(32)
        # Eve's best attempt: sign the challenge with HER key and submit it with ALICE's public key.
        proof = base64.b64encode(self.eve.sign(challenge.encode(), PSS, hashes.SHA256())).decode()
        accepted = verify_proof_of_possession(self.alice.public_key(), challenge, proof)
        # Replaying Alice's old proof does not help either: the challenge is new every time.
        return {"challenge": challenge, "eve_proof": base64.b64decode(proof).hex(),
                "accepted": accepted,
                "fingerprint": public_key_fingerprint(self.alice.public_key())}


# --------------------------------------------------------------------------- #
# Scene 6 - non-repudiation: signed receipts and a hash-chained evidence log
# --------------------------------------------------------------------------- #
class EvidenceLab:
    """Uses evidence.build_entry / verify_entries, i.e. exactly the production code,
    on an in-memory chain with its own server key (the real log is never touched)."""

    def __init__(self):
        self.server = self.alice = None
        self.chain, self.receipt, self.pem = [], None, ""

    def _append(self, event, details, time_iso):
        prev = self.chain[-1]["entry_hash"] if self.chain else GENESIS_HASH
        entry = build_entry(self.server, len(self.chain) + 1, prev, event,
                            {"id": "alice", "email": "alice@securesign-demo.com", "name": "Alice Nguyen"}, details, time_iso)
        self.chain.append(entry)
        return entry

    def setup(self, req):
        self.server = ec.generate_private_key(ec.SECP256R1())
        self.pem = self.server.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.alice = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pdf = make_pdf(_text(req), title="SecureSign Contract")
        sig = self.alice.sign(pdf, PSS, hashes.SHA256())
        fp = public_key_fingerprint(self.alice.public_key())
        self.chain = []
        self._append("KEY_REGISTERED", {"fingerprint": fp, "algorithm": "RSA-PSS", "proof_of_possession": "verified"}, "2026-11-28T08:59:12Z")
        signed = self._append("PDF_SIGNED", {"file_name": "contract-SO-7781.pdf", "document_sha256": hashlib.sha256(pdf).hexdigest(),
                                             "signature_sha256": hashlib.sha256(sig).hexdigest(), "key_fingerprint": fp}, "2026-11-28T09:14:03Z")
        self._append("DOCUMENT_SENT", {"file_name": "contract-SO-7781.pdf", "document_sha256": hashlib.sha256(pdf).hexdigest(),
                                       "recipient": "bob@securesign-demo.com"}, "2026-11-28T09:14:40Z")
        self.receipt = receipt_bundle(signed, self.pem)      # the copy Bob keeps
        return {"entries": [{"seq": e["seq"], "event": json.loads(e["body"])["event"], "hash": e["entry_hash"],
                             "time": json.loads(e["body"])["time"]} for e in self.chain],
                "receipt_seq": signed["seq"], "receipt_time": json.loads(signed["body"])["time"],
                "document_sha256": hashlib.sha256(pdf).hexdigest(), "server_key": public_key_fingerprint(self.server.public_key()),
                "chain": verify_entries(self.chain, self.server.public_key())}

    def _require(self):
        if self.server is None:
            raise ValueError("Run the first step first.")

    def deny(self, _):
        """Alice: 'I never signed that contract' / 'I signed it a week later'. A judge checks Bob's receipt."""
        self._require()
        result = verify_receipt_bundle(self.receipt, self.server.public_key())
        # Alice's escape attempt: produce her own 'receipt' with a different time, signed by a key she controls.
        fake_key = ec.generate_private_key(ec.SECP256R1())
        body = dict(self.receipt["receipt"], time="2026-12-05T10:00:00Z")
        fake_entry = build_entry(fake_key, body["seq"], body["prev_hash"], body["event"], body["actor"], body["details"], body["time"])
        fake_pem = fake_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        fake = verify_receipt_bundle(receipt_bundle(fake_entry, fake_pem), self.server.public_key())
        return {"receipt_valid": result["valid"], "time": result["receipt"]["time"], "event": result["receipt"]["event"],
                "document_sha256": result["receipt"]["details"]["document_sha256"],
                "fake_valid": fake["valid"], "fake_reason": fake["reason"]}

    def tamper(self, req):
        """Insider with database access edits entry #2 (and optionally re-computes the hashes)."""
        self._require()
        recompute = bool(req.get("recompute"))
        chain = [dict(e) for e in self.chain]
        body = json.loads(chain[1]["body"])
        body["time"] = "2026-12-05T10:00:00Z"                  # move the signing event a week later
        chain[1]["body"] = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if recompute:                                          # rewrite every later hash link too
            chain[1]["entry_hash"] = hashlib.sha256(chain[1]["body"].encode()).hexdigest()
            for i in range(2, len(chain)):
                b = json.loads(chain[i]["body"]); b["prev_hash"] = chain[i - 1]["entry_hash"]
                chain[i]["body"] = json.dumps(b, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                chain[i]["entry_hash"] = hashlib.sha256(chain[i]["body"].encode()).hexdigest()
        check = verify_entries(chain, self.server.public_key())
        receipt_matches = chain[1]["entry_hash"] == self.receipt["entry_hash"]
        return {"recompute": recompute, "check": check, "receipt_matches_log": receipt_matches,
                "new_hash": chain[1]["entry_hash"], "old_hash": self.chain[1]["entry_hash"]}


# --------------------------------------------------------------------------- #
# Per-user state and routes
# --------------------------------------------------------------------------- #
class LabSession:
    def __init__(self):
        self.correct, self.ecdsa, self.rsa, self.keysub = CorrectUse(), EcdsaLab(), RsaLab(), KeySubLab()
        self.evidence = EvidenceLab()
        self.lock = threading.Lock()


_SESSIONS: dict[str, LabSession] = {}
_SESSIONS_LOCK = threading.Lock()
MAX_LAB_SESSIONS = 200


def _session(user: User) -> LabSession:
    with _SESSIONS_LOCK:
        lab = _SESSIONS.get(user.id)
        if lab is None:
            if len(_SESSIONS) >= MAX_LAB_SESSIONS:
                _SESSIONS.pop(next(iter(_SESSIONS)))     # drop the oldest lab state
            lab = _SESSIONS[user.id] = LabSession()
        return lab


ACTIONS = {
    "demo1/keygen": lambda L: L.correct.keygen,
    "demo1/sign": lambda L: L.correct.sign,
    "demo1/verify": lambda L: L.correct.verify,
    "demo1/eve_sign": lambda L: L.correct.eve_sign,
    "ecdsa/start": lambda L: L.ecdsa.start,
    "ecdsa/sign": lambda L: L.ecdsa.sign,
    "ecdsa/attack": lambda L: L.ecdsa.attack,
    "ecdsa/forge": lambda L: L.ecdsa.forge,
    "ecdsa/crosscheck": lambda L: L.ecdsa.crosscheck,
    "rsa/run": lambda L: L.rsa.run,
    "keysub/setup": lambda L: L.keysub.setup,
    "keysub/legacy": lambda L: L.keysub.legacy,
    "keysub/secure": lambda L: L.keysub.secure,
    "evidence/setup": lambda L: L.evidence.setup,
    "evidence/deny": lambda L: L.evidence.deny,
    "evidence/tamper": lambda L: L.evidence.tamper,
}


@router.post("/{group}/{action}")
def run_action(group: str, action: str, payload: dict = Body(default={}), user: User = Depends(require_csrf)):
    getter = ACTIONS.get(f"{group}/{action}")
    if getter is None:
        raise HTTPException(status_code=404, detail="Unknown lab action.")
    lab = _session(user)
    with lab.lock:
        try:
            return getter(lab)(payload or {})
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))


@router.get("/ecdsa/files/{name}")
def download_artifact(name: str, user: User = Depends(get_current_user)):
    lab = _session(user)
    with lab.lock:
        try:
            content, media = lab.ecdsa.artifact(name)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    return Response(content=content, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="lab-{name}"', "Cache-Control": "private, no-store"})
