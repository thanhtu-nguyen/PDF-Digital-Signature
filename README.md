# Digital Signatures in Practice: Final Demonstration (SecureSign Cloud)

**Course:** Introduction to Information Security, Ton Duc Thang University
**Instructor:** Ph.D. Huynh Ngoc Tu
**Group:** N05_G05: Trieu Ngoc Van Anh (524H0005), Duong Tran Quoc Khanh (523H0040), Nguyen Vo Thanh Tu (523H0189)

This project puts the midterm theory report into practice in two parts:

1. **SecureSign Cloud**, a multi-user web platform that signs and verifies PDF documents correctly with
   **RSA-PSS or ECDSA P-256** (SHA-256), and issues **server-signed, timestamped receipts** kept in a
   **hash-chained evidence log** for non-repudiation. It is the "correct use" of digital signatures, built like a real service.
2. **SecureSign Security Lab** (`/lab`), built into the same app, which shows step by step how badly
   implemented signatures are broken and how SecureSign prevents each attack.

| # | Part | What it shows |
|---|------|---------------|
| – | SecureSign web app | Create an RSA-2048 or ECDSA P-256 key in the browser (private key encrypted with PBKDF2 + AES-256-GCM, never uploaded), prove possession of the key, sign a PDF, send it to another user, verify it, detect a tampered copy, download and check a server-signed receipt; the admin checks the integrity of the whole evidence chain. |
| 1 | Lab scene 1: How it works | RSA-PSS and ECDSA P-256 sign a contract PDF. A one-character change (1,000 → 9,000 USD) and an impostor's key are both rejected. |
| 2 | Lab scene 2: **The attack** | An invoice-signing service reuses the ECDSA nonce `k`. From two public signed PDFs the attacker recovers the private key and forges a 1,000,000 USD invoice that the audited `cryptography` library **and OpenSSL** accept. |
| 3 | Lab scene 3: **The fix** | RFC 6979 deterministic nonces. The same attack code fails, and the output is byte-identical to `cryptography` (`deterministic_signing=True`). |
| 4 | Lab scene 4: RSA padding | Textbook RSA multiplicative forgery, blocked by RSA-PSS. |
| 5 | Lab scene 5: Key registry | Key substitution: Eve registers Alice's *public* key as her own. A registry without proof-of-possession accepts it; SecureSign's challenge-response rejects it. |
| 6 | Lab scene 6: **Non-repudiation** | Alice denies having signed (with a fake, later-dated receipt) and an insider edits the log, then even recomputes every hash. The server-signed receipt and the hash chain expose all three. |
| – | `demos/` | Console versions of scenes 1–4, an OpenSSL CLI demo and `verify_receipt.py` (offline receipt check). |
| – | `tests/` | 37 automated tests: crypto (RSA and ECDSA), multi-user isolation, receipts and the evidence chain, the lab attacks and patches, the RFC 6979 test vector, the security fixes and the demo accounts. |

## Requirements
* Python 3.11+ (tested on Python 3.11.9, macOS and Windows 10). On macOS/Linux use `python3` instead of `python`
* A modern browser (Chrome, Edge, Firefox, Safari). Web Crypto needs `http://127.0.0.1` / `localhost` or HTTPS
* Packages in `requirements.txt` (FastAPI, SQLAlchemy, `cryptography >= 44`, argon2-cffi, ...)
* Optional: OpenSSL / LibreSSL CLI to re-check the forged PDF and to run `demos/openssl_demo.sh`

No VM, internet access or external service is needed for the demonstration. Locally the app uses SQLite in
`storage/`, does not require email verification and creates demo accounts (see below).

## Setup
```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -r requirements-dev.txt
```
Or just double-click `start.bat` (Windows) / run `sh start.sh` (macOS/Linux).

## Run

### Web app (recommended for the live demo)
```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```
Open `http://127.0.0.1:8000` and sign in with one of the demo accounts below (no registration needed).

#### Demo accounts
The server creates these accounts automatically at start-up (local development only). Alice already has a
registered **RSA-PSS 2048** key and Bob an **ECDSA P-256** key; their encrypted private keys are in `demo_data/`.

| Role | Email | Password | Private key file (key password `DemoKey@2026`) |
|------|-------|----------|------------------|
| Administrator | `admin@securesign-demo.com` | `Admin@Demo2026` | – |
| User (signer) | `alice@securesign-demo.com` | `Alice@Demo2026` | `demo_data/alice.key.json` (RSA-PSS 2048) |
| User (recipient) | `bob@securesign-demo.com` | `Bob@Demo2026` | `demo_data/bob.key.json` (ECDSA P-256) |
| User (outsider) | `charlie@securesign-demo.com` | `Charlie@Demo2026` | – (no key; used to show he cannot see Alice's and Bob's documents) |

Sample files: `demo_data/contract-demo.pdf` (original) and `demo_data/contract-demo-tampered.pdf`
(1,000 → 9,000 USD, used to show that the signature no longer matches).

> These passwords and keys are **public, for testing only**. Demo accounts are disabled automatically when
> `APP_ENV=production` (the server refuses to start if `SECURESIGN_DEMO_ACCOUNTS=true` in production). Set
> `SECURESIGN_DEMO_ACCOUNTS=false` to turn them off locally. If you change a demo password in the app, the new one
> is kept; delete `storage/securesign.db` to reset everything. Run `python demo_data/make_demo_data.py` to
> generate new demo keys (then delete the database so the new public keys are registered).

Use two browser windows (one normal, one private) to be Alice and Bob at the same time:

1. Alice → **Ký tài liệu**: drag `demo_data/contract-demo.pdf` onto the drop zone (or click it), choose the key file
   `demo_data/alice.key.json` and the key password `DemoKey@2026`, click **Tạo chữ ký số**, then download the `.sig`
   and the **receipt** (`.json`). The key is decrypted only in the browser; a selected file can be removed with **✕ Gỡ**.
2. Alice → **Gửi tài liệu**: recipient `bob@securesign-demo.com`, choose her key, the PDF and the `.sig`, then send.
   The server re-verifies the signature first.
3. Bob → **Quản lý khóa** → in **Danh bạ Public Key**, mark Alice's key as trusted (after comparing the fingerprint),
   then **Hộp thư tài liệu** → **Kiểm tra**: valid and trusted.
4. Bob → **Xác thực chữ ký**: verify `demo_data/contract-demo-tampered.pdf` with the same `.sig` and Alice's key. It is rejected.
5. Bob → **Hộp thư tài liệu** → **Biên nhận** downloads the server-signed receipt of the delivery; on **Xác thực chữ ký** →
   **Kiểm tra biên nhận** it shows who sent which PDF (SHA-256) at what time. Bob can also sign with his ECDSA key
   (`demo_data/bob.key.json`): the signature is about 72 bytes instead of 256.
6. Charlie: his inbox is empty and he cannot open the document or its receipts, because only the sender and the recipient can.
7. Admin → **Quản trị**: list accounts, suspend/unlock a user or change a role, and **Kiểm tra toàn vẹn** the evidence chain.

You can still register new accounts. A new user chooses **RSA-PSS 2048** or **ECDSA P-256** in **Quản lý khóa** →
**Tạo cặp khóa**, downloads the encrypted private key (`.key.json`) and clicks **Đăng ký Public Key**: the browser signs
a one-time challenge to prove it owns the private key.

#### Receipts and the evidence log (non-repudiation)
Every key registration/revocation, PDF signature, delivery and verification by the recipient is written to an
append-only log. Each entry is a JSON receipt with a server timestamp, the PDF's SHA-256 and the signer's key
fingerprint; it contains the SHA-256 of the previous entry (`prev_hash`) and is signed by the server with ECDSA P-256.
Anyone can check a receipt offline with the server's public key (`GET /api/receipts/server-key`):
```bash
python demos/verify_receipt.py securesign-receipt-2.json --server-key server.pem --pdf contract-demo.pdf
```
By default the server generates its receipt key once and stores it in the database; for a deployment set
`SECURESIGN_RECEIPT_KEY_PEM` (EC P-256 private key, PEM) and keep it in a secret store.

For a real deployment use your own administrator account instead (never commit it):
```bash
ADMIN_EMAIL=admin@your-domain.com ADMIN_PASSWORD='a-long-unique-password' python -m uvicorn backend.app.main:app --port 8000
```

### Security Lab
While signed in (any demo account works), click **Security Lab** in the sidebar or open `http://127.0.0.1:8000/lab`.

| Scene | Steps (one click each) |
|-------|-------|
| 1 · How it works | keys → sign contract PDF → Bob verifies (valid) → Eve changes 1,000 to 9,000 USD (rejected) → Eve signs with her own key (rejected) |
| 2 · The attack | service starts (k reused) → signs invoice PDF #1001 → #1002 (same r) → Eve recovers the private key → forged 1,000,000 USD invoice accepted |
| 3 · The fix | the same steps with RFC 6979: r differs → wrong key → forgery rejected → byte-identical to the `cryptography` library |
| 4 · RSA padding | sign(100) × sign(50) = valid signature on 5,000 with textbook RSA; RSA-PSS rejects it |
| 5 · Key registry | Alice registers her key with proof-of-possession → Eve claims Alice's key in a naive registry (attack works) → the same against SecureSign (rejected) |
| 6 · Non-repudiation | Alice signs and sends (3 chained receipts) → Alice denies with a fake receipt (rejected) → an insider edits entry #2 (detected) → the insider recomputes all hashes (still detected: no server signature) |

Controls: **→ / Space / Enter** next step, **R** restart the scene, **M** show or hide the math, **EN / VI**
switches the language. Values are shown as coloured fingerprints, so equal values have equal colours. Deep links:
`#correct`, `#attack`, `#defense`, `#rsa`, `#keysub`, `#evidence`; `#attack/5` opens a scene and runs its first 5 steps.

After scene 2 the forged invoice can be downloaded and checked with an independent verifier:
```bash
openssl dgst -sha256 -verify lab-public.pem -signature lab-forged.sig lab-forged.pdf    # Verified OK
```

The lab is enabled by default for local development and disabled when `APP_ENV=production`
(set `SECURESIGN_LAB_ENABLED=true` to force it on).

### Console and tests
```bash
python -m pytest -v                               # 37 automated checks
python demos/run_all.py --pause                   # console version of lab scenes 1–4
python demos/demo2_nonce_reuse_attack.py
bash demos/openssl_demo.sh
```
Generated keys, signatures and intercepted/forged data from the console demos are written to `demos/output/`.

## File layout
```
backend/app/main.py            FastAPI app: auth, keys, signing, documents, admin, security middleware
backend/app/crypto_service.py  verify_signature() for RSA-PSS and ECDSA P-256, verify_proof_of_possession(), key policy
backend/app/evidence.py        signed receipts, hash-chained evidence log, chain/receipt verification
backend/app/security.py        Argon2id passwords, session tokens, CSRF, roles
backend/app/database.py        SQLAlchemy models (users, sessions, keys, documents, audit log, evidence entries)
backend/app/lab.py             Security Lab API (6 scenes, state per user)
backend/app/storage_service.py local disk or private Vercel Blob storage
backend/lab/ecc_core.py        P-256 arithmetic, ECDSA with explicit nonce, RFC 6979 (educational)
backend/lab/attack.py          nonce-reuse detection and private-key recovery
backend/lab/pdf_tools.py       small deterministic PDF builder for the lab
frontend/                      SecureSign web app (Web Crypto signing in the browser)
frontend/lab/                  Security Lab page (story mode, EN/VI)
backend/app/demo_seed.py       demo accounts created at start-up (development only)
demo_data/                     demo key files, sample PDFs and make_demo_data.py
demos/                         console demos 1-4, run_all.py, openssl_demo.sh, verify_receipt.py
tests/                         pytest suite
docs/                          architecture, Vietnamese user guide, Docker/Vercel deployment
Dockerfile, docker-compose.yml, Caddyfile, vercel.json   deployment (HTTPS, PostgreSQL)
```

> `backend/lab/ecc_core.py` is intentionally minimal and **not constant-time**. It exists only because audited
> libraries do not let the caller choose `k`, which we need in order to reproduce the bug. SecureSign itself never
> uses it: all production signing uses Web Crypto in the browser and the `cryptography` library on the server.
>
> SecureSign is a course project, not a licensed signature service: it uses detached RSA-PSS / ECDSA signatures
> (ECDSA `.sig` files are DER-encoded, so OpenSSL can verify them) and its own receipt service, not CA-issued
> certificates, an RFC 3161 time-stamping authority or PAdES. See `docs/SECURESIGN_GUIDE_vi.md` for deployment and the full API list.
