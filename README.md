# Digital Signatures in Practice: Final Demonstration (SecureSign Cloud)

**Course:** Introduction to Information Security, Ton Duc Thang University
**Instructor:** Ph.D. Huynh Ngoc Tu
**Group:** N05_G05: Trieu Ngoc Van Anh (524H0005), Duong Tran Quoc Khanh (523H0040), Nguyen Vo Thanh Tu (523H0189)

This project puts the midterm theory report into practice with **SecureSign Cloud**, a multi-user web platform that
signs and verifies PDF documents with **RSA-PSS or ECDSA P-256** (SHA-256) and guarantees **non-repudiation** with
server-signed, timestamped receipts kept in a **hash-chained evidence log**.

| Security property | How SecureSign provides it | Attack it stops |
|-------------------|----------------------------|-----------------|
| Integrity | Detached signature over the exact PDF bytes (SHA-256), re-verified by the server | Changing one character of a signed PDF (1,000 → 9,000 USD) |
| Authentication | Public keys bound to accounts only after a proof-of-possession challenge; trust marks after comparing fingerprints | Impersonation and key substitution (registering someone else's public key) |
| Non-repudiation | Server-signed receipt (ECDSA P-256) for every key event, signature, delivery and verification, chained with SHA-256 | Denying a signature, back-dating it with a fake receipt, editing or rewriting the log |
| Key confidentiality | Private key generated and encrypted in the browser (PBKDF2 310,000 + AES-256-GCM), never uploaded | Server or database compromise revealing private keys |
| Account security | Argon2id, hashed session tokens, CSRF tokens, rate limiting, strict Content Security Policy | Password guessing (including the X-Forwarded-For bypass we fixed), CSRF, script injection |

The attack flows and defenses are explained with diagrams in the report (Chapters 3–5). `tests/` contains 21
automated tests for the signatures, receipts, evidence chain, access control and security fixes.

## Requirements
* Python 3.11+ (tested on Python 3.11.9, macOS and Windows 10). On macOS/Linux use `python3` instead of `python`
* A modern browser (Chrome, Edge, Firefox, Safari). Web Crypto needs `http://127.0.0.1` / `localhost` or HTTPS
* Packages in `requirements.txt` (FastAPI, SQLAlchemy, `cryptography >= 44`, argon2-cffi, ...)
* Optional: OpenSSL / LibreSSL CLI to check `.sig` files independently

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

### Console tools and tests
```bash
python -m pytest -v                               # 21 automated checks
python demos/verify_receipt.py RECEIPT.json --server-key server.pem --pdf FILE.pdf   # offline receipt check
python demo_data/make_demo_data.py                # regenerate demo keys and sample PDFs
```
An ECDSA `.sig` file is DER-encoded, so it can also be checked with OpenSSL using the signer's public key
(downloaded from **Danh bạ Public Key**):
```bash
openssl dgst -sha256 -verify bob-public.pem -signature contract.sig contract.pdf
```

## File layout
```
backend/app/main.py            FastAPI app: auth, keys, signing, documents, receipts, admin, security middleware
backend/app/crypto_service.py  verify_signature() for RSA-PSS and ECDSA P-256, verify_proof_of_possession(), key policy
backend/app/evidence.py        signed receipts, hash-chained evidence log, chain/receipt verification
backend/app/security.py        Argon2id passwords, session tokens, CSRF, roles
backend/app/database.py        SQLAlchemy models (users, sessions, keys, documents, audit log, evidence entries)
backend/app/demo_seed.py       demo accounts created at start-up (development only)
backend/app/storage_service.py local disk or private Vercel Blob storage
frontend/                      SecureSign web app (Web Crypto key generation and signing in the browser)
demo_data/                     demo key files, sample PDFs, make_demo_data.py and pdf_tools.py
demos/verify_receipt.py        offline receipt verifier (no need to trust the server)
tests/                         pytest suite
docs/                          architecture, Vietnamese user guide, Docker/Vercel deployment
Dockerfile, docker-compose.yml, Caddyfile, vercel.json   deployment (HTTPS, PostgreSQL)
```

> SecureSign is a course project, not a licensed signature service: it uses detached RSA-PSS / ECDSA signatures
> and its own receipt service, not CA-issued certificates, an RFC 3161 time-stamping authority or PAdES.
> See `docs/SECURESIGN_GUIDE_vi.md` for deployment and the full API list.
