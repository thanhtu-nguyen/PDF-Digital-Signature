# SecureSign Cloud 2.1 — Deploy to Vercel (student project)

This guide deploys the existing FastAPI application to Vercel, uses Neon PostgreSQL for persistent relational data, a **private** Vercel Blob store for PDF/signature files, Upstash Redis for shared rate limits, and Resend (or SMTP) for account email.

> This is an educational MVP, not a legally qualified digital-signature service. Do not use it for sensitive real contracts. Test with sample PDFs only.

## 1. What changed for Vercel

- `index.py` exposes the existing FastAPI app to the Vercel Python runtime.
- `.python-version` selects Python 3.12.
- `backend/app/storage_service.py` uses local disk for local development and private Vercel Blob for cloud documents.
- SQLAlchemy accepts Neon `postgresql://` URLs and uses psycopg 3 with a small per-instance pool. Use Neon’s pooled connection string.
- `httpx` and `vercel-blob` are included in `requirements.txt`.
- The public upload limit is 4 MiB because Vercel Functions have a 4.5 MB request-body limit. The margin accounts for multipart overhead and the detached signature.
- Upstash REST rate limiting is shared across serverless instances. Production refuses to start without it.
- Resend HTTPS API is supported for verification and password-reset email; SMTP remains available as a fallback.

## 2. Create the external services

Create these accounts/stores before the production deployment:

1. **Vercel**: https://vercel.com/signup
2. **Neon PostgreSQL**: https://neon.tech/ — create a database and copy the pooled connection string. The hostname should include `-pooler`.
3. **Vercel Blob**: in the Vercel project, open Storage → Create Storage → Blob. Choose **Private**, not Public. Connect it to the project for Production. Vercel injects `BLOB_STORE_ID` and OIDC credentials for the connected project.
4. **Upstash Redis**: https://upstash.com/ — create a Redis database and copy its REST URL and REST token.
5. **Resend** (recommended) or SMTP: https://resend.com/ — create an API key and configure a sender. Resend requires a verified sender/domain for sending to arbitrary recipients. For a restricted test, its onboarding sender may only deliver to the account’s own verified address.

Use separate Neon and Blob resources for Preview if you enable Preview deployments. Do not let preview deployments write to the production database or production document store.

## 3. Push the project to a private GitHub repository

From the extracted project root (the folder containing `index.py`):

```powershell
git init
git add .
git commit -m "Prepare SecureSign Cloud for Vercel"
```

Create a **private** GitHub repository and push the project. `.gitignore` excludes `.env`, local databases, PDF files, signatures, private-key files, `.vercel/`, and local storage. Never commit real secrets, `.env`, Private Keys, PDFs, or `.sig` files.

## 4. Import the repository into Vercel

1. Open https://vercel.com/new.
2. Import the private GitHub repository.
3. Set the Root Directory to the repository root (the folder containing `index.py`, `requirements.txt`, and `vercel.json`).
4. Use the Other/FastAPI detected framework settings. Do not set a custom Build Command or Output Directory unless Vercel specifically asks for one.
5. Do not deploy production yet; configure the services and environment variables first.

Vercel detects the FastAPI `app` exported by `index.py`. Static assets remain served through the existing FastAPI `/static` mount.

## 5. Configure Vercel Blob

In the Vercel project:

1. Open Storage.
2. Create a Blob store.
3. Select **Private** access.
4. Connect it to this project and the Production environment.
5. Confirm that `BLOB_STORE_ID` is present in the project’s Production environment variables. The Vercel Blob Python SDK uses Vercel OIDC by default when the store is connected.

The application stores only Blob pathnames in PostgreSQL. Every download first checks the signed-in user is the sender or recipient, then the backend fetches the private Blob. Never change this store to Public.

## 6. Configure Neon PostgreSQL

Copy the Neon pooled connection string and add it as `DATABASE_URL`. It usually resembles:

```text
postgresql://USER:PASSWORD@ep-example-pooler.REGION.aws.neon.tech/neondb?sslmode=require
```

The application automatically changes `postgresql://` to `postgresql+psycopg://` for the installed psycopg 3 driver. Do not remove `sslmode=require` or the pooler hostname.

The app creates its initial tables on startup with SQLAlchemy `create_all`. For future schema changes, introduce Alembic migrations rather than relying on `create_all` as a migration system.

## 7. Add Production environment variables

Open Project → Settings → Environment Variables. Add the following variables to **Production**. Add Preview values only after creating separate Preview database and Blob resources.

| Name | Value |
|---|---|
| `APP_ENV` | `production` |
| `DATABASE_URL` | Neon pooled PostgreSQL URL |
| `STORAGE_BACKEND` | `vercel_blob` |
| `COOKIE_SECURE` | `true` |
| `COOKIE_SAMESITE` | `lax` |
| `PUBLIC_BASE_URL` | `https://YOUR-PROJECT.vercel.app` |
| `ALLOWED_ORIGINS` | `https://YOUR-PROJECT.vercel.app` |
| `REQUIRE_EMAIL_VERIFICATION` | `true` |
| `ADMIN_EMAIL` | Your admin email |
| `ADMIN_PASSWORD` | Unique random password, at least 16 characters |
| `ADMIN_NAME` | `SecureSign Administrator` |
| `ADMIN_RESET_PASSWORD` | `false` |
| `SESSION_TTL_HOURS` | `12` |
| `SECURESIGN_MAX_UPLOAD_BYTES` | `4194304` |
| `SMTP_FROM` | Verified sender, e.g. `SecureSign <no-reply@your-verified-domain>` |
| `RESEND_API_KEY` | Your Resend API key (or configure SMTP instead) |
| `UPSTASH_REDIS_REST_URL` | Upstash REST URL |
| `UPSTASH_REDIS_REST_TOKEN` | Upstash REST token |

`BLOB_STORE_ID` should be added automatically by the connected Blob store. Do not paste any secret into source code or commit it to Git.

For SMTP instead of Resend, set `SMTP_HOST`, `SMTP_PORT` (normally `587`), `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_STARTTLS=true`. If `RESEND_API_KEY` is configured, the app uses Resend’s HTTPS API first.

After saving variables, redeploy. Environment-variable changes do not alter an already-created deployment.

## 8. Deploy

You can deploy from the Vercel dashboard after connecting GitHub, or install the CLI:

```powershell
npm install -g vercel
vercel login
vercel link
vercel --prod
```

Vercel assigns an address such as `https://your-project.vercel.app` and provides HTTPS automatically.

If the assigned project URL changes, update `PUBLIC_BASE_URL` and `ALLOWED_ORIGINS`, then redeploy. Email verification and password-reset links use `PUBLIC_BASE_URL`.

## 9. Verify the deployment

Open these URLs (replace the host):

- `https://YOUR-PROJECT.vercel.app/` — web interface
- `https://YOUR-PROJECT.vercel.app/api/health` — health check
- `https://YOUR-PROJECT.vercel.app/api/docs` — API docs only in development; disabled in production

Expected health response includes:

```json
{
  "status": "ok",
  "database": "ok",
  "storage": "vercel_blob",
  "rate_limit": "upstash",
  "service": "SecureSign Cloud",
  "version": "2.1.0"
}
```

Then test with two separate accounts and two browsers:

1. Register A and B; verify both emails.
2. Sign in as A, create an RSA key, sign a sample PDF, and record the signature.
3. Send the PDF and `.sig` to B.
4. Sign in as B, download both files, and verify the signature.
5. Sign in as C and confirm C cannot download A/B’s document.
6. Modify one byte of a downloaded PDF and confirm verification returns `valid: false`.

## 10. Existing local data

The first Vercel deployment creates a new Neon database and a new Blob store; it does not automatically migrate the local SQLite database or files under `storage/documents/`. Create new demo accounts in the cloud and register their public keys again. If you already have important local records, export and migrate them deliberately before switching users to the cloud deployment. Keep the old local folder as a backup.

## 11. Vercel constraints and security notes

- Vercel Function request/response payloads are limited to 4.5 MB. The project caps PDFs at 4 MiB. Larger-file support needs a separate authenticated direct-to-Blob upload flow; do not simply raise this environment variable.
- The function filesystem is ephemeral. The application does not use it for persistent document storage in Vercel mode.
- Private Blob is required because PDF documents must not be accessible to anyone who knows a URL.
- Upstash is required in production because in-memory rate limits are not shared between serverless instances.
- Hobby usage quotas apply to Vercel Functions, Blob, Neon, Upstash, and the email provider. Check each provider’s current limits before inviting many users.
- A serverless Function is not a permanently running worker. Keep request handlers bounded and do not depend on background tasks that outlive the response.
- This remains an educational detached-signature system. It is not PAdES, does not issue CA certificates, and does not establish the signer’s legal identity or a trusted timestamp.

## 12. Local development remains unchanged

Run `start.bat` on Windows. It uses local SQLite and local `storage/` by default. The Vercel Blob adapter is activated only when `STORAGE_BACKEND=vercel_blob` is configured. Local tests do not require a Vercel account.
