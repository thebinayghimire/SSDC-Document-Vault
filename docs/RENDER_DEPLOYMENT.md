# Render Free deployment

`render.yaml` deploys the Django application as a free Python web service in
Singapore. `build.sh` installs the locked dependencies, collects static assets,
vendors PDF.js before static collection, runs migrations, and creates the initial
administrator because the free service does not provide an interactive shell.

## Existing SSDC service

The existing public URL is `https://ssdc-document-vault.onrender.com`. Use the
existing service rather than creating a duplicate. Before deploying the hardened
source, inspect its private environment through an authorized Render connection.
On 28 October, its login page returned a non-Secure CSRF cookie and no HSTS.
Set `APP_ENV=production` and `DEBUG=0`, with:

```text
ALLOWED_HOSTS=ssdc-document-vault.onrender.com
CSRF_TRUSTED_ORIGINS=https://ssdc-document-vault.onrender.com
GOOGLE_DRIVE_REDIRECT_URI=https://ssdc-document-vault.onrender.com/storage/google/callback/
```

Preserve the existing MFA and Drive encryption keys. If the app has been using a
default development key, use the audited rotation/recovery procedure before
switching keys; generating a new key alone will not re-encrypt existing data.
Confirm the database URL verifies its certificate/hostname, and explicitly review
the actual scanner setting. The release refuses development mode on Render.

The checked-in Free profile is suitable for previewing the app. Render documents
its free-service availability/storage limits and advises against production use;
inspect the actual plan and approve any paid change before changing resources.
[Render free-service limitations](https://render.com/docs/free).

## Database

Create a PostgreSQL database in the closest available Neon or Aiven region and
put its direct TLS connection URI in `DATABASE_URL`. Use `sslmode=verify-full`;
the app defaults to hostname verification using the current certifi CA bundle.
An explicit `POSTGRES_SSLROOTCERT` file supports a private database CA.
Weaker TLS modes and transaction-pooler endpoints are rejected. When Neon supplies both variables,
the app automatically prefers `DATABASE_URL_UNPOOLED` (the hostname does not
contain `-pooler`). SSDC Document Vault
uses PostgreSQL session advisory locks while validating uploads and changing
permissions; Neon's pooled URL uses PgBouncer transaction mode and cannot preserve
that session state. Two Gunicorn workers with persistent Django connections remain
well below Neon's direct-connection limit.

## Blueprint environment values

Create a Render Blueprint from the repository and supply every `sync: false`
value when prompted:

- `DATABASE_URL`: the external PostgreSQL TLS URI.
- `MFA_ENCRYPTION_KEY`: an independently generated Fernet key. Generate it locally
  with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
  and save it privately in the Render environment. Render's generic generated
  secrets are not Fernet keys. Keep this key stable across deployments.
- `DRIVE_TOKEN_ENCRYPTION_KEY`: output of
  `python manage.py generate_drive_key`. Keep it separate from every database
  backup and do not rotate it without re-encrypting stored credentials.
- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`: the production Google OAuth web
  client.
- `DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_EMAIL`, and
  `DJANGO_SUPERUSER_PASSWORD`: initial administrator values. Later deploys do not
  reset an existing administrator's password.
- `ALLOWED_HOSTS`: exact hostnames, separated by commas, without schemes or ports.
  Render's exact `RENDER_EXTERNAL_HOSTNAME` is added automatically; a shared
  `.onrender.com` suffix is never added.
- `ACCEPT_NO_MALWARE_SCANNING`: set to `1` only after explicitly choosing the
  scanner-free deployment profile. Startup refuses `ENABLE_CLAMAV=false`
  without that acknowledgement. For scanned uploads, use the Docker deployment
  with ClamAV and leave this unset.
- `CSRF_TRUSTED_ORIGINS`: the comma-separated HTTPS origins that can submit forms,
  initially the service URL (for example,
  `https://ssdc-document-vault.onrender.com`) and later the custom domain.

Render generates the Django signing key; MFA and Drive use separately generated
Fernet keys. ClamAV is disabled for this profile with `ENABLE_CLAMAV=false`
and the explicit acknowledgement above; extension,
signature/MIME, strict PDF/image structure, pixel/page, upload-size, quota, and
authorization checks remain active.

Render's container filesystem is ephemeral. Published documents and image
previews live in Google Drive, but each upload is staged under
`PRIVATE_STORAGE_ROOT` until validation, scanning, upload and publication finish.
If the instance is replaced while an upload is in flight, its staging file is
lost and the quarantined row cannot be retried; the manager must upload that file
again. Never set `DOCUMENT_STORAGE_PROVIDER=filesystem` on Render.

Render supplies `RENDER_EXTERNAL_HOSTNAME`, which the app uses for its initial
Google callback and CSRF origin. After adding a custom domain, set:

- `ALLOWED_HOSTS` to the exact custom hostname (the exact Render hostname is retained).
- `CSRF_TRUSTED_ORIGINS` to `https://<custom-hostname>` plus any Render origin in
  active use.
- `GOOGLE_DRIVE_REDIRECT_URI` to
  `https://<custom-hostname>/storage/google/callback/`.

Add that exact callback to the Google OAuth client. Publish the homepage,
`/privacy/`, and `/terms/` URLs on the verified domain before submitting OAuth
verification. Then sign in as the initial administrator, complete MFA enrollment,
and connect the single Google Drive storage-owner account.

The bootstrap command creates an administrator once and records an audit event.
Later deploys preserve account details, password, role and activation state. If the
bootstrap username belongs to a disabled or non-administrator account, deployment
stops instead of silently restoring privileges. Choose a new bootstrap username
or use the documented account recovery workflow. Remove bootstrap credentials
from the hosted environment once the initial account is established.

The Blueprint uses `/live/` for process availability so initial deployment can
finish before Google Drive is connected. Monitor `/health/` separately: it checks
application tables, private staging storage, scanner state and known Drive setup
or reconnect failures. Run `operations_check` for live Drive access verification.
Use a single deployment at a time: the free profile applies migrations during its
build because a separate release phase is unavailable. Validate with synthetic
documents after each release and follow [current verification](RELEASE_READINESS.md).
