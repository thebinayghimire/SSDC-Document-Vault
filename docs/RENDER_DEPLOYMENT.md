# Render Free deployment

`render.yaml` deploys the Django application as a free Python web service in
Singapore. `build.sh` installs the locked dependencies, collects static assets,
runs migrations, and idempotently creates the initial administrator because the
free service does not provide an interactive shell.

## Database

Create a PostgreSQL database in the closest available Neon or Aiven region and
put its TLS connection URI in `DATABASE_URL`. When Neon supplies both variables,
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
- `DRIVE_TOKEN_ENCRYPTION_KEY`: output of
  `python manage.py generate_drive_key`. Keep it separate from every database
  backup and do not rotate it without re-encrypting stored credentials.
- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`: the production Google OAuth web
  client.
- `DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_EMAIL`, and
  `DJANGO_SUPERUSER_PASSWORD`: initial administrator values. Later deploys do not
  reset an existing administrator's password.
- `CSRF_TRUSTED_ORIGINS`: the comma-separated HTTPS origins that can submit forms,
  initially the service URL (for example,
  `https://ssdc-document-vault.onrender.com`) and later the custom domain.

Render generates the unrelated Django signing key and MFA encryption key. ClamAV
is disabled for this 512 MB profile with `ENABLE_CLAMAV=false`; extension,
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

- `ALLOWED_HOSTS` to the custom hostname (`.onrender.com` is always retained).
- `CSRF_TRUSTED_ORIGINS` to `https://<custom-hostname>` plus any Render origin in
  active use.
- `GOOGLE_DRIVE_REDIRECT_URI` to
  `https://<custom-hostname>/storage/google/callback/`.

Add that exact callback to the Google OAuth client. Publish the homepage,
`/privacy/`, and `/terms/` URLs on the verified domain before submitting OAuth
verification. Then sign in as the initial administrator, complete MFA enrollment,
and connect the single Google Drive storage-owner account.
