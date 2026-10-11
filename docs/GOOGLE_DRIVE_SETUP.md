# Google Drive owner setup and recovery

Google Drive is the primary document store for new uploads. Django/PostgreSQL,
HTTPS hosting, ClamAV and the private staging volume are still required. Existing
versions retain their filesystem provider and remain readable. Staff use SSDC
accounts; only the storage owner authorizes Google. Personal paid Drive storage
is supported through owner OAuth, not a service account or shared drive.

Repository implementation and synthetic HTTPS mocks do not establish a live
connection. Complete the following account steps privately, after deploying the
reviewed code. Never send secrets, consent codes or tokens through chat.

## Console and credentials

1. In [Google Cloud Console](https://console.cloud.google.com/), create a dedicated
   project for SSDC. Record its project ID in the operator inventory.
2. APIs & Services → Library → **Google Drive API** → Enable.
3. In Google Auth Platform, configure Branding (application name, support email,
   developer contact; production homepage/privacy links and authorized domains
   as required by Console). Audience must be **External** for a personal account.
   While Testing, add only the storage owner's account as a test user. Data Access:
   request only `https://www.googleapis.com/auth/drive.file`.
4. Clients → Create client → **Web application**. Use separate development and
   production projects/clients, following Google's production policy. Configure
   each project's audience, API and secrets separately. Keep local callbacks out
   of the production client.
   No browser API key or staff Google sign-in client is needed.
5. Register exact Authorized redirect URIs, including scheme, host, port, path
   and trailing slash. The code requires `/storage/google/callback/`:
   - Local: `http://localhost:8080/storage/google/callback/`
   - Production placeholder: `https://portal.example.org/storage/google/callback/`
   Set `GOOGLE_DRIVE_REDIRECT_URI` to exactly the matching URI. Use the same
   hostname for SSDC login and consent initiation; localhost and 127.0.0.1 cookies
   differ. Production must use HTTPS. Do not use wildcards or an inferred Host header.
6. Save the client ID and client secret to private files outside the repository.
   Google may show the client secret only when creating it. Generate a separate
   Fernet credential key locally, saving it directly to a private file rather
   than printing it:

   ```powershell
   .\.venv\Scripts\python.exe -c "from pathlib import Path; from cryptography.fernet import Fernet; p=Path('C:/private-ssdc/google-credential-key'); p.parent.mkdir(parents=True,exist_ok=True); f=p.open('xb'); f.write(Fernet.generate_key()); f.close()"
   ```

   Use an operator-owned private directory with Windows ACLs or Linux mode 0600;
   limit read access to the application service and designated custodians.
   Store a recovery copy of the key separately from PostgreSQL and backup archives.
   Do not reuse the Django, MFA or backup encryption key. Losing the key makes
   stored owner credentials unreadable. Mount files read-only; do not bake them
   into images, commits or screenshots. `.env.example` contains placeholders only.

## Release and connect

For this local vault, register `http://127.0.0.1:8080/storage/google/callback/` to
match the existing portal links. Once the Web application client JSON is downloaded,
the local helper can prepare private secret files without displaying their values:

```powershell
.\.venv\Scripts\python.exe scripts/configure_drive_local.py --client-json "C:\path\to\client_secret.json"
docker compose --env-file .env.drive.local -f compose.yaml -f compose.host.yaml -f compose.drive.local.yaml up -d --no-deps app
docker compose exec proxy nginx -s reload
```

The helper keeps the OAuth files under the operator's `.ssdc-vault/google-drive`
directory and writes only their paths and callback to the ignored `.env.drive.local`.
It preserves the credential encryption key on repeat runs and refuses to replace
a different OAuth client. If the repository also uses `.env`, pass `--env-file .env`
before `--env-file .env.drive.local` to retain those settings. Owner consent is still
required. Local authenticator prompts may be temporarily disabled; this does not
remove Google's owner-authorization step. Use the same portal hostname throughout.

Stop/drain older application workers and scan retries before the release. Make
an encrypted paired backup using the old release, then build this release and
apply `vault.0005_driveconnection_driveobject_version_storage_provider_and_more`.
Do not let older code write after migration. No migration changes existing files,
Drive permissions, credentials or version provider values.

Production `compose.prod.yaml` selects Drive and mounts the three Google secret
files. Supply `GOOGLE_DRIVE_CLIENT_ID_FILE`, `GOOGLE_DRIVE_CLIENT_SECRET_FILE`,
`GOOGLE_DRIVE_CREDENTIAL_KEY_FILE` and `GOOGLE_DRIVE_REDIRECT_URI` in the deployment
environment alongside existing secrets. Allow outbound HTTPS to
`accounts.google.com`, `oauth2.googleapis.com`, `www.googleapis.com`. The application
network already has egress; PostgreSQL remains on its internal network. Ensure
the proxy and any external logs record neither query strings nor authorization
headers (OAuth callback URLs contain one-time codes). The supplied Nginx configs
use a log format with no URI/query. Keep Django DEBUG off.
The application also forces DEBUG off when Google credential secrets are configured,
including local development, to keep technical error pages from exposing tokens.

For local Docker use the explicit overlay:

```powershell
docker compose -f compose.yaml -f compose.drive.local.yaml up -d --build
docker compose -f compose.yaml -f compose.drive.local.yaml exec app python manage.py migrate --noinput
```

Set the placeholder paths to actual private files first. For host development,
set environment variables in the process before running Django; Django does not
automatically load `.env`. Docker Compose reads `.env` for substitution.

7. Sign in to SSDC as an active administrator, complete MFA and recent identity
   confirmation. Open **Document storage** in navigation (or `/storage/google/`).
   Click **Connect / reconnect Google Drive**. Select the storage owner's personal
   account and approve the narrow permission. This is storage authorization, not
   a replacement for staff login. State is session/account bound, expires after
   ten minutes, is single use and uses PKCE; initiation is CSRF-protected POST.
8. After returning to SSDC, click **Prepare / verify private folder**. The app
   creates **SSDC Private Documents** in the owner's My Drive, with no sharing
   changes. Leave it private. Do not share this folder or its files with staff,
   move files out of it, rename application markers or edit stored bytes in Drive.
   Portal folders remain logical PostgreSQL relationships inside one Drive folder.
9. Upload a synthetic PDF and image through an authorized folder. Confirm READY
   status, personalized viewer watermark, image thumbnail, PDF pagination and
   seeking, HEAD and byte ranges through SSDC. In browser network tools, document
   traffic must stay on the SSDC origin, without Google download URLs, credentials
   or Drive IDs. Confirm a different ungranted staff account gets no access, then
   revoke a grant/disable an account and verify the next request is denied.
   Confirm files use the owner's storage and have only the owner permission.
   Run `operations_check` and `verify_storage` from the configured application.
10. After revocation or an `invalid_grant` refresh failure, content returns a safe
    storage error and new uploads remain quarantined. An administrator must confirm
    identity and use **Connect / reconnect** again, with the **same owner account**
    and the same OAuth client. An omitted refresh token preserves the existing
    token; initial connection requires one. The original folder/IDs remain intact.
    Verify the folder, then run `retry_scans`. No Drive account consent happens
    automatically. Different-owner connections are rejected. Switching clients or
    owners requires an explicit operator data-migration plan, not reconnect.

## Consent publishing and token lifetime

Google's official OAuth documentation states that External apps in **Testing**
receive refresh tokens expiring after **seven days** when requesting Drive scope.
Publish the consent configuration appropriately before relying on unattended
production storage. Publishing does not guarantee permanent credentials:
revocation, disuse, account restrictions and token limits can still require
reconnection. `drive.file` is classified as non-sensitive; it avoids restricted
full-Drive scope verification. Follow Console's actual branding/domain and
verification requirements for your audience and production status; do not add
restricted scopes to bypass setup. A personal-use audience may qualify for
verification exceptions, but this code makes no promise that Google will approve
any particular consent screen.

## Reliability and cleanup

To move existing READY filesystem versions after connecting, take an encrypted
paired backup and stop all writers. Run `migrate_storage_to_drive` for a dry run,
then `migrate_storage_to_drive --execute`. It checks original hashes, uploads with
durable IDs, and changes each provider only after remote verification. Successful
commits remove local copies; failures retain the filesystem version and can be
retried. Quarantined/rejected versions are excluded. This migration has not been
run against any real documents. Run `verify_storage` before reopening service.

Originals and generated image previews use bounded resumable uploads. File IDs
are generated by Drive and recorded in `DriveObject` before create/upload.
Resumable session URLs are also encrypted in the upload intent before sending
chunks. Later retries probe and continue that session; an expired session restarts
with the same reserved ID. No upload-session capability is exposed to the browser.
An uncertain completion is probed, and retries reuse the ID. Reusing a completed ID
cannot create a duplicate; conflicts require matching owner, app markers, parent,
MIME type, size and checksum. Each version has an exclusive processing claim.
No version becomes visible before validation, scan, upload and publication commit.
If metadata publication rolls back, the quarantined version, temporary bytes and
upload intent support a retry. Initial HTTP form resubmission is a new version;
network retries of one persisted operation reuse its ID.

Transient network, rate-limit and server failures receive bounded backoff with
jitter; non-transient quota/missing/integrity failures do not trigger blind retries.
Network connect/read timeouts and existing parser/scanner/file-size limits apply.
Uploads share a sixty-second network budget for the original and thumbnail,
with short connect/read timeouts; retrieval also has a bounded stream duration.
Slow/repeated failures leave a retryable quarantined version rather than an
unlimited request. The application remains synchronous at this collection size.
Credentials are encrypted in PostgreSQL, refresh is serialized across workers,
and refreshed access tokens remain server-side. Credentials never go through
ordinary model admin forms. Google Drive metadata is revalidated for content/HEAD
requests; MIME types come from the validated version. Single PDF/image ranges
return 206 with exact Content-Range/Length; malformed/multiple/unsatisfiable ranges
return 416. HEAD ignores Range per HTTP semantics; If-Range without a matching
validator receives the full 200 representation. An upstream full response to a
range request is rejected, never mislabeled 206. Stream interruptions after headers
are sent result in a truncated response requiring a new authorized request.

Keep the private staging volume: quarantined files need it for retry. Successful
Drive publication removes staging files after commit. Staging left by interrupted
post-commit cleanup can also be removed by `cleanup_orphans`: it checks the
published Drive copy before removing local bytes. Stop **all** uploads, scan
retries, migrations and purges before cleanup, using a cutoff older than any
in-flight operation. `cleanup_orphans --before <ISO-8601-time>` is dry-run by
default. `--execute` only removes unreferenced recorded Drive objects after
ownership/app/parent/checksum checks. It does not search or delete arbitrary
owner Drive files. Quarantined originals and deterministic preview keys remain
referenced. Interrupted purge deletion leaves ledger entries for a later cleanup.
If ownership/integrity is uncertain, cleanup fails closed for operator investigation.

## Independent encrypted backup and restore

**Drive is not a separate backup.** A database-only backup cannot restore lost
Drive files. Nothing here provisions another service. Choose an independent
offline or offsite destination and key custodian under SSDC's retention policy.

Use `scripts/backup.py backup --compose compose.prod.yaml --env-file <private-env>
--key-file <separate-backup-key-file> --archive <new-independent-path>.ssdcbackup`.
The existing AES-256-GCM backup key format is base64-encoded 32 bytes, stored apart
from the archive. Stop external schedulers/operators first. The script stops app
and proxy, dumps PostgreSQL, calls `export_storage --stdout` in a one-shot app
container, and archives both PostgreSQL and private storage before authenticated
encryption. Drive originals/previews are downloaded through server credentials,
verified, and added to that snapshot; quarantined/filesystem bytes are included.
An unavailable, revoked or corrupt Drive object fails the backup. It restarts app
and proxy in `finally`. Use an encrypted operator disk for temporary staging and
adequate free space (up to several times collection size). Retain failed/incomplete
archives only for investigation; never count them as successful backups.

Run `scripts/backup.py drill` with the same configuration/key/archive on an
isolated operator machine: it authenticates/decrypts, restores to a temporary
PostgreSQL database, verifies original hashes/sizes and thumbnail presence, then
removes the temporary database. It does not upload or change live Drive files.
Schedule and record restore drills and independently protect archived copies.

Disaster recovery when Drive or credentials cannot be recovered:

1. Keep live workers stopped. Authenticate/decrypt the archive on a trusted
   encrypted disk (use the same `decrypt_file` helper as the drill). Extract only
   the two expected members, `postgres.dump` and `private.tar`, using Python's
   `tarfile` data filter. Never extract an unverified archive.
2. Restore PostgreSQL into a **new isolated database** with `pg_restore
   --exit-on-error --no-owner`. Extract `private.tar` with the data filter into a
   new private volume, with mode 0700 directories and 0600 files. Retain original
   Django/MFA keys separately if restoring those identities and MFA secrets.
3. Configure that isolated application with `DOCUMENT_STORAGE_PROVIDER=filesystem`
   and the restored private root; remove Google secret requirements/mounts from
   its Compose override. Use `restore_storage_to_filesystem` for a hash-verifying
   dry run, then `restore_storage_to_filesystem --execute`. It changes provider
   metadata only after all non-rejected originals and referenced previews verify.
   It never deletes or modifies Drive documents. If any check fails, restore stops.
4. Run `verify_storage`, Django checks and synthetic permission/preview checks.
   Invalidate old sessions before reopening service. Preserve the old database and
   volume until the restore is approved. New uploads may later target Drive after
   owner setup; restored filesystem versions remain readable.

The backup contains sensitive account, document and encrypted owner-token data.
The archive encryption key and Drive credential key must be held separately from
the database/archive. Restoring a database retains old Drive-object ledger entries:
do not run Drive cleanup against a restored environment without reconciling the
production catalog. This prevents a recovery drill from deleting live content.

## Official sources checked 2026-10-07

- [Web-server OAuth: redirect URIs, state, offline access and token exchange](https://developers.google.com/identity/protocols/oauth2/web-server)
- [OAuth token lifetime, Testing expiry and revocation](https://developers.google.com/identity/protocols/oauth2)
- [Drive scopes and `drive.file` classification](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)
- [Resumable uploads and pre-generated IDs](https://developers.google.com/workspace/drive/api/guides/manage-uploads)
- [Blob downloads and byte ranges](https://developers.google.com/workspace/drive/api/guides/manage-downloads)
- [Drive errors, quota and retries](https://developers.google.com/workspace/drive/api/guides/handle-errors)
- [OAuth production policy and personal-use verification exceptions](https://developers.google.com/identity/protocols/oauth2/production-readiness/policy-compliance)
- [Personal-use verification exceptions](https://developers.google.com/identity/protocols/oauth2/production-readiness/sensitive-scope-verification)
