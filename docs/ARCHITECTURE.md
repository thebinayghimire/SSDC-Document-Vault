# Architecture

Browser -> HTTPS reverse proxy -> Django/Gunicorn -> PostgreSQL and Google Drive API.
Google Drive is primary storage for new accepted documents and image previews;
PostgreSQL owns filenames, hashes, sizes, MIME, processing status, folder relationships,
version history and SSDC grants. `DriveObject` records remote IDs and durable upload
intents. A private local volume stages validation/scanning and pending retries.
Each version records its provider so existing filesystem versions continue to work.
The storage-provider interface retains private filesystem support and recovery.
The browser never addresses private storage. Nginx serves application static
assets only. Application endpoints stream authorized originals or sanitized
thumbnails. PDF.js and its worker are self-hosted and version pinned.

Apps: `accounts` (custom user, login, MFA, revocation); `vault` (folders, explicit
grants, document/version lifecycle, private storage, scanner, policy, viewer);
`audit` (security events and shared rate limits). `config` owns environment
settings, routes, headers, health and session middleware.

Authorization is evaluated from current database state for each request. Folder
cycles are rejected. Document metadata uses UUID identifiers, which are not
credentials. Policy-filtered querysets run before pagination and search responses.
An authorization service resolves inherited grants without client-side filtering.

Uploads are bounded, stored under generated relative identifiers, inspected in
an isolated Python subprocess (15-second timeout; Linux CPU/memory/file limits;
no inherited application secrets), and
scanned through ClamAV INSTREAM. No original user filenames enter filesystem paths.
Scanning is synchronous and time bounded for v1, with a retry command for pending
versions. A future queue can replace the scanner invocation without changing the
storage/policy contract. Production fails closed without antivirus; an explicit
development-only skip permits synthetic local fixtures.

MFA secrets are encrypted using a separate configured Fernet key. Recovery codes
use Django password hashing. Session IDs rotate after complete authentication.
Authorization-version, account state, idle/absolute expiry, and MFA assurance are
checked on every authenticated request. Reauthentication guards high-impact UI
mutations. Audit rows are read-only in administration; database operators remain
a trust boundary. Rate limits live in PostgreSQL and apply across workers.

Deployment separates proxy/public and internal service networks. App containers
are non-root with dropped capabilities, resource limits, and private volumes.
Production startup runs migrations as an explicit release step, not per worker.
Backup pairs database and storage in a maintenance window to ensure consistency.
`export_storage` includes server-fetched Drive blobs in that pair; Drive alone is
not a backup. Owner credentials use offline OAuth with `drive.file`, encrypted
in the database under a separate key. Staff Google accounts are unnecessary.
See [owner setup and independent recovery](GOOGLE_DRIVE_SETUP.md).

References: [Django custom users](https://docs.djangoproject.com/en/5.2/topics/auth/customizing/),
[PDF.js](https://mozilla.github.io/pdf.js/getting_started/),
[Compose networks](https://docs.docker.com/reference/compose-file/networks/).
The global storage quota reserves 1 MiB of preview space for each image while
quarantined, then accounts for actual thumbnail bytes after publication. Original
and generated preview bytes both count. Pre-existing thumbnails receive a
conservative reservation during migration. Failed/rejected originals are cleaned.
