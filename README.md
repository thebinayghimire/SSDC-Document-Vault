# SSDC Document Vault

Private document library for Siddhartha Social Development Centre: Django,
PostgreSQL, private Google Drive storage, ClamAV, self-hosted PDF.js, and Docker/Nginx.
Original requirements and segments: `ssdc-conversation.md`.

Staff can sign in, browse/search permitted folders and documents, switch between
list/gallery, and preview PDFs/images. Managers have
scoped uploads, replacement/version history, archive/deletion/restoration. Admins
manage accounts/grants and review audit events. Privileged roles require MFA.
Every content/thumbnail/range request checks current authorization. Removed
download/print controls discourage copying; authorized users can still extract
bytes or take screenshots. See the threat model for residual risks.

Managers and administrators can use **Add documents** in the sidebar or the import
section in the library. Staff can see the entry point and upload-access guidance.
Choose a destination folder, select files or a local folder,
drag files/folders into the drop area, or paste copied files when the browser exposes
them. Review document titles and import up to 50 files per batch with individual
progress and results. Folder imports include supported files from subfolders and
save them all to the selected vault folder. PDF, JPEG, PNG, and WebP are supported;
the default limit is 25 MiB per file. Uploads retain folder permissions, scanning,
storage quotas, and audit records. If no upload destination is available, create a
folder as an administrator or request a manage grant. **Choose files** also works
when clipboard access is unavailable; a single-file form is available without JavaScript.

## Start locally

New uploads now select Google Drive. Complete the private owner setup in
[docs/GOOGLE_DRIVE_SETUP.md](docs/GOOGLE_DRIVE_SETUP.md), including the local
Compose overlay and exact OAuth callback, before uploading. Existing private
filesystem versions remain readable. For synthetic filesystem-only development,
explicitly set `DOCUMENT_STORAGE_PROVIDER=filesystem` in the app environment.
Implementation is mock-tested; no live Google account connection or deployment
has been verified. The website/database still need hosting, and Drive is not a backup.

Docker Desktop must be running. In a fresh PowerShell terminal here:

```powershell
docker compose up -d --build
docker compose exec app python manage.py migrate --noinput
docker compose exec app python manage.py createsuperuser
```

Open **http://127.0.0.1:8080**. Complete authenticator enrollment and save recovery
codes when MFA is enabled. Local Compose temporarily uses password-only login;
set `MFA_ENABLED=1` in `.env` and recreate the app to restore authenticator prompts.
Production always requires MFA. In Administration, create folders/accounts and assign grants. Managers
need a manage grant in addition to their role. Upload from a folder page. Files
become viewable after scanning; ClamAV's first startup may take several minutes.
Run `retry_scans` to retry an early quarantined upload.

Stop/restart: `docker compose stop` / `docker compose start`. After changing code,
run `docker compose up -d --build app` and `docker compose exec proxy nginx -s reload`.
Data stays in private named volumes. Use synthetic documents locally. Production
uses a separate Compose file and explicit secrets/HTTPS.

Optional demo: `docker compose exec app python manage.py seed_demo`. It refuses
production and existing demo users. Random passwords are saved in the container
at `/app/artifacts/demo-credentials.json`; copy locally using
`docker compose cp app:/app/artifacts/demo-credentials.json artifacts/demo-credentials.json`.
The file is ignored by Git. `demo.staff` demonstrates viewing; `demo.admin` uses
MFA enrollment. Keep demo accounts confined to local development.

## Development checks

Git, Node/npm, uv and Python 3.13 are needed for host development. Runtime and
development dependencies are pinned separately; npm supplies PDF.js assets.

```powershell
uv python install 3.13
uv venv --python 3.13 .venv
uv pip sync requirements-dev.txt
npm.cmd ci --ignore-scripts
npm.cmd run vendor
.\.venv\Scripts\python.exe -m playwright install chromium
docker compose -f compose.yaml -f compose.host.yaml up -d db
.\.venv\Scripts\python.exe manage.py migrate --noinput
.\.venv\Scripts\python.exe manage.py collectstatic --noinput
.\.venv\Scripts\pytest.exe -q --tb=short
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt --no-deps --disable-pip
npm.cmd audit --omit=dev
```

Tests use a dedicated PostgreSQL test database. Browser checks use the synthetic
demo: `python scripts/browser_check.py`. Screenshots/reports are in ignored
`artifacts/`. No real SSDC data or secrets belong in Git. Refresh pins deliberately
using `uv pip compile --universal` on the `.in` files.

If Docker's credential helper isn't found in an old terminal, restart it or add
`C:\Program Files\Docker\Docker\resources\bin` to the process PATH. Host DB testing
needs `compose.host.yaml`; normal DB networking is internal. For quarantined
previews, check scanner readiness and run `scanner_selftest`.

## Documentation and release status

- `docs/PRODUCT_SPEC.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`: design and limits.
- `docs/SECURITY.md`, `TEST_PLAN.md`: controls and verification strategy.
- `docs/DEPLOYMENT.md`: HTTPS, release, backup, restore and operator procedures.
- `docs/PROGRESS.md`, `SECURITY_REVIEW.md`: actual results, gaps and release gates.

Local implementation and production configuration are reviewable. Public
deployment needs approved hosting/policies and independent security review.
Automated self-review cannot approve SSDC's release.
