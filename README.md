# SSDC Document Vault

Private document library for Siddhartha Social Development Centre: Django,
PostgreSQL, private storage, ClamAV, self-hosted PDF.js, and Docker/Nginx.
Original requirements and segments: `ssdc-conversation.md`.

Staff can sign in, browse/search permitted folders and documents, switch between
list/gallery, and preview PDFs/images with personalized watermarks. Managers have
scoped uploads, replacement/version history, archive/deletion/restoration. Admins
manage accounts/grants and review audit events. Privileged roles require MFA.
Every content/thumbnail/range request checks current authorization. Removed
download/print controls discourage copying; authorized users can still extract
bytes or take screenshots. See the threat model for residual risks.

## Start locally

Docker Desktop must be running. In a fresh PowerShell terminal here:

```powershell
docker compose up -d --build
docker compose exec app python manage.py migrate --noinput
docker compose exec app python manage.py createsuperuser
```

Open **http://127.0.0.1:8080**. Complete authenticator enrollment and save recovery
codes. In Administration, create folders/accounts and assign grants. Managers
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
