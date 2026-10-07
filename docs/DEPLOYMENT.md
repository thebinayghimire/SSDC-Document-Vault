# Deployment and operations

## Local setup

Docker Desktop must be running. From a fresh terminal in this repository:

```powershell
docker compose up -d --build
docker compose exec app python manage.py migrate --noinput
docker compose exec app python manage.py createsuperuser
```

Open http://127.0.0.1:8080. Enroll an authenticator on first administrator login
and save recovery codes. Only loopback 8080 is published; DB/scanner/app remain
internal. Stop/start with `docker compose stop` / `docker compose start`.
`docker compose down` retains volumes. Do not use `down -v` unless intentionally
destroying this environment's data. Do not expose development to LAN/internet.
For host tests only, add `-f compose.host.yaml` after `-f compose.yaml`; it publishes
PostgreSQL on loopback 5432 and adds a host-test network.

## Production requirements

SSDC must approve a Linux server/domain/operator, current Docker/Compose, TLS
certificate/renewal, firewall, storage capacity and backup owner. Start with at
least 4 GiB RAM and measure representative workloads. Allow HTTPS, HTTP redirect
and restricted operator SSH; never publish 5432, 3310 or 8000. No public production
server/domain has been supplied or deployed.

Generate unique production keys on that host using `scripts/generate_secrets.py`
(requires cryptography in an operator Python environment). Never reuse local keys
or demo accounts. Restrict secret files to the operator/Compose runtime, and keep
MFA/backup key recovery copies separately from backups.

Create an operator-owned, ignored `.env.production` with paths and approved hostnames:

```dotenv
POSTGRES_DB=ssdc
POSTGRES_USER=ssdc
ALLOWED_HOSTS=vault.example.org
HEALTHCHECK_HOST=vault.example.org
CSRF_TRUSTED_ORIGINS=https://vault.example.org
DB_PASSWORD_FILE=/srv/ssdc/secrets/db-password
DJANGO_KEY_FILE=/srv/ssdc/secrets/django-key
MFA_KEY_FILE=/srv/ssdc/secrets/mfa-key
TLS_CERT_FILE=/srv/ssdc/tls/fullchain.pem
TLS_KEY_FILE=/srv/ssdc/tls/privkey.pem
MFA_ALL_STAFF=0
```

Replace example.org with the approved domain. Compose mounts secrets, never public
document media. Use the separate production configuration:

```sh
docker compose --env-file .env.production -f compose.prod.yaml build --pull --no-cache
docker compose --env-file .env.production -f compose.prod.yaml up -d db clamav
docker compose --env-file .env.production -f compose.prod.yaml run --rm app python manage.py migrate --noinput
docker compose --env-file .env.production -f compose.prod.yaml run --rm app python manage.py check --deploy
docker compose --env-file .env.production -f compose.prod.yaml run --rm app python manage.py createsuperuser
docker compose --env-file .env.production -f compose.prod.yaml up -d app proxy
docker compose --env-file .env.production -f compose.prod.yaml exec app python manage.py scanner_selftest
```

The application runs non-root with read-only root, dropped capabilities, bounded
memory/processes and writable bounded /tmp. Private storage and DB use separate
volumes. Base images are pinned by digest. Proxy/scanner builds additionally apply
current Alpine security updates; preserve resulting release image digests for
repeatable rollback. PostgreSQL runs unprivileged and its obsolete root helper is
removed from filesystem and image layers. Unused proxy modules are removed.
Confirm the hostname for health.
`security.W021` reports that HSTS preload is off: this is intentional until the
domain owner approves browser preload registration. It is not suppressed. HSTS
and includeSubDomains are on; ensure all affected subdomains support HTTPS.

## Releases and rollback

Review changes, run tests/scans, build the pinned image, create an encrypted paired
backup, enter maintenance, apply migrations once, replace app, and reload/restart
Nginx so it resolves the replacement address. Confirm health, antivirus signatures,
HTTPS/MFA, denied cross-user requests and synthetic previews. Preserve the previous
release/image and backup. Base-distribution changes can change PostgreSQL collation
versions: rebuild affected indexes before refreshing database collation versions
(including development templates) during maintenance; do not just silence the
warning. Migration rollback may require paired DB/file restore;
never restore only DB while retaining inconsistent file metadata. Refresh image
digests deliberately and retest. Do not load real SSDC records before review.

## Backups and restoration

`scripts/backup.py` stops app/proxy during a consistent PostgreSQL custom dump and
private volume archive, then restarts both even on failure. AES-256-GCM encryption
streams to an exclusive file. Store the base64 32-byte backup key separately;
the MFA key is also required after recovery. Schedule via systemd/Task Scheduler
under a restricted operator account after SSDC chooses frequency, retention,
offsite destination and RPO/RTO. Monitor job failures and available disk space.

```sh
python scripts/backup.py backup --compose compose.prod.yaml --env-file .env.production --key-file /secure/backup-key --archive /backups/ssdc-release.ssdcbackup
python scripts/backup.py drill --compose compose.prod.yaml --env-file .env.production --key-file /secure/backup-key --archive /backups/ssdc-release.ssdcbackup
```

The drill authenticates/decrypts the archive, restores a fresh temporary database,
extracts private files into a temporary directory, verifies all original hashes,
sizes and thumbnails, then drops only the temporary database it created. Live data
stays intact. Protected temporary plaintext needs encrypted host disks and enough
disk for bundles/extraction. Temporary files are removed on normal completion.

Disaster recovery uses a fresh isolated host: recover code/keys, start empty
DB/private volume, authenticate/decrypt using `scripts.backup.decrypt_file`, extract
with tar's data filter, restore with `pg_restore --exit-on-error --no-owner` into
the empty DB, copy `private/` into `/data/private` owned by UID/GID 10001, run
`verify_storage`, revoke old sessions, check migrations/permissions and synthetic
preview, then reopen proxy. Do not overwrite live data outside an approved recovery
maintenance window. Repeat drills regularly and record evidence.

## Monitoring and maintenance

Monitor `docker compose ps`, `/health/`, `operations_check`, disk/DB connections, scanner signature
freshness, quarantined versions and HTTP/audit errors. Production container logs
rotate (5 × 10 MiB). An SSDC-owned alert destination is still needed; none is
invented. Run `clearsessions` and `clear_rates` regularly. Audit retention awaits organizational policy.
Retry scans with `retry_scans --limit 20`. `cleanup_orphans --before <ISO timestamp>`
is dry-run; stop uploads and choose a cutoff older than in-flight work before
`--execute`. `purge_deleted --before ...` also defaults to dry-run and execution
requires `--policy-reference <approved reference>`.

DB/storage/scanner failures produce unavailable health or quarantined uploads.
Investigate infrastructure/limits; never weaken permissions or bypass scanning.
Keep debug off. Patch dependencies/images and test before releasing.

## Local production smoke fixture

The local smoke uses separate volumes and a two-day self-signed certificate:

```powershell
.\.venv\Scripts\python.exe scripts/generate_secrets.py
.\.venv\Scripts\python.exe scripts/prepare_https_smoke.py
docker compose build app
docker compose --env-file .env.production-smoke -f compose.prod.yaml -f deploy/compose.smoke.yaml up -d --no-build
docker compose --env-file .env.production-smoke -f compose.prod.yaml -f deploy/compose.smoke.yaml exec app python manage.py migrate --noinput
.\.venv\Scripts\python.exe scripts/production_smoke.py
docker compose --env-file .env.production-smoke -f compose.prod.yaml -f deploy/compose.smoke.yaml down
```

Skip key generation if local keys already exist (it never overwrites). This fixture
is loopback-only and not a public deployment. Certificate-error bypass exists only
in this synthetic test browser.
