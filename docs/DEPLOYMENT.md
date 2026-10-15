# Deployment and operations

For the Supabase PostgreSQL pilot use [HOSTED_PILOT.md](HOSTED_PILOT.md) and
standalone `compose.pilot.yaml`. Commands below using `compose.prod.yaml`
describe the existing self-hosted database stack. Do not combine the two files.

The primary document store is personal Google Drive through confidential owner
OAuth. Follow [the exact setup/release/backup guide](GOOGLE_DRIVE_SETUP.md) before
uploading. Apply vault migration 0005 with all old writers stopped. Production
Compose mounts Google client ID, secret and separate credential encryption key
files and requires the exact HTTPS callback URI. The local opt-in overlay is
`compose.drive.local.yaml`. Hosting logs must omit callback queries and Google
Authorization headers. Manual Google setup/consent has not been completed or
verified in this repository work.

Existing versions retain filesystem storage; preserve the private staging volume.
Drive does not replace Django/PostgreSQL/HTTPS hosting, ClamAV or independent backups.
The updated backup script exports referenced Drive documents/previews into the
encrypted paired snapshot. Use that script for Drive installations in the backup
procedures below. Quiesce external jobs and app workers before snapshots or cleanup.
Restore drills use isolated databases/files without modifying Google Drive.

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

For the free-first hosting plan, network/SSH setup, and automated HTTPS renewal,
see [HOSTING_SETUP.md](HOSTING_SETUP.md). Its ACME overlay and timer are optional;
they do not establish a provisioned host or close F16 without external evidence.

SSDC must approve a Linux server/domain/operator, current Docker/Compose, TLS
certificate/renewal, firewall, storage capacity and backup owner. Start with at
least 4 GiB RAM and measure representative workloads. Allow HTTPS, HTTP redirect
and restricted operator SSH; never publish 5432, 3310 or 8000. No public production
server/domain has been supplied or deployed.

Generate unique production keys on that host using `scripts/generate_secrets.py`
(requires cryptography in an operator Python environment). Never reuse local keys
or demo accounts. Restrict secret files to the operator/Compose runtime, and keep
MFA/backup key recovery copies separately from backups. On Linux:

```sh
sudo python scripts/generate_secrets.py --linux --directory /srv/ssdc/secrets --recovery-directory /secure/ssdc-recovery
```

Service files are root-owned `0640`: numeric GID 11001 for application secrets,
11002 for the bootstrap password, and 11003 for the migration password. Compose
adds only the reader groups required by each service. Files are mounted individually;
the host directory stays `0700`. The backup key stays operator-only `0600` outside
service mounts. Import Google client files privately, then run the generator with
`--linux --permissions-only --directory /srv/ssdc/secrets` to set their permissions.
Do not rely on Compose secret `uid/gid/mode` remapping. Rootless/user-namespace Docker
requires corresponding mapped host IDs and a repeated permission check. On SELinux
hosts label the dedicated secret directory for container reads using the host's
approved persistent `semanage fcontext`/`restorecon` policy; never disable enforcement.
Generation also restricts pre-existing secret and recovery directories to `0700`.
`python scripts/check_linux_secrets.py --image <app-release-image> --db-image <db-release-image>`
transfers the current generator into a disposable Linux fixture, verifies ownership
and modes, and binds individual files from the Linux daemon's volume directory.
It checks application/migration reader groups, the database image's configured user,
denial to an unrelated UID, imported Google client permissions, and exclusion of
the recovery key, with read-only roots and dropped capabilities. It cleans up only
its randomly named fixture volumes. Run against a local Linux Docker daemon with
permission to create containers and bind its volume files. It does not attest to
the final host's user-namespace or SELinux configuration; repeat those checks there.

Create an operator-owned, ignored `.env.production` with paths and approved hostnames:

```dotenv
POSTGRES_DB=ssdc
POSTGRES_USER=ssdc_bootstrap
DB_BOOTSTRAP_PASSWORD_FILE=/srv/ssdc/secrets/db-bootstrap-password
DB_MIGRATION_PASSWORD_FILE=/srv/ssdc/secrets/db-migration-password
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
docker compose --env-file .env.production -f compose.prod.yaml run --rm migrate
docker compose --env-file .env.production -f compose.prod.yaml run --rm migrate python manage.py configure_runtime_role
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

Copy the complete environment template from `deploy/production.env.example`, including
the Google secret paths. PostgreSQL bootstrap is operator-only; migrations use
`ssdc_migrator`; the web application uses `ssdc_runtime` with table/sequence grants,
no schema/object ownership or role memberships, and insert/read-only access to audit events. Run
`configure_runtime_role` after **every** migration before starting app traffic.
Grant configuration refuses privileged runtime attributes, membership in any other
role, and ownership of databases, schemas, tables/sequences or functions. Revoking
explicit grants cannot remove ownership rights; repair ownership with the operator
identity before retrying. `python scripts/check_database_roles.py` verifies fresh
initialization/migration, rejection of unsafe membership/ownership, synthetic upload,
staff sign-in/view/range/logout, administrator MFA and denied SQL privileges in a
disposable database/container. It uses development scanning and non-manifest static
serving for its HTTP checks; it does not validate ClamAV, TLS or production assets.

Existing volumes do not rerun initialization. Take a paired backup, stop all writers,
mount the new secrets, and explicitly execute `sh /docker-entrypoint-initdb.d/10-roles.sh`
in the DB service using the existing bootstrap identity. Transfer existing objects
in this database from that identity to `ssdc_migrator` with PostgreSQL
`REASSIGN OWNED BY <existing-bootstrap-role> TO ssdc_migrator` as the operator;
check ownership first (this statement also affects shared objects owned by that
role). Do not run it against an unrelated/shared database cluster. Run migrations
and grant configuration with the migration service, verify runtime denials, then
start rebuilt writers. Never give the runtime role membership in either other role.
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

For the F04 update, stop the app and any operator scan/purge jobs before applying
`vault.0004_serialize_policy_writes`. Restart only rebuilt processes from the same
release after migration succeeds; do not overlap older writers with the new lock
order. This migration installs PostgreSQL guards coordinating document/folder
policy changes with the authorization checks immediately before writes. A policy
change that commits first prevents the write; a write already authorized completes
its short transaction before a waiting policy change takes effect. File validation
and scanning run outside that guard and publication checks access again. Account
role, active-state, and session-version changes coordinate through account locks.
The physical purge command also follows the new lock order.

The F05 update adds no migration beyond F04's existing requirement. Stop/drain
older app processes and retry jobs before replacing them; older scan code does
not participate in the new per-version processing claim. Each attempt uses a
nonblocking PostgreSQL session advisory lock, held through its final outcome and
normal committed cleanup. Duplicate attempts leave that version pending while
its owner works; other versions can still scan concurrently. Claims are released
on completion/error or when the owning database session ends, following
[PostgreSQL advisory-lock semantics](https://www.postgresql.org/docs/current/explicit-locking.html#ADVISORY-LOCKS).
Keep the configured direct PostgreSQL connection or session-preserving pooling;
transaction pooling cannot preserve this claim across scanning and finalization.

The F09 update adds no migration of its own. Account, permission, and document
mutations commit with their local audit events; a failed event write rolls back
the associated database change. Selected-user session revocation and MFA reset
are all-or-nothing across the selection, as is administrative bulk deletion,
including Django's deletion history. A cancelled password-disable submission
does not generate a password-reset success event.

## Backups and restoration

`scripts/backup.py` stops app/proxy during a consistent PostgreSQL custom dump and
private storage archive including exported Drive blobs, then restarts both even on failure. AES-256-GCM encryption
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
`restore_storage_to_filesystem` for a dry run and then `--execute` if recovering
independently of Drive (configure the isolated app with filesystem storage first).
Run `verify_storage`, revoke old sessions, check migrations/permissions and synthetic
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

Executing orphan cleanup first commits an `operator_orphan_cleanup` event with
outcome `started` and prints its operation ID. A matching `success` or `failed`
event records the result. Run execution outside an existing database transaction
so that this initial record is durable before any files are removed. A failed
initial event prevents deletion. If completion recording fails or the process
stops, files may already have been removed; the initial record remains, and a
recording error makes the command fail rather than report successful completion.
Investigate operations with a start and no terminal result. Dry runs remove
nothing and do not create execution events.

Physical purge processes each document separately: removing its database records
and recording `operator_purge` / `scheduled` commit together, followed by file
removal and a matching `success` or `failed` event using the document ID. A failure
on a later document does not undo earlier completed documents. If scheduling
fails, that document and its files remain; if file removal or completion recording
fails after commit, its scheduled record remains and the command fails. Review
scheduled purges without a terminal result before retrying or reconciling storage.
These records do not replace the maintenance and approved-retention prerequisites.

If upload access changes during scanning, the accepted original remains
quarantined with an administrator-review note and is not published. Scan retries
recheck the uploader's current account and document permissions; restore the
appropriate approved access before retrying. Retry commands skip versions already
being processed and versions removed after the command's initial query. A fresh
status check protects published/rejected outcomes before scanning and before each
outcome is saved. Generated previews use complete temporary files followed by
atomic replacement, so interrupted previews can be rebuilt on retry. Rejection
and its audit event commit together; original/preview deletion follows commit,
and rollback preserves the files. Genuine scanner failures remain quarantined.

DB/storage/scanner failures produce unavailable health or quarantined uploads.
Investigate infrastructure/limits; never weaken permissions or bypass scanning.
Keep debug off. Patch dependencies/images and test before releasing.

## Local production smoke fixture

The local smoke uses separate volumes and a two-day self-signed certificate:

```powershell
.\.venv\Scripts\python.exe scripts/generate_secrets.py
.\.venv\Scripts\python.exe scripts/prepare_https_smoke.py
docker compose build app
docker compose -p ssdc-vault-smoke --env-file .env.production-smoke -f compose.prod.yaml -f deploy/compose.smoke.yaml up -d db clamav --no-build
docker compose -p ssdc-vault-smoke --env-file .env.production-smoke -f compose.prod.yaml -f deploy/compose.smoke.yaml run --rm migrate
docker compose -p ssdc-vault-smoke --env-file .env.production-smoke -f compose.prod.yaml -f deploy/compose.smoke.yaml run --rm migrate python manage.py configure_runtime_role
docker compose -p ssdc-vault-smoke --env-file .env.production-smoke -f compose.prod.yaml -f deploy/compose.smoke.yaml up -d app proxy --no-build
.\.venv\Scripts\python.exe scripts/production_smoke.py
docker compose -p ssdc-vault-smoke --env-file .env.production-smoke -f compose.prod.yaml -f deploy/compose.smoke.yaml down
```

Skip key generation if local keys already exist (it never overwrites). This fixture
is loopback-only and not a public deployment. Certificate-error bypass exists only
in this synthetic test browser.

For a repeatable isolation check without starting the browser or reusing that
fixture, run `python scripts/check_smoke_isolation.py`. It uses random disposable
project names with the production and smoke configurations and fresh synthetic
credentials. Both databases run concurrently; smoke writes and teardown must leave
the other's container, start time, database and file sentinels unchanged. All
persistent volume/network names must be disjoint. The checker removes only its own
projects and loads no deployment environment file. It uses the local DB image and
does not test public HTTPS or actual Google Drive.
