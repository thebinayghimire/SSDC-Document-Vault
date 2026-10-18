# SSDC Document Vault — Production Readiness & Deployment Runbook

**Audit Date:** 18 October 2026  
**Target Repository:** SSDC Document Vault (Django 5.2, PostgreSQL 17, ClamAV, Google Drive API, Nginx, Docker Compose)

---

## Executive Summary: Audit Findings

An end-to-end audit of the repository shows that the core security architecture—custom authentication, TOTP MFA, row-locked authorization, PostgreSQL policy triggers (`0004` and `0007`), Landlock + seccomp parser sandboxing, atomic audit logging, and resumable Google Drive storage—is implemented and covered by tests.

However, **9 specific code/configuration issues** must be fixed before you build your final images and deploy:

| # | Severity | Location | Issue Found |
|---|---|---|---|
| **1** | **CRITICAL** | `.gitignore` | `*.db` is in `.gitignore` (line 37), which matches and ignores `deploy/Dockerfile.db`. Any fresh clone or packed release is missing the database Dockerfile required by `compose.prod.yaml` and `compose.oracle.yaml`. |
| **2** | **HIGH** | `compose.prod.yaml` | `clamav` is limited to `mem_limit: 2g` in `compose.prod.yaml` (unlike `compose.pilot.yaml`, which was updated to `4g`). During `freshclam` signature reloads, two engines coexist in RAM (~3 GiB) and the Linux OOM-killer will terminate `clamd`. |
| **3** | **HIGH** | `deploy/nginx.prod.conf.template` & `accounts/views.py` | If deploying behind **Cloudflare Tunnel** (the zero-cost route in `docs/HOSTING_SETUP.md`), Nginx sees all traffic arriving from the tunnel container IP (`$remote_addr`). Without trusting `CF-Connecting-IP` from the tunnel, **all staff share one rate-limit bucket** (`10r/s` in Nginx and `LOGIN_IP_LIMIT` in Django), allowing one user to lock out the entire organization. |
| **4** | **HIGH** | `scripts/release_manifest.py` | Hardcodes `for service in ("app", "db", "proxy", "clamav"):`, which crashes with `KeyError` when generating a release manifest for `compose.pilot.yaml` (no `db` service) or `compose.oracle.yaml` (no `clamav` service). |
| **5** | **HIGH** | `Dockerfile` / `PILOT_IMAGE_AUDIT.md` | `scripts/release_manifest.py` fails with exit code `1` because Debian Trixie's `zlib` (`1:1.3.dfsg+really1.3.1-1`) is flagged for `CVE-2026-85091` with no upstream Debian binary fix yet. You must either upgrade the base image digest or pass a reviewed VEX/ignore rule so the release gate is deterministic. |
| **6** | **MEDIUM** | `compose.prod.yaml` & `compose.pilot.yaml` | `app` depends on `clamav: {condition: service_healthy}`, but `clamav` has no explicit `start_period` in Compose. On a cold start when `freshclam` downloads initial `.cvd` databases over slower links, `clamav` can be marked unhealthy before `clamd` starts. |
| **7** | **MEDIUM** | `vault/views.py` & `config/admin.py` | Several reauthentication redirects (`manage_document`, `lifecycle`, `create_folder`, `restore_version`, and `VaultAdminSite.login`) redirect to `/accounts/confirm/` without `?next=...`, dropping the user back to `/` instead of their intended action. |
| **8** | **LOW** | `vault/management/commands/operations_check.py` | Duplicate database/storage probes (already performed inside `readiness_failures()`) and an unguarded `probe.unlink()` that can leave a `health-*` file behind if a write fails. |
| **9** | **LOW** | `scripts/browser_check.py` & `DEPLOYMENT_FIXES.md` | `scripts/browser_check.py` still asserts the removed `.watermark` selector from before the UI redesign, and `DEPLOYMENT_FIXES.md` still marks F11–F32 and F34–F36 as unchecked (`[ ]`) even though their code is already in the repository. |

---

## Phase 1: Code & Configuration Fixes (Do This First)

### Step 1.1: Un-ignore and restore `deploy/Dockerfile.db`

Because `.gitignore` contains `*.db`, Git ignores `deploy/Dockerfile.db`.

1. **Edit `.gitignore`** and add `!deploy/Dockerfile.db` right after `*.db`:

```gitignore
*.pem
*.key
*.db
!deploy/Dockerfile.db
*.db-shm
*.db-wal
```

2. **Verify `deploy/Dockerfile.db` exists and is tracked in Git.** If it is missing on your machine, recreate `deploy/Dockerfile.db` with the hardened non-root PostgreSQL 17 Trixie build (which removes the `gosu` root helper and runs as UID/GID `999:999`):

```dockerfile
# deploy/Dockerfile.db
FROM postgres:17-trixie@sha256:ae69c452f483507a6b99fb654cf93aad7fe156ffd2c56247707eef4e36d3c12b AS base
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/local/bin/gosu

FROM scratch
COPY --from=base / /
ENV LANG=en_US.utf8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/17/bin PGDATA=/var/lib/postgresql/data
VOLUME ["/var/lib/postgresql/data"]
USER 999:999
ENTRYPOINT ["docker-entrypoint.sh"]
EXPOSE 5432
CMD ["postgres"]
```

3. Stage it in Git and verify `package-lock.json` is also tracked:

```bash
git add -f deploy/Dockerfile.db package-lock.json .gitignore
```

---

### Step 1.2: Fix ClamAV memory limit and startup grace period in `compose.prod.yaml` & `compose.pilot.yaml`

In `compose.prod.yaml`, update the `clamav` service so `mem_limit` is `4g` (matching `compose.pilot.yaml`) and add a `healthcheck` with `start_period: 180s` to both `compose.prod.yaml` and `compose.pilot.yaml`:

```yaml
  clamav:
    image: ${SCANNER_IMAGE:?Set exact scanner release image reference}
    build: {context: ., dockerfile: deploy/Dockerfile.scanner}
    environment: {TZ: UTC}
    volumes: [clam-data:/var/lib/clamav]
    read_only: true
    tmpfs: ["/run/clamav:rw,noexec,nosuid,size=8m,uid=100,gid=101,mode=0770", "/tmp:rw,noexec,nosuid,size=64m"]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    networks: [backend, updates]
    restart: unless-stopped
    mem_limit: 4g
    logging: {driver: json-file, options: {max-size: 10m, max-file: "5"}}
    healthcheck:
      test: [CMD, /usr/local/bin/clamdcheck.sh]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 180s
```

---

### Step 1.3: Fix `scripts/release_manifest.py` to support all Compose targets (`prod`, `pilot`, `oracle`)

In `scripts/release_manifest.py`, replace line 67:

```python
    # Replace:
    # for service in ("app", "db", "proxy", "clamav"):
    # With:
    for service in [s for s in ("app", "db", "proxy", "clamav") if s in config["services"]]:
```

---

### Step 1.4: Preserve `?next=` across all reauthentication redirects

1. **In `config/admin.py`**, update `VaultAdminSite.login`:

```python
from urllib.parse import urlencode
from django.contrib.admin import AdminSite
from django.shortcuts import redirect
from django.urls import reverse

class VaultAdminSite(AdminSite):
    ...
    def login(self, request, extra_context=None):
        if request.user.is_authenticated:
            return redirect(
                reverse("reauthenticate") + "?" + urlencode({"next": request.get_full_path()})
            )
        return redirect(reverse("login") + "?" + urlencode({"next": request.get_full_path()}))
```

2. **In `vault/views.py`**, add a helper function right below `recent_identity(request)` and use it in `manage_document`, `lifecycle`, `create_folder`, `restore_version`, and `import_documents`:

```python
def redirect_reauthenticate(request):
    target = request.get_full_path() if request.method in {"GET", "HEAD"} else reverse("library")
    return redirect(reverse("reauthenticate") + "?" + urlencode({"next": target}))
```

Then replace `return redirect("reauthenticate")` in `manage_document` and `create_folder` with `return redirect_reauthenticate(request)`, and in `lifecycle` / `restore_version` redirect to `reverse("reauthenticate") + "?" + urlencode({"next": reverse("manage_document", args=[document.pk])})`.

---

### Step 1.5: Clean up `vault/management/commands/operations_check.py`

`readiness_failures()` in `config/readiness.py` already checks `SELECT 1`, private storage write/read/unlink (with a `finally` block), disk headroom, and ClamAV signature age. Simplify `vault/management/commands/operations_check.py` so it does not run duplicate unguarded probes:

```python
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from config.readiness import readiness_failures
from vault.models import Version
from vault.storage import StorageError


class Command(BaseCommand):
    help = "Operator checks: DB, private storage, disk headroom, Drive folder, and scan backlog."

    def handle(self, *args, **options):
        failures = readiness_failures()
        if settings.DOCUMENT_STORAGE_PROVIDER == "gdrive":
            from vault.drive_storage import ensure_folder

            try:
                ensure_folder()
            except StorageError as exc:
                failures.append(str(exc))
        try:
            if Version.objects.filter(
                status=Version.Status.QUARANTINED,
                uploaded_at__lt=timezone.now() - timedelta(minutes=15),
            ).exists():
                failures.append("quarantined versions older than 15 minutes")
        except Exception:
            failures.append("scan backlog could not be checked")
        if failures:
            raise CommandError("; ".join(failures))
        self.stdout.write("Database, private storage, disk headroom and scan backlog checks passed")
```

---

### Step 1.6: Add Cloudflare Tunnel Client-IP Support (Only if Using Cloudflare Tunnel)

If you deploy using the **Self-Hosted Machine + Cloudflare Tunnel** route (`docs/HOSTING_SETUP.md`), Nginx will see all requests coming from the `cloudflared` container IP unless configured otherwise.

Create `deploy/compose.tunnel.yaml` if using Cloudflare Tunnel:

```yaml
# Overlay for Cloudflare Tunnel: binds proxy to loopback only; no public ports exposed on LAN/WAN.
services:
  proxy:
    ports: !override
      - "127.0.0.1:8443:8443"
```

And if routing through `cloudflared` on localhost/Docker network, ensure `deploy/nginx.prod.conf.template` extracts `CF-Connecting-IP` only from the trusted local tunnel proxy (`set_real_ip_from 127.0.0.1; set_real_ip_from 172.16.0.0/12; real_ip_header CF-Connecting-IP;`). *(Do not enable `CF-Connecting-IP` if port 443 is directly open to the public internet without Cloudflare IP range restrictions, or clients could spoof headers.)*

---

### Step 1.7: Update `scripts/browser_check.py` to match the redesigned UI

In `scripts/browser_check.py`, remove line 44 (`expect(page.locator(".watermark")).to_contain_text("demo.staff")`) and replace it with `expect(page.locator(".watermark")).to_have_count(0)` so it matches the watermark-free preview requirement in `FEATURE_ROADMAP.md` and `tests/test_ui.py`.

---

## Phase 2: Pre-Deployment Verification Gate

Run the following verification checklist from a clean terminal against your local Docker daemon before touching any production server. Every check must exit `0`:

### Step 2.1: Static, Lint, Migration, and Dependency Checks

```bash
# 1. Install locked dependencies & vendor PDF.js
python -m pip install --require-hashes -r requirements.txt
python -m pip install -r requirements-dev.txt
npm ci --ignore-scripts
npm run vendor

# 2. Django system & migration checks
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py collectstatic --noinput

# 3. Code formatting and linting
python -m ruff check .
python -m ruff format --check .

# 4. Dependency vulnerability audits
python -m pip_audit -r requirements.txt --no-deps --disable-pip
python -m pip_audit -r requirements-dev.txt --no-deps --disable-pip
npm audit --omit=dev
```

### Step 2.2: Full Test Suite + Linux Container Security Harnesses

```bash
# 1. Run full backend + Playwright UI test suite against disposable PostgreSQL
python scripts/run_checks.py --junit artifacts/pre-release-tests.xml

# 2. Build candidate images
docker build -t ssdc-vault-app -t ssdc-vault-candidate-app .
docker build -f deploy/Dockerfile.db -t ssdc-postgres .
docker build -f deploy/Dockerfile.proxy -t ssdc-proxy .
docker build -f deploy/Dockerfile.scanner -t ssdc-clamav .

# 3. Verify Linux TLS installer inside the Linux container (closes the Windows skip gap in PILOT_VALIDATION.md)
docker run --rm -v "${PWD}:/work:ro" -w /work ssdc-vault-app python -m unittest tests/test_tls_install.py

# 4. Verify Linux Landlock + seccomp parser sandbox
python scripts/check_linux_parser.py

# 5. Verify Linux flock maintenance lock exclusion and crash release
python scripts/check_linux_maintenance.py

# 6. Verify Linux 0640 secret reader groups (11001, 11002, 11003)
python scripts/check_linux_secrets.py --image ssdc-vault-app --db-image ssdc-postgres

# 7. Verify PostgreSQL role separation (ssdc_bootstrap, ssdc_migrator, ssdc_runtime)
python scripts/check_database_roles.py

# 8. Verify smoke/production volume isolation
python scripts/check_smoke_isolation.py
```

### Step 2.3: Resolve the Container CVE Gate (`CVE-2026-85091`)

Before running `scripts/release_manifest.py`:
1. Pull the latest `python:3.13-slim-trixie` and `postgres:17-trixie` digests to check if Debian has published a patched `zlib1g` binary:
   ```bash
   docker pull python:3.13-slim-trixie
   docker pull postgres:17-trixie
   ```
2. Update the `@sha256:...` digests in `Dockerfile` and `deploy/Dockerfile.db` if newer images are available, then rebuild and run:
   ```bash
   docker scout cves --only-severity critical,high --exit-code local://ssdc-vault-app
   ```
3. If Debian still marks `CVE-2026-85091` as `unfixed` in Trixie (where `zlib 1.3.1` is present and the application never invokes non-blocking `gzprintf`/`gzvprintf` on C streams), record the signed owner risk acceptance in `docs/PILOT_IMAGE_AUDIT.md`.

---

## Phase 3: External Prerequisites (Google Drive, Domain & Host)

### Step 3.1: Prepare the Linux Host (Ubuntu Server 24.04 LTS)

1. Install Ubuntu Server 24.04 LTS with full-disk encryption, unattended security upgrades, Docker Engine + Compose plugin, `certbot`, `openssl`, `git`, and `python3-cryptography`.
2. Ensure the Linux kernel is **6.2+** (Ubuntu 24.04 ships with 6.8) and Landlock is enabled (`dmesg | grep -i landlock`), which is required by `vault/parser_sandbox.py`.
3. Harden SSH (`/etc/ssh/sshd_config.d/ssdc.conf`):
   ```text
   PermitRootLogin no
   PubkeyAuthentication yes
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   ```
   Verify with `sudo sshd -t`, reload `sshd`, and test key login in a second terminal before closing your current session.
4. Configure the firewall to allow only **TCP 80/443** (or no inbound web ports if using Cloudflare Tunnel) and **TCP 22** from approved operator IPs. Never expose ports `5432`, `3310`, or `8000`.
5. If deploying on a physical office server, disable sleep/suspend:
   ```bash
   sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
   ```

### Step 3.2: Configure Production Google Cloud OAuth Client

1. Open [Google Cloud Console](https://console.cloud.google.com/) and create a dedicated production project for SSDC.
2. Enable the **Google Drive API**.
3. Under **Google Auth Platform**:
   - Configure Branding and set Audience to **External** (or Internal if using Google Workspace).
   - Add **only** the scope `https://www.googleapis.com/auth/drive.file`.
   - **Important:** Publish the OAuth consent screen out of "Testing" status (or complete any required verification) so refresh tokens do not expire every 7 days.
4. Under **Clients**, create a **Web application** client:
   - Authorized redirect URI (exact match, including trailing slash):
     ```text
     https://vault.YOUR-DOMAIN.org/storage/google/callback/
     ```
5. Download the Client ID and Client Secret to place in `/srv/ssdc/secrets/` in Step 4.2 below.

---

## Phase 4: Step-by-Step Production Deployment

Choose **one** of the deployment stacks below (`compose.prod.yaml` is the standard self-hosted stack; `compose.pilot.yaml` is for remote Supabase PostgreSQL; `compose.oracle.yaml` is for Oracle ARM64 without ClamAV). The steps below use `compose.prod.yaml`.

### Step 4.1: Clone Release Repository onto the Host

```bash
sudo install -d -m 0755 -o root -g root /srv/ssdc
sudo git clone <YOUR_REPO_URL> /srv/ssdc/app
cd /srv/ssdc/app
sudo chown -R root:root /srv/ssdc/app
```

### Step 4.2: Generate Production Secrets & Set Reader Groups

```bash
# 1. Create private directories
sudo install -d -m 0700 /srv/ssdc/secrets
sudo install -d -m 0700 /secure/ssdc-recovery
sudo install -d -m 0700 /backups

# 2. Generate unique cryptographic keys and Linux GIDs (11001, 11002, 11003)
sudo python3 /srv/ssdc/app/scripts/generate_secrets.py \
  --linux \
  --directory /srv/ssdc/secrets \
  --recovery-directory /secure/ssdc-recovery

# 3. Write your Google OAuth Client ID and Secret without trailing newlines
sudo sh -c 'printf "%s" "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com" > /srv/ssdc/secrets/google-client-id'
sudo sh -c 'printf "%s" "YOUR_GOOGLE_CLIENT_SECRET" > /srv/ssdc/secrets/google-client-secret'

# 4. Lock permissions (root:11001, mode 0640) on imported Google files
sudo python3 /srv/ssdc/app/scripts/generate_secrets.py \
  --linux --permissions-only \
  --directory /srv/ssdc/secrets
```

> **CRITICAL:** Copy `/secure/ssdc-recovery/backup-key`, `/srv/ssdc/secrets/mfa-key`, `/srv/ssdc/secrets/django-key`, and `/srv/ssdc/secrets/google-credential-key` to an encrypted offline/offsite custodian location now. Losing `mfa-key` or `google-credential-key` makes stored TOTP seeds and Drive tokens unrecoverable.

### Step 4.3: Issue and Install the TLS Certificate

Ensure your DNS `A` record for `vault.YOUR-DOMAIN.org` points to the server's public IP and port 80 is reachable:

```bash
sudo install -d -m 0755 /srv/ssdc/acme
sudo install -d -m 0700 /srv/ssdc/tls

sudo certbot certonly --standalone --preferred-challenges http \
  --cert-name vault.YOUR-DOMAIN.org \
  -d vault.YOUR-DOMAIN.org \
  --email operator@YOUR-DOMAIN.org \
  --agree-tos --non-interactive

sudo python3 /srv/ssdc/app/scripts/install_tls.py \
  --hostname vault.YOUR-DOMAIN.org \
  --lineage /etc/letsencrypt/live/vault.YOUR-DOMAIN.org \
  --tls-directory /srv/ssdc/tls
```

### Step 4.4: Create `/srv/ssdc/.env.production`

```bash
sudo cp /srv/ssdc/app/deploy/production.env.example /srv/ssdc/.env.production
sudo chmod 0600 /srv/ssdc/.env.production
```

Edit `/srv/ssdc/.env.production` and set your canonical domain (`vault.YOUR-DOMAIN.org`):

```dotenv
APP_IMAGE=ssdc-app:release-2026-10-18
DB_IMAGE=ssdc-db:release-2026-10-18
SCANNER_IMAGE=ssdc-scanner:release-2026-10-18
PROXY_IMAGE=ssdc-proxy:release-2026-10-18
POSTGRES_DB=ssdc
POSTGRES_USER=ssdc_bootstrap
DB_BOOTSTRAP_PASSWORD_FILE=/srv/ssdc/secrets/db-bootstrap-password
DB_MIGRATION_PASSWORD_FILE=/srv/ssdc/secrets/db-migration-password
DB_PASSWORD_FILE=/srv/ssdc/secrets/db-password
DJANGO_KEY_FILE=/srv/ssdc/secrets/django-key
MFA_KEY_FILE=/srv/ssdc/secrets/mfa-key
GOOGLE_DRIVE_CLIENT_ID_FILE=/srv/ssdc/secrets/google-client-id
GOOGLE_DRIVE_CLIENT_SECRET_FILE=/srv/ssdc/secrets/google-client-secret
GOOGLE_DRIVE_CREDENTIAL_KEY_FILE=/srv/ssdc/secrets/google-credential-key
GOOGLE_DRIVE_REDIRECT_URI=https://vault.YOUR-DOMAIN.org/storage/google/callback/
ALLOWED_HOSTS=vault.YOUR-DOMAIN.org
HEALTHCHECK_HOST=vault.YOUR-DOMAIN.org
CSRF_TRUSTED_ORIGINS=https://vault.YOUR-DOMAIN.org
TLS_CERT_FILE=/srv/ssdc/tls/cert.pem
TLS_KEY_FILE=/srv/ssdc/tls/key.pem
TLS_DIRECTORY=/srv/ssdc/tls
ACME_WEBROOT=/srv/ssdc/acme
PORTAL_HOST=vault.YOUR-DOMAIN.org
HTTPS_PORT=443
MFA_ALL_STAFF=0
```

### Step 4.5: Build Images, Initialize Roles, Migrate, and Start Services

```bash
cd /srv/ssdc/app

# Define helper alias for production compose with ACME webroot overlay
alias dcp='sudo docker compose --env-file /srv/ssdc/.env.production -f compose.prod.yaml -f deploy/compose.acme.yaml'

# 1. Validate resolved Compose configuration
dcp --profile operations config --quiet

# 2. Build pinned production images
dcp --profile operations build --pull --no-cache

# 3. Verify Linux secret permissions with the built release images
sudo python3 scripts/check_linux_secrets.py \
  --image ssdc-app:release-2026-10-18 \
  --db-image ssdc-db:release-2026-10-18

# 4. Start PostgreSQL and ClamAV first (ClamAV will download signatures)
dcp up -d db clamav

# 5. Run database migrations using the ssdc_migrator identity
dcp run --rm --no-deps migrate

# 6. Apply least-privilege grants to ssdc_runtime (audit_event is insert/read-only)
dcp run --rm --no-deps migrate python manage.py configure_runtime_role

# 7. Verify production deployment settings (expect 0 errors; only W021 HSTS preload notice)
dcp run --rm --no-deps app python manage.py check --deploy

# 8. Create the initial SSDC portal administrator account
dcp run --rm --no-deps app python manage.py createsuperuser

# 9. Start the application and Nginx HTTPS reverse proxy
dcp up -d --wait app proxy

# 10. Run ClamAV INSTREAM self-test (clean + EICAR check)
dcp exec app python manage.py scanner_selftest
```

---

## Phase 5: Post-Deployment Setup, Timers & Backup Drill

### Step 5.1: Enroll Admin MFA and Authorize Google Drive

1. Open `https://vault.YOUR-DOMAIN.org/accounts/login/` in your browser.
2. Sign in with the superuser account created in Step 4.5.
3. Enroll your TOTP authenticator app and **save the 8 one-use recovery codes** offline.
4. Navigate to **Document storage** (`https://vault.YOUR-DOMAIN.org/storage/google/`):
   - Click **Connect / reconnect Google Drive** and authorize the storage owner's Google account.
   - After returning to the portal, click **Prepare / verify private folder** to create the private `SSDC Private Documents` folder in Google Drive.
5. Upload a synthetic test PDF and test PNG into a test folder, verify the preview and byte-range pagination work, and then run:
   ```bash
   dcp exec app python manage.py operations_check
   dcp exec app python manage.py verify_storage
   ```

### Step 5.2: Enable Automated Systemd Timers (Cert Renewal & Maintenance)

```bash
# 1. Create the host renewal environment file
sudo sh -c 'printf "SSDC_PORTAL_HOST=vault.YOUR-DOMAIN.org\n" > /etc/ssdc-hosting.conf'
sudo chmod 0600 /etc/ssdc-hosting.conf

# 2. Install systemd services and timers
sudo install -m 0644 /srv/ssdc/app/deploy/systemd/ssdc-cert-renew.service /etc/systemd/system/
sudo install -m 0644 /srv/ssdc/app/deploy/systemd/ssdc-cert-renew.timer /etc/systemd/system/
sudo install -m 0644 /srv/ssdc/app/deploy/systemd/ssdc-operations.service /etc/systemd/system/
sudo install -m 0644 /srv/ssdc/app/deploy/systemd/ssdc-operations.timer /etc/systemd/system/
sudo systemctl daemon-reload

# 3. Test certificate renewal dry-run and proxy reload hook
sudo certbot renew --cert-name vault.YOUR-DOMAIN.org --webroot --webroot-path /srv/ssdc/acme --dry-run
sudo python3 /srv/ssdc/app/scripts/install_tls.py \
  --hostname vault.YOUR-DOMAIN.org \
  --lineage /etc/letsencrypt/live/vault.YOUR-DOMAIN.org \
  --reload-proxy

# 4. Enable and start both timers
sudo systemctl enable --now ssdc-cert-renew.timer ssdc-operations.timer
sudo systemctl start ssdc-operations.service
sudo systemctl list-timers ssdc-*
```

### Step 5.3: Execute Your First Paired Backup & Restore Drill

Before uploading real organizational records, run a paired encrypted backup (which captures PostgreSQL + local files + Google Drive blobs) and verify it with a non-destructive restore drill:

```bash
# 1. Pause the 5-minute maintenance timer during the snapshot window
sudo systemctl stop ssdc-operations.timer

# 2. Create an encrypted paired backup
sudo python3 /srv/ssdc/app/scripts/backup.py backup \
  --compose /srv/ssdc/app/compose.prod.yaml \
  --compose /srv/ssdc/app/deploy/compose.acme.yaml \
  --env-file /srv/ssdc/.env.production \
  --key-file /secure/ssdc-recovery/backup-key \
  --archive /backups/ssdc-initial-$(date -u +%Y%m%dT%H%M%SZ).ssdcbackup

# 3. Run the non-destructive restore drill (restores to a temporary DB and verifies all SHA-256 hashes)
sudo python3 /srv/ssdc/app/scripts/backup.py drill \
  --compose /srv/ssdc/app/compose.prod.yaml \
  --compose /srv/ssdc/app/deploy/compose.acme.yaml \
  --env-file /srv/ssdc/.env.production \
  --key-file /secure/ssdc-recovery/backup-key \
  --archive /backups/ssdc-initial-*.ssdcbackup

# 4. Re-enable the maintenance timer
sudo systemctl start ssdc-operations.timer
```

---

## Final Go-Live Sign-Off Checklist

- [ ] `deploy/Dockerfile.db` un-ignored in `.gitignore` and committed to Git.
- [ ] `clamav` memory limit raised to `4g` in `compose.prod.yaml`.
- [ ] `scripts/release_manifest.py` updated to iterate over configured services.
- [ ] All backend, Playwright UI, Linux TLS, Linux parser sandbox, Linux secret group, and DB role tests pass (`0` failures).
- [ ] Only ports `80`, `443`, and restricted operator `22` are reachable (`ss -tulpn` / external `nmap` scan shows `5432`, `3310`, and `8000` closed).
- [ ] `https://vault.YOUR-DOMAIN.org/live/` and `/health/` return HTTP `200`.
- [ ] Google OAuth consent screen published (not in 7-day Testing expiry mode) and private Drive folder verified.
- [ ] Recovery keys (`backup-key`, `mfa-key`, `django-key`, `google-credential-key`) backed up offline in a separate physical/cloud location from the server.
- [ ] First `.ssdcbackup` archive created, verified with `scripts/backup.py drill`, and copied offsite.