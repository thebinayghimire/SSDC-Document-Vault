# Release preparation — 28 October 2026

The release candidate passes local application, container, HTTPS and recovery checks.
The existing public service is https://ssdc-document-vault.onrender.com. Its current
login response lacks HSTS and sets a non-Secure CSRF cookie; changing the hosted
configuration still requires the Render account connection. No live configuration,
production database, Google account or public deployment was changed in this pass.

## Changes

- Management supports scoped document/folder search, lifecycle and folder filters,
  stable sorting and pagination that retains filters. Rejected uploads and pending
  replacements have clearer status labels.
- Managers can retry quarantined checks from version history. The action requires
  POST, CSRF, recent authentication and current management access, and uses the
  existing exclusive scan/publication protocol.
- Multipart intake bounds file bytes before Django's storage handlers. Oversized
  bodies/files and multiple files per request receive HTTP 413 before a view can
  accept a partial submission. Batch import still sends one request per file.
- Valid uploads work on macOS again. The parser retains Linux memory limits and
  production Landlock/seccomp isolation without applying unsupported macOS limits.
- Production trusts exact hosts, including the exact Render hostname; the shared
  `.onrender.com` suffix is no longer automatically trusted. Explicit production
  and test environments do not read local dotenv files.
- Hosted database URLs use certificate/hostname verification, bounded connection
  lifetimes and session-lock safeguards. The current certifi bundle is the default
  for public CAs; unsupported transaction-pooler endpoints are rejected.
- Both `SCAN_MODE=disabled` and `ENABLE_CLAMAV=false` require explicit
  `ACCEPT_NO_MALWARE_SCANNING=1` in production, including Render.
- Render requires a valid, separate MFA Fernet key. Its build installs hashed
  dependencies and vendors PDF.js before collecting static files. Python/Node
  versions and Gunicorn binding/recycling are explicit.
- Administrator bootstrap creates and audits an account once. Redeploying cannot
  restore a disabled account, promote an existing account or overwrite its
  password/details. Creation rolls back if its audit write fails.
- Readiness includes application tables and known Drive setup/reconnect failures.
  Previews honor matching `If-Range` ETags and handle local storage I/O failures.
- Pillow, pypdf and certifi were upgraded and lockfiles regenerated. All four
  container bases were refreshed and pinned by digest. The application, database
  and scanner now use patched Alpine packages, with native
  amd64/arm64 images. Scanner UID/GID 100:101 and database UID/GID 999:999 are
  preserved. Existing database volumes require logical migration; a startup guard
  prevents accidental reuse under a different C library/locale implementation.
- The disposable test runner works without a custom prebuilt database image and
  clears inherited deployment credentials. CI permissions/job bounds are explicit.
  Browser/SQL workflow checks match the public homepage.
- Render automatically selects production defaults and refuses explicit development
  or test mode. The read-only hosted release check detects missing HSTS, non-Secure
  CSRF cookies, readiness failures and unauthenticated management access.
- A repeatable rehearsal creates random isolated stacks, verifies real HTTPS/MFA/
  ClamAV/PDF access, creates an encrypted paired backup, and restores it into a
  second empty stack. A second rehearsal verifies Debian-to-Alpine logical recovery.

## Current verification

All fixtures were synthetic. Host checks use Python 3.13.17, Node 24.22.1,
OpenSSL 3.5.9 and disposable PostgreSQL 17. The built app uses Python 3.13.18.
Container checks ran on Linux ARM64 through OrbStack.

| Check | Result | Evidence |
| --- | --- | --- |
| Full unit/integration/browser suite | **533 passed**, 3 subtests passed; no failures/skips | `artifacts/release-completion/full-suite.xml` |
| Runtime Python/npm audits | No known vulnerabilities in the prior dependency audit; no additional dependencies introduced | `artifacts/production-dependency-audit-final.json` |
| Ruff lint/format, whitespace | Passed | Terminal checks |
| Real Linux parser isolation | Passed | `artifacts/release-completion/linux-parser.log` |
| Secret reader groups | Passed | `artifacts/release-completion/linux-secrets.log` |
| Fresh schema and runtime SQL privileges | Passed | `artifacts/release-completion/database-roles.log` |
| Production HTTPS, MFA, scanned upload, PDF/ranges | Passed in an isolated localhost TLS fixture | `artifacts/rehearsal-b7175b01a56a/result.json` and `rehearsal.log` |
| Encrypted paired backup and full recovery | Passed; file hashes, MFA seeds and restored MFA/PDF access verified | Same rehearsal |
| Debian-to-Alpine logical database recovery | Passed using separate source/recovery volumes | `artifacts/rehearsal-860f9097ecb2/result.json` and `rehearsal.log` |
| Public Render HTTPS | TLS connection and public endpoints respond; production cookie/HSTS checks **fail** | `artifacts/release-completion/live-render-warm-probe.json`, `hosted-release-check.json` |

The production fixture uses a self-signed localhost certificate; it does not
establish public certificate renewal, live Drive access or production-host capacity.
The full recovery check includes an encrypted dump/storage pair, a separate empty
PostgreSQL/private-storage destination, migration/runtime grants, file hash checks,
MFA seed validation, session revocation and restored MFA/PDF/range/logout checks.
Existing application databases/volumes were not changed.

## Container advisory gate

The previous Debian-based candidates had unresolved OS findings. The patched
release candidates now report **zero HIGH or CRITICAL findings in all four
images**, without ignoring unfixed entries or creating a VEX exception. The unused
PostgreSQL root helper is removed from the final filesystem and its image layers.

| Image | Critical | High | Report |
| --- | ---: | ---: | --- |
| Application | 0 | 0 | `artifacts/release-completion/app-final.json` |
| PostgreSQL | 0 | 0 | `artifacts/release-completion/db-final.json` |
| Scanner | 0 | 0 | `artifacts/release-completion/scanner-final.json` |
| Proxy | 0 | 0 | `artifacts/release-completion/proxy-final.json` |

The reports retain exact image identifiers and scanner metadata. Tags used locally
are `ssdc-vault-app:release-candidate`, `ssdc-postgres:release-candidate`,
`ssdc-clamav:release-candidate` and `ssdc-proxy:release-candidate`. The GitHub
container audit builds/scans all four images on pull requests and manual dispatch;
its hosted amd64 result is separate from these local ARM64 results.

## Apply to the existing Render service

The public URL is not dashboard authentication. Connect the Render account before
editing the service or triggering deployment. Preserve existing MFA/Drive keys:
changing an encryption key without a migration can prevent recovery/login.

1. Inspect the actual service environment, database connection, storage connection,
   deployment branch and plan through the authorized Render account.
2. Correct production mode (`APP_ENV=production`, `DEBUG=0`), exact allowed hosts,
   trusted CSRF origin, Google callback, PostgreSQL certificate verification and
   separately stored valid encryption keys. Validate any existing encrypted data
   before replacing an absent/default key. The Render runbook lists required values.
3. Determine the actual scanner configuration. Production bypass requires explicit
   acknowledgement; do not silently add it while fixing unrelated settings.
4. Take a current paired backup with the appropriate hosted maintenance procedure,
   then deploy the reviewed source and run real owner/admin/staff acceptance.
5. Run:

```sh
python scripts/check_hosted_release.py \
  --base-url https://ssdc-document-vault.onrender.com \
  --output artifacts/hosted-release-check.json
```

The current site fails this check for `hsts_missing` and `csrf_cookie_not_secure`;
intermittent liveness timeouts were also observed. A green `/health/` alone did not
establish production security. Review the actual host's capacity and availability
before describing it as a production service.

## Backup activation and operator work

The selected separate-provider destination is a private R2 Standard bucket; see
[offsite setup](OFFSITE_BACKUP.md). No new cloud resource or subscription has been
created. Offsite activation needs the owner's account, private credentials, key
custody, schedule/retention, alert ownership and budget. A local rehearsal is not
an offsite restore or a production-data backup.

No application migration is introduced by this pass. Existing Docker databases
need the explicit [database image transition](DATABASE_IMAGE_MIGRATION.md).
Keep the previous image/volume until the logical restore has been accepted.
For native Render hosting, follow [the Render runbook](RENDER_DEPLOYMENT.md).
Organizational/independent review gates remain recorded in
[DEPLOYMENT_FIXES.md](../DEPLOYMENT_FIXES.md).

## Reproduce locally

```sh
python scripts/run_checks.py --junit artifacts/release-tests.xml
ruff check .
ruff format --check .
python scripts/rehearse_release.py \
  --app-image ssdc-vault-app:release-candidate \
  --db-image ssdc-postgres:release-candidate \
  --scanner-image ssdc-clamav:release-candidate \
  --proxy-image ssdc-proxy:release-candidate
```

Build the four images from their checked-in Dockerfiles first. The rehearsal uses
loopback-only ports 8081/8443 and removes only its own randomly named resources.
Prior diagnostic artifacts, including failed baseline runs and superseded Debian
container scans, remain available; they are not passing release evidence.
