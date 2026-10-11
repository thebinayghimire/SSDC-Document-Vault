# Test plan

Drive tests in `tests/test_drive.py` use synthetic PDFs/images and a mocked HTTPS
Drive transport. They cover administrator/CSRF/PKCE/state/session/expiry restrictions,
encrypted refresh and revocation, missing refresh-token preservation, owner mismatch,
unauthorized staging/previews, revoked grants/disabled accounts, upload quarantine,
bounded retries, quota/missing-file errors, uncertain completion and durable ID reuse,
encrypted cross-attempt resumable sessions and expired-session restart,
publication rollback, exact byte ranges/HEAD, unsafe upstream full responses, private
sharing checks, credential redaction, protected cleanup, migration and backup export.
These tests cannot verify actual Google consent, personal storage accounting, live
Drive latency/rate limits, domain configuration or deployed proxy logs. Perform the
manual synthetic smoke checks in `GOOGLE_DRIVE_SETUP.md` after connecting privately.

Run unit/integration tests on a dedicated PostgreSQL test database using only
synthetic PDFs and images. Verify custom identity/MFA, expiry/revocation, inherited
and explicit ACLs, policy changes, unauthorized GET/HEAD/range/thumbnail requests,
manager scope, upload validation/quota/scanner failure, lifecycle and audit events.
Enforce CSRF using a client configured to perform actual CSRF checks.

Scan regression coverage is in `tests/test_scan_processing.py`: stale snapshots
and late outcomes, one upload against two simultaneous retry commands, independent
versions scanning concurrently, nested attempts, interrupted/disconnected owners,
commit/rollback and audit failures, interrupted previews, and removed versions.
Use separate PostgreSQL connections for actual competing workers. Assert that
published originals/previews and audit results survive stale attempts, genuine
malware is rejected, and unavailable scans remain quarantined for retry.

Audit failure coverage is in `tests/test_audit_atomicity.py`, using real commits
against disposable PostgreSQL. Fail event storage at initial and later batch
writes; verify account security state, permissions, document metadata/lifecycle,
version restoration, upload reservation, and scan outcomes roll back. Cover
password-hash upgrades, password administration and cancelled submissions,
sign-in/enrollment/identity confirmation, recovery codes and authenticator replay
counters. Assert both portal events and Django deletion history follow successful
or rolled-back administrative batches. For external file cleanup, verify committed
intent precedes deletion, failed initial recording preserves files, interrupted
completion retains intent, and later per-document purge failures preserve earlier
completed results. Inject filesystem failures as well as event-store failures.

Browser tests use Playwright Chromium against a disposable seeded environment:
login, folder navigation, search, list/gallery, PDF page render/zoom, image preview,
watermark identity, absent print/download controls, logout and unauthorized access.
No production credentials or records. Add meaningful regression tests as each
segment introduces behavior.

Checks: Django system/deployment checks, migration consistency, Ruff formatting
and linting, pip-audit, npm audit, container build/start/health, PostgreSQL migration
and restart, and synthetic backup/restore drill. Report exact results and any gaps.
Separate automated self-review from independent penetration testing.

F06 Linux permission regression: run `python scripts/check_linux_secrets.py`
after building the local app/DB images, or pass `--image` and `--db-image` with the
release references. This generates synthetic secrets in disposable Linux volumes
using the current generator and its documented permissions-only import procedure.
It verifies existing directory modes, root ownership and reader groups, individual
secret-file binds with read-only roots/dropped capabilities, application/migration
read access and forbidden-secret denial, actual database-image UID access, unrelated
user denial, and backup-key exclusion. It never reads the workspace's secrets.
Run `python scripts/run_checks.py --junit artifacts/f06-config.xml tests/test_deployment_configuration.py`
for the five configuration/generation checks using a disposable PostgreSQL container.
Neither check validates the final host's user-namespace mapping or SELinux policy.

F07 isolation: `python scripts/check_smoke_isolation.py` resolves production and
smoke configurations under randomly named disposable projects, starts both DB
services, writes a synthetic smoke table, then tears down the smoke volume. It
asserts the other DB's container ID, start time, SQL and filesystem sentinels remain
unchanged. It uses synthetic credentials, loads no deployment environment file,
starts no app/proxy/scanner, and removes only its own projects. The configuration
suite additionally verifies the standard production/smoke names differ and the
smoke tool's actual guard rejects production/shared/external resources before writes.

F08 SQL role checks: `python scripts/check_database_roles.py` initializes a fresh
disposable PostgreSQL container, migrates with `ssdc_migrator`, and applies runtime
grants. Deliberately grant membership in the schema-owner role and transfer audit
table ownership to the runtime role; grant configuration must refuse both. Restore
the fixtures and grants, then upload/audit, authenticate staff, view the library and
document, request a versioned range, sign out, and complete administrator TOTP/MFA
under `ssdc_runtime`. Direct SQL must deny audit update/delete/truncate, schema
creation, privileged-role creation and migration-history tampering. Confirm absent
privileged role attributes, memberships and database/schema/table ownership.
These use development scanning and non-manifest static serving, not production
ClamAV/TLS/assets; no existing deployment database is changed.
