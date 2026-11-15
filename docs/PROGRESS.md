# Build progress - 7 October 2026

Current results and remaining release gates from 28 October 2026 are in
[RELEASE_READINESS.md](RELEASE_READINESS.md). The entries below preserve earlier
verification history.

## Google Drive primary storage integration

Implemented owner-only offline OAuth with `drive.file`, administrator/CSRF/state/
PKCE controls, separate-key encrypted persistent credentials, serialized refresh
and reconnect status. New versions select Drive while existing filesystem versions
retain their provider. Originals and generated image previews use durable reserved
Drive IDs and resumable uploads before atomic publication. Protected portal UUID
endpoints stream content and exact ranges; Drive IDs/credentials/download URLs are
not exposed to staff. Permission revocation, disabled accounts, no-store headers,
watermarks and the existing parser/scanner limits remain in place.

Added provider-aware integrity checks/purge/orphan cleanup, explicit legacy-storage
migration, Drive-inclusive encrypted paired backup export and filesystem recovery.
Architecture/security/deployment/configuration and owner setup instructions are
updated. No Google Console project, owner consent, production deployment, live
Drive upload, real-document migration or real-data backup/restore has been performed.
The running application/database have not received this code or migration 0005.
Repository testing uses disposable PostgreSQL databases and synthetic documents.
Verification completed on 2026-10-07:

- Full PostgreSQL regression run: **278 passed** in 446.23 seconds.
- Subsequent affected-feature run (Drive/OAuth, vault permissions/viewer, mutation
  authorization, scan processing and operations): **141 passed** in 171.99 seconds.
- Final Drive/OAuth run after adding encrypted persistent resumable sessions and
  expired-session restart coverage: **36 passed** in 36.24 seconds. This includes
  the installed OAuth library's exact redirect/PKCE token exchange with mocked HTTP.
- Django system check and migration consistency: passed; only new migration 0005
  is required, and it was applied only in disposable test databases.
- Ruff lint/format and Git whitespace checks: passed (88 Python files formatted).
- Runtime pinned dependency audit: no known vulnerabilities found.
- Production Compose configuration validated using placeholder paths; secret-
  configured DEBUG suppression also verified using synthetic values.

The full run preceded the final resumable-session addition; the final Drive run
verifies that addition and the resulting fresh migration schema. Earlier runs
encountered stale modules from edits during execution, a concurrent test-database
setup collision, and a parser timeout under concurrent host load; fresh completed
runs above supersede those results. No parser timeouts/security limits were weakened.
Live Google consent/quota/latency, real-data migration, production image deployment,
and an actual Drive-inclusive encrypted backup/restore drill remain unverified.
Uploads remain synchronous. Repeated HTTP form submissions create new versions;
retries of a persisted storage operation reuse its reserved Drive ID and session.
Existing release findings and organizational/security approval gates still apply.

Local portal implementation is available at http://127.0.0.1:8080. It contains
only two synthetic sample documents. Random demo credentials are in ignored
`artifacts/demo-credentials.json`; they are not committed. Docker engine verified.

## Segment status

| Segment | Status and deliverables |
|---|---|
| 00 Specification | Product, architecture, threat model and acceptance mapping written; organizational decisions explicitly unresolved |
| 01 Foundation | Django config, custom-user-first migrations, PostgreSQL, pinned dependencies, Docker/Nginx, health/logging and README |
| 02 Identity | Staff IDs, roles, password change/admin recovery, privileged TOTP, recovery codes/replay checks, sessions/revocation and shared rates |
| 03 Storage | Generated private paths, signature/structure validation, bounded isolated parser, ClamAV quarantine/retry, original+preview quota, cleanup commands |
| 04 Library | Responsive list/gallery, folders, authorized search/type/sort/pagination, safe image thumbnails, empty states and escaped metadata |
| 05 Viewer | Self-hosted pinned PDF.js, PDF page/range/image previews, zoom/fit, staff watermarks, removed ordinary controls and no-store |
| 06 Authorization | Shared current policy, folder/document overrides, GET/HEAD/range/thumbnail checks, destination scope and adversarial tests |
| 07 Administration | Accounts/grants/audit UI, session/MFA reset, version restore, archive/trash/restore, dry-run purge with explicit policy reference |
| 08 Hardening | Secure production config, CSP/HTTPS/cookies, non-root app/DB, bounded containers, image remediation; acceptance BLOCKED by remaining advisories |
| 09 Verification | Backend/browser/security/operations checks executed; exact evidence below; no penetration-test claim |
| 10 Deployment | Separate production Compose and operator docs, TLS local smoke, encrypted paired backup and restore drill; public deployment NOT performed |
| 11 Review | Automated self-review written in SECURITY_REVIEW.md; independent review and organizational release approval NOT performed |

## Actual verification

- F09 full Windows/PostgreSQL suite: all 247 tests passed (243 backend and four
  browser tests) in an isolated frozen source copy, including all 52 audit checks.
  Results: `artifacts/f09-full-suite.xml`; source hashes and the preserved copy are
  in `artifacts/f09-verification-manifest.json` and `f09-verification-copy/`.
  Filesystem storage was used; this does not verify later concurrent storage
  edits or live Google Drive behavior. Snapshot Django system/migration checks
  and Ruff lint passed, plus formatting of seven F09-related files. Current F09
  files passed lint and `git diff --check`. Warnings concerned the copy's
  uncollected `staticfiles` directory; its development browser checks passed.
- F09 audit regression suite: all 52 new checks passed against the shared project
  with synthetic fixtures, filesystem storage, and disposable PostgreSQL. Covers
  failed event writes across account/password/MFA, grant/folder administration,
  document lifecycle/metadata, uploads, scanning and version restoration; includes
  later failures in administrative batches and both deletion histories. File cleanup
  verifies durable intent, failed scheduling, filesystem/completion failures, and
  partial per-document purge. Results: `artifacts/f09-audit-final.xml`.
- F09 baseline: nine checks failed before remediation. An initial focused run
  passed 106 checks and failed two new checks due to an incorrect reauthentication
  test URL, subsequently corrected. A later run during separate storage changes
  encountered the new storage column before its migration was available; those
  errors were resolved for the final audit run after that session added migration
  0005. Results: `artifacts/f09-before.xml`, `artifacts/f09-focused.xml`, and
  `artifacts/f09-audit-interrupted.xml`. The successful full run used an isolated
  frozen copy to avoid concurrent edits changing the running tests.
- Earlier Windows/PostgreSQL project suite after F05 remediation: all 195
  tests passed (191 backend and four browser tests). This includes eight F01
  document-edit regressions, 18 F02 account-edit checks, and 32 F03 authentication
  checks with actual overlapping requests, simultaneous security changes/MFA
  verification, and PostgreSQL lock checks through sign-in/identity-confirmation
  completion, plus 35 F04 mutation-authorization checks covering changes during
  validation/scanning, inherited and explicit grants, overlapping revocations,
  and queued writes waiting on PostgreSQL, plus 21 F05 scan-processing checks for
  concurrent commands/uploads, stale/late outcomes, interrupted work, previews,
  and transaction/audit failures. Results: `artifacts/f05-full-suite.xml`.
- F05 baseline: 10 regression checks failed before remediation. All 106 focused
  tests passed after the fix; the full run adds a late permission-denial check.
  Results: `artifacts/f05-before.xml` and `artifacts/f05-focused.xml`.
- Earlier F04 suite: all 174 tests passed. Results: `artifacts/f04-full-suite.xml`.
- F04 migration: fresh installation, reversal, and reapplication passed on a
  disposable PostgreSQL database, verifying all four policy guards and their
  function. Results: `artifacts/f04-migrations.log`. An initial focused run
  recorded one preview failure from a missing import; the import was restored
  before the successful final full run. Results: `artifacts/f04-focused.xml`.
- Earlier F03 suite: all 139 tests passed. Results: `artifacts/f03-final-suite.xml`.
- Earlier F02 suite: all 107 tests passed. Results: `artifacts/f02-current-suite.xml`.
  Its initial broad run captured two browser failures while interface files were
  changing; both passed on the F02 rerun. Results: `artifacts/f02-full-suite.xml`.
- Previous Linux-container/PostgreSQL suite: all 77 tests passed as the non-root app
  user, including isolated parser validation with Linux resource limits.
- Playwright: login, ACL-filtered library, search, gallery, rendered PDF pages/zoom,
  images, watermark, no ordinary print/download controls, mobile layout, logout,
  cross-user denial passed. Screenshots saved in ignored `artifacts/`.
- Local production Compose/TLS: health/login/logout, Secure/HttpOnly/Strict
  session cookies, secure CSRF cookie, HSTS/CSP/framing and HTTP redirect passed.
- Real ClamAV: clean fixture accepted; harmless EICAR test detected. Two sample
  documents are ready with `clean` scan status. Storage hash verification passed.
- Encrypted paired backup and temporary PostgreSQL restore drill passed, including
  a final audited backup/recovery cycle; both original hashes/sizes and thumbnail
  presence were verified. Live documents were unchanged.
- Fresh non-root PostgreSQL volume initialization and all application migrations
  passed in a disposable Compose project.
- Django system check, migration consistency, Ruff lint/format and pip check passed.
- Python runtime pip-audit and npm audit found no known package vulnerabilities.
- Docker Scout after refreshed image remediation: app 0 critical/2 high; DB 0 critical/4 high;
  proxy 0 critical/0 high; scanner 0 critical/1 high. These findings remain open.
- Production deployment check: one unsuppressed HSTS preload warning (`security.W021`).

Initial failed checks were fixed and rerun: Docker credential PATH/network reachability,
development MFA key, CSRF port forwarding, mobile hidden-label overflow and a missing
test import. Supporting base images were remediated and rescanned. PostgreSQL's
local synthetic DB/template indexes and collation versions were refreshed after
the OS update. No failed check has been represented as passing.

## Operational decisions and remaining work

Private originals never share static paths. Default deny ACLs are current on each
request; already delivered content cannot be recalled. Recovery/retention policy,
domain/operator, offsite backup destination/key custody, monitoring alerts and
staff devices/permissions still require SSDC input. No automatic retention or
public hosting has been invented. No real documents or production credentials
have been committed or uploaded.

Release remains blocked by open findings in `../DEPLOYMENT_FIXES.md`, including
image advisories and pending independent/organizational review. F01–F09 are
closed: document edits preserve concurrent ACL/lifecycle/version changes and
recheck current scope; account edits preserve current security state and cannot
reverse session revocation or restore consumed MFA codes; pending sign-ins and
identity confirmation cannot adopt access revoked after password authentication.
Password verification, MFA completion/setup, and password changes coordinate
with account revocation, including automatic upgrades of older password hashes.
Vault writes also refresh the actor's active state, role, and authenticated account
version and recheck current source/destination policy inside their transaction.
Policy edits coordinate with those writes, including bulk grant changes and
folder/document restriction or relocation. Publication rechecks access after
scanning; an accepted original stays quarantined if access changed. Expensive
validation/scanning remain outside the short policy guard.
Scan processing is exclusive per version, with fresh status checks for every
outcome. Competing/stale attempts preserve published/rejected results; unrelated
versions can scan concurrently. Rejection and audit save together, with file
cleanup after commit. Rollback retains originals/previews, and retries rebuild
interrupted previews through complete temporary files and atomic replacement.
Security mutations and local events save together. Selected-user session/MFA
resets and administrative bulk deletion are all-or-nothing, including Django's
deletion history. Password administration records success only after a real save;
automatic password-hash upgrades are audited in the upgrade transaction.
File cleanup commits intent before deletion and records its outcome separately;
interrupted completion retains intent and raises an error. Physical purge is
partial across documents, preserving earlier completed results on a later failure.
All 247 frozen-copy project tests and 52 current-project audit checks passed;
system/migration and code-check scope is recorded above. This step did not update
the running development app or database; runtime application has not been verified.
F04 requires a rebuilt app and migration `vault.0004_serialize_policy_writes`;
stop old writers before applying it and restarting the rebuilt release, following
`DEPLOYMENT.md`. Only disposable databases received the migration in this step.
F05 and F09 add no further migration of their own; stop/drain older scan processors
before replacing the app. Separate storage work added migration 0005, which was
used only on disposable test databases in this remediation. Next in the agreed
closure sequence is F10, then F11–F17. All other findings remain open.
Deployment follows only after the remaining release gates are resolved.

F06 closed on 8 October 2026: Linux secrets use root-owned `0640` files and explicit
service reader groups; the backup key remains operator-only outside service mounts.
The generator now sets existing secret/recovery directories to `0700` too. The
stronger Linux fixture failed before that correction and passed afterwards with
individual secret binds, read-only roots, dropped capabilities, application and
migration identities, the actual database image's UID, unrelated-user denial, and
imported Google client files. Five deployment configuration/generation checks and
focused Ruff lint/format checks passed. Evidence: `artifacts/f06-before.log`,
`artifacts/f06-linux-secrets.log`, and `artifacts/f06-config.xml`; exact image IDs and
verification scope are in `../DEPLOYMENT_FIXES.md`. This used Docker's Linux engine
and disposable fixtures, without changing live secrets, rebuilding running services,
or migrating an application database. The final Linux host's user-namespace and
SELinux configuration still require verification under F16.

F07 closed on 8 October 2026: smoke uses its own project and refuses shared or
external resources before writing synthetic data. All 12 configuration/generation/
guard tests passed (`artifacts/f07-config.xml`). A new disposable coexistence check
confirmed smoke startup, writes and teardown preserve the other deployment's
container, start time, SQL and filesystem sentinels (`artifacts/f07-coexistence.log`).
It uses randomly named projects, synthetic credentials and no deployment env file.

F08 closed on 8 October 2026: bootstrap/operator, migration/schema-owner and runtime
SQL identities are separate. Runtime grants protect audit/migration history; grant
configuration rejects privileged role attributes, memberships and object ownership.
Fresh role/migration checks, runtime upload/audit, staff HTTP login/view/range/logout,
administrator password/TOTP/MFA and SQL denial checks passed
(`artifacts/f08-database-roles.log`). Initial extended checks needed grant reapplication
after a deliberate ownership-transfer fixture and non-manifest static serving; both
harness corrections preceded the successful rerun. All eight Python files touched
in this continuation passed Ruff lint/format checks; `git diff --check` passed.
These checks used development scanning/non-manifest static serving, not production
ClamAV/TLS/assets or live Google Drive. Existing databases, roles, secrets and running
services were preserved. Apply and verify the corrected production configuration
and grants on the final host before opening traffic; recovery and external deployment
gates remain open. Next is F10's image-advisory disposition.
