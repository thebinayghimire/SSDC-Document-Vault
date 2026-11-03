# SSDC Document Vault: fixes required before deployment

Current automated verification and container scan results are recorded in
[docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md), dated 28 October 2026.
Historical finding closure below does not replace that report or go-live review.

Reviewed **7 October 2026 (Asia/Kathmandu)**, against commit `8c7d9f3eac76da64508d6da0948d35a45e143345`.

**Release assessment: not ready for production.** The existing tests pass, but additional checks reproduced security and data-integrity defects that those tests do not cover. Fix the release blockers below before uploading confidential SSDC documents or opening the service to staff.

This report covers the primary project checkout: application code, authentication/MFA, permissions, storage and scanning, database models/migrations, management commands, templates/CSS/JavaScript, dependency manifests, Docker/Compose/Nginx, operator scripts, tests, and project documentation. The nested `.kilo` Git worktree is a duplicate checkout, not a separate release. Generated dependencies, collected static assets, local scan reports, and synthetic fixtures were inspected where relevant. Secret values and document contents are not included here.

## How to use this report

- **P1 — release blocker:** fix, or resolve the explicitly identified architecture/policy assessment, before production.
- **P2 — required readiness work:** close before normal staff use; an explicitly agreed deferral needs an owner and a concrete workaround.
- **P3 — follow-up improvement:** useful, but not itself a reason to block deployment.
- **Reproduced** means a synthetic check demonstrated the current behavior. **Source/configuration** means the finding follows from the implementation. **Validation/decision gap** means the work has not been established on the intended deployment environment; it does not claim a demonstrated exploit.

Checkboxes reflect the current closure status. The original review evidence below is retained as a baseline. Its reproduction probes deliberately assert unsafe behavior; they do **not** establish that a defect is fixed. Use the new regression tests listed in closure notes to verify each remediation.

## Closure progress

**F01 completed — 7 October 2026.** Document-detail and administration edits now lock and reload the current document and save only fields intentionally changed. Newer permissions, archive/deletion state, current version, and unchanged folder selections are preserved. Metadata writes recheck current document and destination access; the metadata change and its audit event commit together.

Verification: five regression checks failed on the original implementation. After the fix, all **85 backend tests passed**, including eight new tests in `tests/test_document_edits.py` and real overlapping PostgreSQL transactions involving administrator and manager actions. Django system/migration checks and Ruff lint/format checks passed. Evidence: `artifacts/f01-before.xml`, `f01-focused.xml`, and `f01-full-suite.xml`. No schema migration is needed. These are source changes; the running development container has not been rebuilt in this step.

**F02 completed — 7 October 2026.** Existing-account saves now lock the current account and write only intentionally edited fields. Authorization versions cannot be overwritten by an older saved account; security changes actually being saved increment the current version while holding that lock. Administration edits preserve concurrent password, role, disabled-account, and MFA changes. Password changes and MFA enrollment use explicitly scoped writes. Consumed recovery codes and authenticator steps stay consumed after profile edits, password changes, and MFA resets, including overlapping requests.

Verification: **12 regression checks failed** before remediation. After the fix, all **107 project tests passed** on Windows against a disposable PostgreSQL database: 103 backend tests and four browser tests from the current interface work. This includes 18 new checks in `tests/test_account_edits.py`, actual overlapping administrator requests, simultaneous password/role changes, and simultaneous recovery/TOTP verification. Django system/migration checks and Ruff lint/format checks passed. Evidence: `artifacts/f02-before.xml`, `f02-focused.xml`, and `f02-current-suite.xml`. An earlier broad run (`f02-full-suite.xml`) recorded two browser failures while interface files were changing; both passed on the latest-source rerun. No schema migration is needed. The running development container has not been rebuilt in this step.

**F03 completed — 7 October 2026.** Password verification, MFA verification/setup, and sign-in completion now coordinate on the current account lock. Pending challenges remain bound to the account version authenticated with the password; completion cannot adopt a later version after revocation. Account changes and expired attempts clear pending sign-in/setup data and require a fresh sign-in. Enrollment retains the lock through its intentional version increment and session creation; expiry at completion rolls back incomplete setup. Identity confirmation and password changes recheck the current session/account inside their transaction. Ordinary sign-in also locks before Django's password check, so an automatic upgrade of an older password hash cannot overwrite a concurrent password reset. A revocation after completion invalidates the established session on its next request.

Verification: **28 regression checks failed** on the F02 implementation before this fix. An additional password-hash-upgrade regression failed before its guard was added, then passed. The final Windows/disposable-PostgreSQL suite passed all **139 project tests** (135 backend and four browser tests), including 32 new checks in `tests/test_authentication_races.py`. Coverage includes authenticator/recovery challenges against all five revocation actions, actual overlapping requests, PostgreSQL lock checks through challenge/enrollment/identity-confirmation completion, staff sign-in, password changes, and expiry before and after verification. Django system/migration checks and Ruff lint/format checks passed. Evidence: `artifacts/f03-before.xml`, `f03-focused.xml`, `f03-hash-upgrade-before.xml`, `f03-hash-upgrade-after.xml`, and `f03-final-suite.xml`. The earlier full run (`f03-full-suite.xml`) passed 138 tests before the final password-hash-upgrade guard was added. No schema migration is needed. These remain source changes; the running development container has not been rebuilt in this step.

**F04 completed — 7 October 2026.** Vault mutations now refresh and lock the current actor, checking active state, management role, and the authenticated account version before saving. Document edits, uploads/replacements, archive/delete/restore, folder creation, and version restoration recheck the current source and destination policy inside their write transaction. Explicit document-only grants remain supported, alongside inherited folder grants, folder reparenting/restriction, and document moves/restriction.

A shared PostgreSQL transaction guard coordinates these checks with document/folder policy changes. Migration `vault.0004_serialize_policy_writes` installs statement-level guards on folders, documents, and both grant tables, covering ordinary ORM writes, bulk updates, and grant insertion/deletion. Administration saves/deletes refresh the administrator and use the same guard. Account security changes coordinate through the actor's row lock. The purge command acquires the policy guard before document locks to preserve the same lock order.

Revocation that commits before authorization prevents the waiting write. A write already authorized holds the guard through its short commit; a competing revocation waits and prevents subsequent writes. File inspection and antivirus scanning run outside the guard. Publication rechecks access after scanning, retaining the original in quarantine with an administrator-review note if access changed. Synchronous uploads retain their authenticated account version; operator retries require the uploader's current account and document permissions.

Verification: **31 regression checks failed** on the F03 implementation before remediation. The final Windows/disposable-PostgreSQL suite passed all **174 project tests** (170 backend and four browser tests), including 35 checks in `tests/test_mutation_authorization.py`. These cover changes during validation/scanning and initial lookup, actual overlapping writes and revocations, bulk grant downgrades, administrator grant deletion, and queued writes verified to be waiting on PostgreSQL before revocation commits. Django system/migration checks and Ruff lint/format checks passed. Fresh forward, reverse, and reapplied migration checks verified all four database guards and their function. Evidence: `artifacts/f04-before.xml`, `f04-full-suite.xml`, and `f04-migrations.log`. The initial focused run (`f04-focused.xml`) recorded one preview failure from a missing import; that was corrected before the successful final full run.

This step **requires migration 0004 and a rebuilt app**. This remediation migrated only disposable databases and did not rebuild the development app or migrate its database. Application of F04 to the running environment has not been verified. Stop older app processes and scan/purge jobs before applying this migration, then restart processes from the rebuilt release, as documented in `docs/DEPLOYMENT.md`. Capacity validation remains open under F12.

**F05 completed — 7 October 2026.** Upload processing and scan retries now share an exclusive, nonblocking claim for each version. A competing attempt returns the current status without parsing/scanning or changing files. Each attempt reloads the version before work, and all outcome paths lock and recheck current state before saving. Published/rejected outcomes are preserved, including a newer outcome committed after the initial lookup. Nested calls cannot reenter a claim on the same connection. Other versions can still scan concurrently, without keeping a policy lock or opening a long write transaction for parsing/scanning.

Rejection and its audit event commit together. Original/preview deletion is scheduled only for an accepted rejection and occurs after commit; audit failure or rollback preserves the files. Rejection also releases the preview reservation and cleans an interrupted preview associated with that version. Publication writes a complete temporary preview before atomic replacement, repairing incomplete previews left by interruptions and allowing retries after a rolled-back publication. Retry commands skip versions removed after their initial query. Claims are released on completion/error or when the owning PostgreSQL session ends; the current direct database connection is retained.

Verification: **10 regression checks failed** before remediation. All **106 focused tests passed** after the fix. The final Windows/disposable-PostgreSQL suite passed all **195 project tests** (191 backend and four browser tests), including 21 checks in `tests/test_scan_processing.py`. Coverage includes stale and late outcomes, one upload racing two actual retry commands on separate connections, concurrent scanning of different versions, nested calls, unexpected errors and database disconnection, rejection/publication rollback, audit failure, incomplete previews, staged-write failure, and removed versions. The full run also includes a late permission-denial outcome check added after the focused run. Django system/migration checks and Ruff lint/format checks passed. Evidence: `artifacts/f05-before.xml`, `f05-focused.xml`, and `f05-full-suite.xml`.

F05 adds **no new schema migration**; F04's migration requirement still applies. This step did not rebuild the running development app or migrate its database. Stop/drain older app processes and scan jobs before replacing them with this release; older processors do not use the new claim. Updated procedures and behavior are in `docs/DEPLOYMENT.md`, `docs/SECURITY.md`, and `docs/TEST_PLAN.md`.

**F09 completed — 7 October 2026.** Account administration now saves password resets and their portal/Django history together, recording success only after a valid password form actually saves. Selected-user session revocation and MFA reset lock accounts in ID order and commit the entire selection with its events; a later failure rolls back earlier selected users and their events. Administrative bulk deletion now includes Django's deletion history in the same guarded transaction as the selected rows and portal events. Automatic password-hash upgrades during sign-in also record an event in the transaction containing the upgrade, including before an MFA challenge.

Operator orphan cleanup commits a unique `started` checkpoint before deleting files, then records `success` or `failed`. Execution refuses an enclosing/manual transaction that would prevent that checkpoint from committing. Physical purge commits each document's deletion with a `scheduled` event, then records file-removal success/failure after commit. Filesystem operations cannot roll back: interrupted completion or a failed terminal audit write retains the initial record and the command fails. Purge is explicitly partial across documents; earlier completed documents remain deleted if a later document fails. Failed scheduling preserves the affected document and files. These mechanisms do not close the separate maintenance, retention-reference, or audit-detail findings.

All **52 new audit-atomicity tests passed** against the shared project using synthetic fixtures, filesystem storage, and a separate disposable PostgreSQL test database. Evidence: `artifacts/f09-audit-final.xml`. Nine initial regression checks failed before remediation. The first focused run passed 106 checks and failed two new reauthentication checks because their test URL was incorrect; the URL was corrected. A subsequent run during concurrent Google Drive storage development passed 27 checks but could not finish document checks because the new `storage_provider` column had no migration when the test database was created. That run is retained as `artifacts/f09-audit-interrupted.xml`. Full-suite verification uses an isolated frozen copy with the other session's subsequently available migration, filesystem storage, synthetic fixtures, and a disposable PostgreSQL database. Evidence includes `artifacts/f09-before.xml`, `f09-focused.xml`, `f09-full-suite.xml`, and the copy's SHA-256 manifest `f09-verification-manifest.json`; full-suite results apply to that copy, not later concurrent edits or live Google Drive behavior.

F09 introduces no schema migration of its own; F04's requirement still applies, and any migration from separate storage work must be handled with that release. This step has not rebuilt the running app or migrated its database. Release remains blocked by the remaining findings.

The final frozen-copy suite passed all **247 project tests** (243 backend and four browser tests), including all 52 audit checks, in 767.38 seconds. Snapshot Django system/migration checks and Ruff lint passed; all seven F09-related Python files passed formatting checks. The shared project's F09 files also passed lint and `git diff --check`. The full run reported warnings about the frozen copy's uncollected `staticfiles` directory; its browser checks passed using development static serving. This is not a production static-asset or live Google Drive deployment check. Operations, failure behavior, and test scope are documented in `docs/DEPLOYMENT.md`, `docs/SECURITY.md`, and `docs/TEST_PLAN.md`.

**F06 completed — 8 October 2026.** Linux secret generation assigns root-owned `0640` service files to numeric reader groups: 11001 for application secrets, 11002 for the bootstrap password, and 11003 for the migration password. Production Compose adds the corresponding supplementary groups and mounts files individually. The backup key remains `0600` outside service mounts. Imported Google client files use the same application-reader group through `--linux --permissions-only`. Generation now restricts existing as well as newly created secret/recovery directories to `0700`; the previous implementation left existing directories at their old mode.

Verification: the strengthened Linux fixture failed before the existing-directory correction (`artifacts/f06-before.log`), then passed with real individual bind mounts on Docker's Linux engine (`artifacts/f06-linux-secrets.log`). It verifies file owner/group/mode and directory mode, application and migration reader access, denial of bootstrap/migration secrets to the application identity, denial to an unrelated UID, imported Google client permissions, and exclusion of the backup key. Checks run with read-only container roots, all capabilities dropped, no-new-privileges, and no network. The actual database image's configured UID 999 also reads all three required DB secrets under those restrictions. Five deployment configuration/generation tests passed against the current checkout (`artifacts/f06-config.xml`); focused Ruff lint/format checks passed. App image used: `sha256:ae269997cf9a3b7ac03800d2c5b529832a3bf45c4cffb05914b96784d35c116e`; DB image: `sha256:6a2a471e9aee0c80a431dce7e88efb5c62905d273a4adcadaac9fd9b43743192`. The checker transfers the current generator into its disposable Linux fixture, so it exercises the updated source rather than an older image copy.

This closes the Linux ownership/group defect. No live secret values or permissions were changed, and no application database was migrated or running service rebuilt. The final host's rootless/user-namespace mapping and SELinux labeling remain deployment-specific checks under F16. The repeatable check accepts explicit app/DB release images; repeat it on the final host and release candidate as documented in `docs/DEPLOYMENT.md`.

**F07 completed — 8 October 2026.** The smoke override and synthetic browser tooling use the separate `ssdc-vault-smoke` project. Resolved volume/network names are checked before creating synthetic accounts or documents; shared/production names and external resources are refused. The guard is now a separately testable function used by the actual smoke script. Setup, migration, checks and cleanup commands in the runbook explicitly select the smoke project.

Verification: all **12 deployment configuration/generation/guard tests passed** (`artifacts/f07-config.xml`), including seven refusal cases for production project/resource names, external resources, and missing names. Production and smoke configuration resolve to disjoint persistent-volume and network names. `scripts/check_smoke_isolation.py` started two fresh databases using the production configuration and smoke override under randomly named disposable projects. Smoke creation, SQL writes and volume teardown preserved the other container ID, start time, SQL sentinel and filesystem sentinel (`artifacts/f07-coexistence.log`). The harness uses synthetic credentials, loads no deployment environment file, and cleans up only its own projects. All existing application/restore/smoke services were preserved. This is a coexistence check for isolation; it does not close the separate HTTPS/browser/scanner release gates.

**F08 completed — 8 October 2026.** Production PostgreSQL now has separate bootstrap/operator, schema-owner/migration, and application runtime credentials. Fresh initialization creates `ssdc_migrator` and `ssdc_runtime` without privileged role attributes. Compose's app uses only the runtime password; the migration service uses its separate password. `configure_runtime_role` assigns ordinary table/sequence access, read-only migration history and insert/read-only audit events. It now also refuses runtime membership in any other role and ownership of databases, schemas, relations/sequences or functions: removing explicit grants cannot remove an owner's authority. Existing-volume ownership transfer and grant reapplication are documented; backup/recovery tooling uses the DB service's operator identity.

Verification: a fresh disposable PostgreSQL instance initialized both roles, ran all current migrations as `ssdc_migrator`, and applied runtime grants. Deliberately introduced schema-owner membership and audit-table ownership were refused. After fixture cleanup and grant reapplication, `ssdc_runtime` completed a synthetic upload/audit, actual staff password login/library/document/versioned-range/logout requests, and administrator password/TOTP/MFA authentication. Direct SQL denied audit update/delete/truncate, schema creation, privileged-role creation and migration-history tampering. Role attributes, memberships and database/schema/relation ownership were checked (`artifacts/f08-database-roles.log`). The 12 deployment configuration/generation/guard tests passed, and all eight Python files touched in this continuation passed Ruff lint/format checks; `git diff --check` passed. An initial extended role run needed grant reapplication after its deliberate ownership-transfer fixture; the next run needed non-manifest static serving for its synthetic HTTP checks. Both harness corrections preceded the successful final run; initial results are retained in `artifacts/f08-initial-role-check.log` and `artifacts/f08-static-fixture-check.log`.

The HTTP checks use development scanning and non-manifest static serving. They do not establish production TLS/assets, live Google Drive, real scanner behavior or a fresh recovery drill. No existing deployment database/roles were changed, application migration added, or running services rebuilt. Apply the new identities/ownership/grants to the intended deployment with old writers stopped before claiming runtime enforcement there; F14/F16 and final release checks remain open.

**Next: F10**, then F11–F17, in the agreed closure order. F01–F09 are closed; all other findings remain open. Existing source changes for later findings are not closure evidence by themselves.

## Fresh verification

| Check | Result during this review |
|---|---|
| Existing backend suite | **77 passed**, Windows/Python 3.13.12 against a disposable PostgreSQL container; 178.35 seconds |
| Additional audit probes | **18 passed** as demonstrations of current defects/configuration gaps; saved in `artifacts/review_regressions.py`, with final results in `artifacts/review-probes.xml` |
| Isolated browser checks | **2 passed** using fresh synthetic accounts and a disposable database; basic login/library/PDF/image/mobile checks passed, and viewer error handling/mobile overflow defects were demonstrated |
| Existing `scripts/browser_check.py` | **Failed**: saved `demo.staff` credentials were rejected and navigation timed out; this existing script is not currently reproducible from its saved fixture |
| Django system check | Passed on host and running development container |
| Migration consistency | `makemigrations --check --dry-run`: no changes detected |
| Ruff lint / formatting | Passed: 66 files already formatted at the start of the review |
| Python dependency consistency | `pip check`: passed |
| Python runtime vulnerability audit | No known vulnerabilities reported by fresh `pip-audit` |
| npm production dependency audit | No known vulnerabilities reported by fresh `npm audit --omit=dev` |
| JavaScript syntax | `node --check` passed for viewer and PDF.js vendor script |
| Production settings check | Executed with the existing local smoke configuration: only `security.W021` (HSTS preload off) |
| Compose smoke configuration | Parsed successfully; also confirmed it currently resolves to the **production project/volume names**, see F07 |
| Private storage verification | Running development environment: 2 versions verified |
| Real antivirus self-test | Clean fixture accepted; harmless EICAR fixture detected |
| Operations command | Passed for the current development environment |
| Fresh container scans | App: **0 critical / 2 high**; PostgreSQL: **0 / 4**; proxy: **0 / 0**; scanner: **0 / 1**, critical/high filter only |
| Linux file permission check | App UID **10001** and database UID **999** could not read a synthetic root-owned `0600` secret file |

Evidence is in ignored `artifacts/review-*.xml`, `review-browser-result.json`, `review-python-audit.json`, `review-npm-audit.json`, and `review-*-scan.txt`. Docker Scout encountered Windows temporary-file cleanup locks; the PostgreSQL scan also initially hit its shared cache lock and was rerun sequentially. Final scan reports contain the findings above. Lower-severity findings were outside the selected scan filter.

The isolated browser run is not a fresh public HTTPS deployment test. This review did not run a new full Linux backend suite, perform a live disaster-recovery exercise, stress the service to failure, or test a real domain, production host, staff devices, or independent penetration-test scope. Earlier claims in `docs/PROGRESS.md` are historical evidence, not substitutes for these remaining checks.

## P1: confirmed code and deployment blockers

### [x] F01 — Metadata editing can undo concurrent permissions, deletion, archive, and version changes

**Evidence:** Reproduced. `vault/views.py:279-293`, `vault/forms.py:17-26`, `vault/models.py:52-76`.

`MetadataForm.save()` writes the whole previously loaded `Document`, even though the form edits only title and folder. In a simulated overlapping request, a title-only edit restored the previous active version and reset a concurrent `restricted=True`, archive, and soft deletion. This can republish content or reverse an administrator's restriction.

**Fix:** Lock and reload the document for the write, revalidate the permitted destination, and update only intended fields. Apply the same discipline to Django administration, which also saves loaded model instances. Keep permissions/lifecycle/version changes out of metadata writes.

**Acceptance:** Concurrent title edits cannot reset ACL mode, archive/deletion state, or active version. Add actual overlapping-transaction regression coverage, including admin versus manager changes.

### [x] F02 — Stale account saves can reverse session revocation and restore consumed MFA recovery codes

**Evidence:** Reproduced. `accounts/models.py:38-46`, `accounts/admin.py:63-103`, `accounts/mfa.py:27-48`.

A `User` loaded before a session-revocation action can later be saved with an ordinary profile edit and write the old `auth_version` back. A previously revoked session then works again. A stale full save also restored a consumed recovery code, allowing that supposedly one-use code to be accepted a second time. The same full-save pattern risks overwriting MFA replay counters, reset state, and other concurrent account changes.

**Fix:** Make authorization versions monotonic with atomic increments. Save only explicitly edited account fields; preserve current MFA/recovery fields during profile/admin edits. Coordinate security mutations with row locks and narrowly scoped writes, rather than comparing a fresh row and then writing an old full object.

**Acceptance:** Revocation cannot be reversed by concurrent profile edits. Consumed recovery codes and TOTP steps stay consumed across admin edits, password changes, resets, and simultaneous verification requests.

### [x] F03 — An MFA challenge can finish after its password authentication has been revoked

**Evidence:** Reproduced with an intervening password reset. `accounts/views.py:72-91`, `accounts/mfa.py:27-41`, `accounts/views.py:19-34`.

`pending_user()` checks `pending_auth_version` before verification. If the password is reset after that check, `verify()` checks active/MFA state but not the pending version. The view then refreshes the user and creates a session using the **new** authorization version. The password reset therefore fails to invalidate the pending authentication in that interleaving.

**Fix:** Bind MFA verification and login completion to the password-authenticated account version. Recheck it under the account lock before accepting the code and establishing the session. Audit the same race boundary in enrollment and reauthentication.

**Acceptance:** Password reset, role change, account disable, MFA reset, and explicit session revocation invalidate pending challenges, including changes between the initial lookup and successful verification.

### [x] F04 — Mutations do not recheck current scope inside the write transaction

**Evidence:** Upload grant revocation reproduced. `vault/views.py:228-257`, `vault/services.py:68-114`, `vault/views.py:279-359`, `vault/views.py:379-394`.

The upload view says “Recheck policy under a transaction,” but `upload_document()` performs no authorization check. A manager's grant was removed during validation and the upload still published. Metadata, lifecycle, folder creation, and version restoration also rely on a policy decision made before their write; locking a document later does not refresh the actor's authority or destination grants.

**Fix:** Enforce actor role/state and source/destination scope in the mutation service and write transaction. Coordinate ACL changes with those checks so concurrent revocation has a defined, enforceable effect. Remove the inaccurate comment after implementing the real control.

**Acceptance:** Revoke grants or move/restrict the target while validation or a write is waiting; the write must not proceed with stale authority. Cover document-only grants and inherited folder policies as well.

### [x] F05 — Concurrent scan retries can reject and delete a version another processor already published

**Evidence:** Reproduced with two snapshots of a quarantined version. `vault/services.py:19-65`, `vault/management/commands/retry_scans.py:13-18`.

The successful branch locks and rechecks status, but the `InvalidUpload` branch saves `REJECTED` and deletes the original without doing either. After one processor published a version, a second processor holding an old quarantined snapshot rejected it and deleted its file. Concurrent thumbnail writes can also race around the `exists()`/exclusive-create pair.

**Fix:** Introduce an exclusive processing claim or lock per version. Make success, unavailability, rejection, and file cleanup conditional on the current processing state. A stale worker must never overwrite a newer terminal result or delete its files. Make thumbnail creation idempotent.

**Acceptance:** Two concurrent retry commands, plus an upload processing the same version, cannot change READY back to REJECTED, remove a published original, or fail because both generated a thumbnail.

### [x] F06 — Linux secret file ownership is incompatible with the documented generation procedure

**Evidence:** Source/configuration plus Linux permission fixture. `scripts/generate_secrets.py:13-24`, `Dockerfile:10-17`, `deploy/Dockerfile.db:9`, `compose.prod.yaml:11-12,35-47,78-81`.

Generated secrets are `0600` files owned by the operator running the generator. The app runs as UID 10001; PostgreSQL runs as UID 999. A normal operator/root-owned file is unreadable to those identities. The app and database also share the database password file, so changing its owner to only one service is insufficient. Docker Desktop's Windows behavior does not establish Linux compatibility. File-backed Compose secrets retain bind-mount ownership; `uid`/`gid`/`mode` overrides cannot be relied on to remap them. [Docker Compose secret documentation](https://docs.docker.com/reference/compose-file/services/#secrets).

**Fix:** Specify and automate a Linux ownership/group/ACL arrangement that gives only the intended services read access. For example, use a dedicated secret-reader group, appropriate host group ownership/read permissions, and explicit supplementary service groups. Keep the backup key outside app/DB mounts. Include host security labeling where applicable.

**Acceptance:** Follow the documented setup on a fresh Linux host with the production users, capabilities, and read-only filesystem settings. Confirm both services can read their required secrets without making the files generally readable.

### [x] F07 — TLS smoke testing shares the production Compose project and persistent volumes

**Evidence:** Resolved Compose configuration. `compose.prod.yaml:1`, `deploy/compose.smoke.yaml:1-6`, `scripts/production_smoke.py:8-17`, `docs/DEPLOYMENT.md` local smoke commands.

The smoke override changes ports/image but does not change the project name. It resolves to `ssdc-vault-production`, with `ssdc-vault-production_db-data` and `ssdc-vault-production_private-data`. Contrary to the documentation's isolation claim, running these smoke commands on a host with production can target its services and volumes. A different `POSTGRES_DB` value does not isolate an existing PostgreSQL volume.

**Fix:** Give smoke a distinct project name everywhere, including setup, tests, cleanup, backup arguments if used, and documentation. Add a guard refusing production volume/project names in synthetic test tooling. Do not point test scripts at production data.

**Acceptance:** Resolve production and smoke together; their containers, networks, and all persistent volume names must differ. Run smoke alongside a disposable production-like deployment and verify the latter remains untouched.

### [x] F08 — The application connects using the PostgreSQL bootstrap superuser

**Evidence:** Source/configuration and live local role query: `ssdc|t|t|t` for user/superuser/create-database/create-role. `compose.prod.yaml:8-12,37-40`, `config/settings.py:88-98`.

The same `POSTGRES_USER`/password initializes PostgreSQL and authenticates Django. The official image creates that bootstrap user with superuser privileges, so production inherits excessive database authority. A compromised application can bypass ordinary database restrictions, alter audit history, and exercise server-level PostgreSQL capabilities. Running the DB process as an unprivileged OS user does not remove SQL superuser power. [Official PostgreSQL image documentation](https://hub.docker.com/_/postgres).

**Fix:** Separate bootstrap/operator, migration/schema-owner, and application runtime credentials. Give the runtime role only required table/sequence rights; make audit events insert/read-only for it. Adjust backup/drill tools to use controlled operator credentials rather than requiring runtime superuser/CREATEDB.

**Acceptance:** Runtime role has no SUPERUSER, CREATEDB, CREATEROLE, or unnecessary schema ownership. Staff flows work under it; it cannot update/delete audit events or create privileged roles. Migrations and recovery still work with their separate identities.

### [x] F09 — Security mutations can succeed without their audit event

**Evidence:** Metadata failure path reproduced. `vault/views.py:289-291`, `accounts/admin.py:87-103`, `accounts/views.py:185-190`, `vault/admin.py:20-27`.

A simulated audit write failure produced an error response but left the metadata change saved without a `metadata_changed` event. Session/MFA reset actions and password changes also write account state before an independently committed event. Bulk administrative deletion needs the same review.

**Fix:** Commit security-relevant state changes and their audit records in the same database transaction. Define partial-batch behavior for admin actions and record successful results accurately. Keep operational/external audit export separate from the durable local transaction.

**Acceptance:** Inject an event-storage failure into each mutation path; state either rolls back with the event or follows a documented durable audit mechanism. Never silently leave an unaudited permission/account/document mutation.

## P1: security architecture and production operation gates

### [ ] F10 — Seven high-severity container scan entries remain unresolved

**Evidence:** Fresh `artifacts/review-app-scan.txt`, `review-db-scan.txt`, `review-proxy-scan.txt`, `review-clamav-scan.txt`; `Dockerfile:8`, `deploy/Dockerfile.db:1`, `deploy/Dockerfile.scanner:1`.

| Advisory | Images reporting it | Primary advisory reference |
|---|---|---|
| CVE-2026-95619 | App, PostgreSQL | [Debian GCC tracker](https://security-tracker.debian.org/tracker/CVE-2026-95619) |
| CVE-2026-85091 | App, PostgreSQL | [Debian zlib tracker](https://security-tracker.debian.org/tracker/CVE-2026-85091) |
| CVE-2026-74860 | PostgreSQL | [Debian libxml2 tracker](https://security-tracker.debian.org/tracker/CVE-2026-74860) |
| CVE-2026-86140 | PostgreSQL, ClamAV | [Debian libxml2 tracker](https://security-tracker.debian.org/tracker/CVE-2026-86140) |

These are four distinct advisories repeated across images. A package/source-package match does not demonstrate an exploitable portal endpoint. The checked trackers describe component/version conditions, so determine actual affected binaries and reachability rather than treating every source-package match identically. No clearance was established here.

**Fix:** Use supported patched images/packages where available. Otherwise obtain a qualified, documented applicability/reachability assessment and explicit release decision. Preserve exact release image identifiers and rerun scans after the final build; do not silently suppress findings.

**Acceptance:** Release images have no unresolved critical/high findings, or each remaining finding has a reviewed, justified disposition with an owner and revisit date.

### [ ] F11 — The untrusted parser shares the app's filesystem identity and secret mounts

**Evidence:** Source/configuration and an already documented residual risk. `vault/validation.py:23-47,138-144`, `compose.prod.yaml:47,50`, `docs/SECURITY.md:33-35`.

Removing credential environment variables and setting CPU/memory limits does not isolate filesystem access. The parser runs under the app UID with access to other private files and the mounted secrets the app can read. A parser exploit would therefore cross directly into the main application's trust boundary. No such exploit was demonstrated in this review.

**Fix/decision:** For confidential production uploads, review a dedicated parser/thumbnail worker with no application/DB/MFA secrets, no network, a read-only mount of only the selected input, and a bounded output channel. Also review ClamAV's root/capability/network exposure. If retaining the current boundary, obtain explicit qualified assessment and SSDC acceptance of this residual risk.

**Acceptance:** A synthetic parser process cannot read an unrelated document or application secrets, modify other originals, or reach the database/network under the selected design; deployment documents accurately describe the boundary.

### [ ] F12 — Upload concurrency can exceed the configured temporary storage and memory budgets

**Evidence:** Configuration calculation; stress failure not induced. `Dockerfile:20`, `compose.prod.yaml:53,57`, `config/settings.py:156-164`, `vault/validation.py:142`, `vault/services.py:88-89,24-25`.

Gunicorn has four request threads. Django spills uploads over 1 MiB into `/tmp`, which is only 64 MiB in production. Three near-25 MiB uploads can need about 75 MiB before parser/other temporary use. Each parser may use up to 512 MiB, so concurrent children plus Gunicorn can exceed the app's 1 GiB container budget. Inspection also occurs twice per upload. The configured service memory ceilings total more than 4 GiB before the host OS, despite a 4 GiB starting-host suggestion.

**Fix:** Bound upload/parser concurrency, budget temporary storage for allowed concurrent file sizes, and size the host/container memory from measured workloads. Consider a bounded job worker so scan/parse work cannot occupy all web threads. Handle disk/resource exhaustion as a controlled failure with cleanup. Include graceful shutdown/drain behavior for uploads during releases/backups.

**Acceptance:** On Linux with the actual read-only production setup, concurrently upload maximum-sized valid files and representative expensive PDFs while staff browse/login. No unexplained 500s, OOM kills, lost files, or persistently unavailable health checks.

### [ ] F13 — Backups need failure-safe service handling, serialization, and atomic publication

**Evidence:** Stop-failure and interrupted-encryption paths reproduced. `scripts/backup.py:20-29,79-126`.

`stop proxy app` runs before `try/finally`: if it partially stops services and then fails, no restart is attempted. The finalizer also starts both services even if they were intentionally stopped before backup. There is no lock preventing overlapping backup/drill/maintenance jobs. Stopping the web service does not stop independent `retry_scans` or purge commands that can mutate the DB/files during the paired snapshot. Encryption writes directly to the final archive name; an interruption leaves an incomplete file that subsequent runs refuse to overwrite.

**Fix:** Use a maintenance/job lock shared with mutating operator tasks, put service stop handling inside guaranteed recovery logic, preserve prior service state, and publish the encrypted archive by an atomic rename only after successful completion. Handle signals/job failures and verify post-maintenance service health. Budget the plaintext archive/bundle plus encrypted output and restore extraction disk usage.

**Acceptance:** Inject stop, dump, archive, encryption, restart, and signal failures. No incomplete archive appears as a successful backup; prior service state is restored; overlapping jobs are rejected; retries/scans/purges cannot invalidate the paired snapshot.

### [ ] F14 — Restore, offsite backup, and key recovery are not yet operationally complete

**Evidence:** Validation/decision gap. `scripts/backup.py:127-213`, `docs/DEPLOYMENT.md` backup/disaster-recovery sections.

The drill verifies a temporary database and files, but it does not boot the restored app, decrypt its MFA accounts, verify grants/login/viewers, or establish actual recovery time. Real restoration is a prose procedure using an internal Python helper, not a fully executable runbook. Offsite destination, scheduling, retention, alerts, RPO/RTO, and key custody remain unresolved.

**Fix:** Provide an exact fresh-host restore procedure or guarded operator command, covering archive authentication, DB/file ownership, keys, migrations, permission checks, session revocation, audit recording, and proxy reopening. Implement approved backup scheduling and encrypted offsite transfer. Preserve MFA and backup keys separately with a tested custody/recovery process; decide host/storage encryption for confidential data and temporary plaintext.

**Acceptance:** Restore to an isolated fresh Linux deployment and successfully use MFA, browse permitted documents, deny cross-user access, and verify hashes. Demonstrate recovery from the offsite copy within approved RPO/RTO, including the lost-host scenario.

### [ ] F15 — Health and monitoring do not establish document-service readiness

**Evidence:** `/health/` still returned 200 with unusable private storage in a synthetic check. `config/views.py:7-13`, `vault/management/commands/operations_check.py:17-46`, `compose.prod.yaml:48-64`, `docs/DEPLOYMENT.md` monitoring section.

Health currently checks only PostgreSQL, despite documentation saying DB/storage/scanner failure produces unavailable health. `operations_check` covers more, but has no connected scheduler or alert destination and does not check signature freshness. The app starts without waiting for ClamAV. Quarantined files rely on a manually invoked retry command. Docker's restart policy does not by itself repair an unhealthy-but-running service.

**Fix:** Separate lightweight liveness from operational readiness, and monitor storage, scanner reachability/signature age, backlog, disk, DB growth/connections, failures, and backup freshness. Define behavior while ClamAV warms up. Add approved scheduled `retry_scans`, `clearsessions`, and `clear_rates`, serialized with maintenance; retain/purge audits only under policy. Send real alerts to a named owner.

**Acceptance:** Simulate scanner outage/stale signatures, unwritable/full storage, DB outage, failed backups, and old quarantined versions. The operator receives an alert, readiness is accurate, and documented recovery restores service without weakening scan or ACL controls.

### [ ] F16 — The actual HTTPS host, certificate renewal, and release environment remain unverified

**Evidence:** Validation/decision gap. `deploy/nginx.prod.conf:3-28`, `compose.prod.yaml:65-81`, `docs/DEPLOYMENT.md` production requirements.

The existing TLS fixture is a two-day self-signed localhost certificate; it does not establish domain/DNS ownership, a trusted public certificate, renewal, real firewall behavior, storage capacity, or operator access. Certificate/key mounts are individual files; renewal that replaces files/symlink targets must be tested with the running container's mount behavior.

**Fix:** Finalize the Linux host/domain/operator, canonical hostname, DNS, trusted full certificate chain, renewal and reload/recreate procedure, expiration alerts, host patching, restricted SSH, and externally verified port exposure. Keep DB/scanner/app inaccessible publicly. Decide HSTS subdomain policy; preload registration is optional and `security.W021` alone is not a defect requiring blind enablement.

**Acceptance:** From outside the host, test trusted HTTPS, HTTP redirect, secure cookies, MFA, previews/ranges, cross-user denial, renewal, restart, and closed infrastructure ports on the intended topology.

### [ ] F17 — Independent review and SSDC release policies remain open

**Evidence:** Decision gap already recorded in `docs/PRODUCT_SPEC.md`, `docs/SECURITY_REVIEW.md`, and `docs/PROGRESS.md`.

**Resolve:** Named release/security/operator owners; actual staff and permission assignments; administrator global-access acceptance; allowed watermark identity; all-staff MFA policy; identity verification for account/MFA recovery; document/deletion/audit retention; backup custody and RPO/RTO; capacity and supported staff devices; single-host availability acceptance; incident response and escalation. Resolve who may restore deleted documents: the lifecycle description says administrators, while current routes/tests allow scoped managers.

Commission independent security review against the corrected application and production configuration, including the concurrency defects above. Close findings and obtain a recorded SSDC go-live decision. The original requirement of preventing all download/copying also needs explicit acceptance of browser byte extraction/screenshots, which this design cannot eliminate.

**Acceptance:** Approved decisions are reflected in configuration/runbooks and staff grants; independent findings are closed or explicitly accepted by the responsible owner. Demo users and local keys are absent from production.

## P2: remaining functional, integrity, and verification fixes

### [ ] F18 — Content requests are not bound to a stable document version

**Evidence:** Source/configuration and URL identity check. `templates/vault/viewer.html:4`, `static/js/viewer.mjs:59-65`, `vault/views.py:158-180`, `vault/urls.py:18`.

PDF.js loads bytes/ranges from a document-only URL, and each request resolves the current active version. Replacement/restoration between requests can mix bytes from different PDFs. There is no version precondition/validator to reject that transition. The same URL remaining unchanged across replacement was verified; an actual mixed-PDF browser failure was not induced.

**Fix:** Bind a preview to its selected version or use a version precondition that returns a controlled refresh/conflict when the active version changes. Maintain current ACL/archive/deletion checks on every request. Do not open an unrestricted historical-version delivery path.

**Acceptance:** Replace/restore during ranged viewing; the viewer receives one consistent version or a clear refresh-required result, never silently mixed byte ranges.

### [ ] F19 — A delayed scan can undo an explicit version restoration

**Evidence:** Reproduced. `vault/services.py:48-53`, `vault/views.py:379-394`.

Publication chooses by upload timestamp relative to the active version. Restoring an older version does not record a newer selection intent. A pending newer upload subsequently scanned successfully and automatically replaced the explicitly restored version.

**Fix:** Record publication/selection intent or revision state so delayed processing cannot overwrite a more recent explicit restore. Decide whether replacement should publish automatically after an intervening restore and make that behavior visible.

**Acceptance:** Upload a quarantined replacement, restore an earlier version, then retry scans; the selected version remains as intended or the user explicitly approves the pending replacement.

### [ ] F20 — Publication does not verify that stored bytes still match intake metadata

**Evidence:** Reproduced by changing a quarantined synthetic PDF before retry. `vault/services.py:19-54,75-113`, `vault/management/commands/verify_storage.py:15-23`, `scripts/backup.py:174-188`.

Retry published the altered file while retaining its original SHA-256 and size metadata. This affects corruption detection, quota accuracy, and the meaning of a successfully published version. Restore verification only checks thumbnail existence, not its recorded size or hash.

**Fix:** Recheck original size/hash before publication and reject/report mismatches as integrity failures. Define thumbnail integrity metadata, validate it on restore, and prevent post-publication mutation through the selected storage/processing boundary.

**Acceptance:** Alter/truncate originals or thumbnails in synthetic storage; publication/verification fails clearly and unaffected documents remain usable. Actual served bytes match reserved size/hash metadata.

### [ ] F21 — Folder reparenting can create cycles and violate descendant depth limits

**Evidence:** Both reproduced. `vault/models.py:26-38`, `vault/admin.py:35-40`.

`full_clean()` follows cached parent model objects. Two admin forms prepared before either is saved can pass the advisory lock sequentially and still create a parent cycle because the second uses cached old ancestry. Separately, moving a subtree validates only the moved folder's ancestry, allowing existing descendants to exceed the 20-level limit.

**Fix:** Read current ancestry under the hierarchy lock without using stale relation caches. Validate the complete affected subtree depth and current folder count before committing. Ensure all folder mutation paths use that protocol and admin validation failures remain usable form errors.

**Acceptance:** Concurrent opposing moves cannot create a cycle, and moving a deep subtree cannot exceed the depth limit for any descendant.

### [ ] F22 — Permission audit events lose the identity of the actual grant being changed

**Evidence:** Deletion case reproduced. `audit/models.py:6-17`, `audit/services.py:12-18`, `vault/admin.py:10-27`.

Grant events store the grant row's integer ID, with no object type, subject user, folder/document ID, grant level, or before/after state. After deletion the row is gone, so the event cannot tell an investigator whose access to what was removed. Failed logins also lack an attributable attempted-identity reference. Operator purge does not persist the supplied policy reference.

**Fix:** Add structured, allowlisted event details: object type, stable target, subject account, relevant before/after permission state, operation/policy reference, and a privacy-conscious failed-authentication correlation identity. Keep credentials, document contents, session tokens, and MFA seeds out. Decide whether a remote append-only audit sink is required.

**Acceptance:** Reconstruct grant creation/change/deletion and recovery/purge decisions from retained events after source rows are removed, without exposing secrets.

### [ ] F23 — Error logs discard the information operators need to diagnose failures

**Evidence:** Two distinct synthetic error records formatted to exactly the same output. `config/logging.py:5-15`, `config/settings.py:170-177`.

The formatter removes all message/location/traceback detail and logs only generic event, level, logger, and sometimes exception type. Unrelated failures become indistinguishable. Nginx logs also have no request correlation ID, so staff error reports cannot be matched reliably to application errors.

**Fix:** Emit structured safe event codes, request IDs, timestamps, status, sanitized code location/exception information, and operational context. Explicitly redact credentials, query/body contents, tokens, and sensitive metadata; do not restore unrestricted request dumps.

**Acceptance:** Diagnose a simulated storage, parser, database, and audit failure from logs and the request reference while confirming sensitive values are absent.

### [ ] F24 — Documented limit/session configuration is not forwarded into production containers

**Evidence:** Source/configuration. `config/settings.py:138-160`, `compose.prod.yaml:33-46`, `.env.example`, `templates/vault/form.html:2`.

Settings read upload/storage/page/pixel/folder/session limits from environment variables, but production Compose forwards none of those overrides. Putting them in `.env.production` therefore does not configure the container. The upload hint and Nginx 26 MiB body limit are hardcoded, so changing only the Django limit would create inconsistent behavior. [Compose environment variable documentation](https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/).

**Fix:** Expose the approved knobs explicitly in Compose and a safe production environment example, validate sensible positive bounds, and keep proxy/request/UI limits aligned. Document units and startup errors. Do not broadly inject every host environment variable or secret.

**Acceptance:** Override each approved limit in staging, inspect effective settings, and verify behavior at the boundary through Nginx; the form describes the actual configured upload limit.

### [ ] F25 — The viewer throws JavaScript errors after failed PDF loading

**Evidence:** Browser reproduction. `static/js/viewer.mjs:21-56,74-80`.

Listeners remain active after PDF loading fails. Clicking Fit width calls `documentPdf.getPage()` on an undefined object and raises an unhandled error. Zoom/render has similar assumptions. The render marker remains set after the initial success and does not establish that later page/zoom operations finished. Decimal page input is not normalized to an integer.

**Fix:** Disable dependent controls until content is ready, guard all render/fit paths, handle listener promise rejection, normalize page input, and clear stale canvas/render state on failures or navigation. Give an accessible expired/revoked/unavailable recovery path.

**Acceptance:** Failed initial load, session expiry, revocation, unavailable range, rapid navigation, and invalid page input produce clear status and no uncaught errors or stale successful-render indication.

### [ ] F26 — Document-only grantees are sent back to an inaccessible folder

**Evidence:** Reproduced. `templates/vault/viewer.html:3`, `vault/views.py:133-141`, `vault/policy.py:39-45`.

An explicit document grant correctly permits viewing without a folder grant, but the preview's only breadcrumb/back link points to that denied folder and returns 404.

**Fix:** Select a permitted breadcrumb/back destination, falling back to the library for document-only access. Decide which containing-folder metadata a document-only grant is intended to reveal.

**Acceptance:** Staff with only a document grant can open it, return to a usable library, and see only approved metadata; equivalent manager flows work too.

### [ ] F27 — Allowed long staff IDs break mobile layout

**Evidence:** Browser reproduction at 390 px with a valid 150-character staff ID. `templates/base.html:25`, `static/css/app.css:1`. Long document headings and admin/management forms also need boundary checks.

The normal short-fixture library passed, but the topbar's long unbroken account label made the page wider than the viewport. Current responsive assertions do not cover allowed input lengths or other authenticated screens.

**Fix:** Constrain/wrap account labels and headings, set appropriate flex/grid minimum widths, and preserve access to sign-out and key controls. Test realistic maximum metadata lengths and narrow screens on forms, management, enrollment, recovery, and viewers.

**Acceptance:** Allowed account/title/folder values do not push essential UI offscreen; horizontal scrolling is limited to intentional document/table surfaces.

### [ ] F28 — PDF accessibility needs an approved usable solution

**Evidence:** Known implementation gap. `templates/vault/viewer.html:6`, `static/js/viewer.mjs:33-44`, `docs/SECURITY.md:7-8`.

Canvas-only PDFs expose a generic “Document page” label rather than document text to assistive technology. Keyboard next/previous controls do not solve screen-reader access. There are no current comprehensive accessibility assertions or staff-device acceptance results.

**Fix/decision:** Agree an accessible viewing approach compatible with SSDC's extraction-risk policy, such as a permission-protected semantic text layer or approved alternative. Audit contrast, labels, focus, errors, status changes, zoom, and keyboard flows across portal and administration.

**Acceptance:** The intended staff, including assistive-technology users where applicable, can complete required tasks on approved devices. If an alternative is chosen, document and test it before excluding affected staff from access.

### [ ] F29 — Recovery and key rotation are described but lack complete executable procedures

**Evidence:** Source/documentation gap. `accounts/admin.py:93-103`, `accounts/views.py:97-136`, `accounts/mfa.py:15-24`, `templates/accounts/enroll.html:2`, `docs/SECURITY.md:16-22`.

The sole-admin recovery text mentions `changepassword`, but that alone does not repair lost MFA; the required audited MFA reset steps are unspecified. Replacing the Fernet key makes stored seeds undecryptable, with no rotation/migration command. Staff cannot opt into MFA through the current account-security page or regenerate exhausted recovery codes without an administrator reset. Whether those self-service features are required is a policy choice.

**Fix:** Write tested operator-only sole-admin recovery and key-rotation runbooks/commands, including identity verification, custody, session/challenge revocation, auditing, and recovery if interrupted. Define code regeneration and optional staff MFA behavior. Add a usable setup flow on actual authenticator apps; QR enrollment can be a follow-up if manual entry is approved.

**Acceptance:** A disposable deployment survives lost sole-admin authenticator and planned key rotation without losing legitimate access or bypassing required identity checks. Recovery-code handling remains one-use under concurrency.

### [ ] F30 — Browser/release automation does not yet cover the risky production paths

**Evidence:** Existing script failure and source review. `scripts/browser_check.py:13-70`, `scripts/production_smoke.py:33-55`, `tests/conftest.py:15-24`, `pyproject.toml`; no tracked CI workflow.

The development browser script depends on a manually saved credential file that was rejected during this review. Backend fixtures force development scanning/settings and synthetic MFA assurance for most endpoint tests. TLS smoke tests a non-MFA staff login and only checks that the HTTP redirect starts with HTTPS; it does not follow the redirect or exercise actual uploads, parser budgets, scanners, MFA, or PDF content through production settings. Page-number updates/render markers do not prove the new page finished rendering correctly.

**Fix:** Make fixtures reproducible in dedicated projects/databases with reliable cleanup and useful failures. Add CI/release checks for the fixes above, Linux production secret permissions/read-only filesystem, actual privileged MFA, real scanner failure/success, uploads and versioned ranges, browser error paths, accessibility, and backup failure handling. Use representative Unicode/fonts/scanned/color PDFs and JPEG/PNG/WebP, not only small Latin/blank PDFs.

**Acceptance:** A clean checkout can run the documented checks without stale credentials; the exact release candidate passes a production-like Linux/browser suite and recorded release gates. A failed required check prevents release.

### [ ] F31 — Release packaging and rollback provenance need tightening

**Evidence:** Source/configuration. `Dockerfile:13-16`, `.dockerignore`, `requirements.txt`, `compose.prod.yaml:4,24,32,66`.

Python pins have no package hashes. Runtime images use mutable local names/default tags, and Compose does not take explicit release image references. `COPY . .` packages any non-excluded local files. `.kilo/worktrees/` exists and is excluded by local Git settings but not by `.dockerignore`, so a future build from this workspace can include a duplicate checkout and its unreviewed contents. It was absent from the currently running app image; this is a next-build packaging risk, not a claim that secrets were found there.

**Fix:** Restrict the build context/COPY inputs or explicitly exclude editor/agent worktrees and other local artifacts. Add dependency hash verification and an exact release manifest for all four resulting images. Use versioned tags/digests selectable in production Compose, preserve prior images and paired backups, and test the rollback/migration procedure.

**Acceptance:** A dirty developer workspace cannot inject unintended files into the release; the released image can be traced to source/dependencies/scans, redeployed unchanged, and rolled back using the documented process.

### [ ] F32 — Proxy/rate-limit behavior needs validation against the real office network

**Evidence:** Source/configuration. `accounts/views.py:46-55`, `audit/services.py:21-35`, `deploy/nginx.prod.conf:1-6,18-26`, `deploy/nginx.dev.conf:6-10`.

Successful logins count against the same 30-per-five-minute IP bucket as failures. An office sharing one public IP can exhaust the login limit collectively. Development requests use the proxy's address for Django's IP bucket. Nginx has a catch-all hostname and builds HTTP redirects from the supplied host. If an additional load balancer/CDN is introduced, client-IP trust and topology need deliberate configuration rather than assuming the current direct-edge setup remains correct.

**Fix:** Test and tune approved limits for staff/NAT concurrency while retaining brute-force protection. Make limits configurable and limit costly management mutations appropriately. Configure canonical hosts/default rejection and only trust forwarding headers from the actual controlled proxy topology.

**Acceptance:** Normal shared-office login/viewing traffic succeeds, abusive attempts throttle across workers, spoofed forwarding headers cannot evade controls, and redirects stay on the intended HTTPS hostname/port.

### [ ] F33 — Existing documentation overstates several controls and operational outcomes

**Evidence:** `docs/PROGRESS.md`, `docs/SECURITY_REVIEW.md`, `docs/DEPLOYMENT.md`, `vault/views.py:250` compared with findings above.

Claims needing correction include isolated smoke volumes, transactional upload policy recheck, one-use recovery safety under concurrent full account saves, failure-safe backup restart, storage/scanner health behavior, and currently reproducible browser checks. The restore permission rule also needs consistency between specification and routes/tests. Historical passing checks must remain explicitly tied to the version/environment that produced them.

**Fix:** After remediation, update product/security/deployment/progress/test documents and inaccurate code comments. Replace claims with actual implementation behavior and new evidence. Maintain one current release checklist with owners and links to results.

**Acceptance:** A new operator can follow the documents on a clean Linux host without undocumented fixes, and every claimed security/operations control has matching code and verification evidence.

## P3: smaller usability and maintainability improvements

- [ ] **F34 — Replacement title input is ignored.** `vault/views.py:240-257` supplies an editable title, but `vault/services.py:101-102` only uses it for a new document. Hide it for replacement or implement an intentional, audited title update; do not silently discard input.
- [ ] **F35 — Administration usability and MFA enrollment.** Consider labels consistently saying “Staff ID,” a usable authenticator QR setup, confirmation/context for MFA-reset actions, and preserving the intended destination after reauthentication instead of returning every user to the root library. References: `accounts/admin.py`, `templates/accounts/enroll.html`, `accounts/views.py:149-170`, `config/admin.py:20-21`.
- [ ] **F36 — Frontend source readability and navigation state.** Large templates and almost all CSS are single lines; the library link is styled active using `.nav-link:first-child` even on account/management screens. Reformat without changing behavior and compute the active navigation item explicitly. References: `templates/`, `static/css/app.css:1`.

These are follow-ups unless SSDC makes them acceptance requirements. New signup, email recovery, office conversion, OCR, and document rights management are outside the current v1 scope; their absence is not a defect in the agreed specification.

## Required closure order

1. Fix F01–F05 and F09 first: stale/concurrent writes, revocation, MFA, scanning, and audit atomicity. Add regression tests that fail on the current behavior.
2. Fix F06–F08: Linux secret access, true smoke isolation, and least-privilege database identities.
3. Resolve F10–F17: advisories, parser boundary, capacity, failure-safe backups, recovery, readiness/alerts, actual HTTPS infrastructure, and organizational/independent release gates.
4. Close F18–F33 against the corrected production candidate, with approved owners/workarounds for any agreed P2 deferral.
5. Repeat required checks on the exact final images/configuration, perform the fresh-host restore and external HTTPS acceptance checks, update evidence/runbooks, and record the SSDC go-live decision.

**Deployment sign-off must be based on the corrected release candidate. Passing tests do not clear the remaining open findings in this report.**
