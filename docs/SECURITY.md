# Security and operational responsibilities

Google Drive is primary document storage. Owner-only offline OAuth uses `drive.file`;
server-held credentials are encrypted in PostgreSQL with a separate configured key.
Administrator connection uses CSRF-protected initiation, short-lived, single-use
session/account-bound state and PKCE. Session cookies use SameSite Lax for Google's
top-level callback; writes retain Django CSRF checks. The callback redirects to
clear its query and uses no-referrer. Supplied proxy logs omit URLs/query strings.
No tokens or Google download locations reach staff. Portal UUIDs resolve to Drive
IDs only after current SSDC ACL, active account/session and MFA checks on every
content, thumbnail and HEAD/range request. No sharing permissions are created.
Owner/app markers, parent, size, MIME and checksum checks fail closed if files are
changed/shared externally. The Drive owner and deployment operators remain trusted;
the owner can access originals in their own Drive. Delivered bytes cannot be recalled.
See [Google setup, limits and backup recovery](GOOGLE_DRIVE_SETUP.md).

Every document endpoint checks current server-side permissions. UUIDs only
identify records. Files are never served as media/static files. The customized
viewer omits print/download controls. It cannot stop
screenshots, OCR, developer tools, or an authorized recipient extracting bytes.
PDF canvas rendering omits link/annotation layers. Extracted page text is exposed
to screen readers; image-only documents still need an accessible alternative.

Privileged roles require TOTP and eight one-use recovery codes. Secrets are
encrypted separately from the database; losing the MFA key prevents decryption.
Back up its key separately with restricted access. Enrollment occurs only after
password authentication. Codes cannot be replayed, including within their time
window. High-impact management/admin actions require recent authentication.

Password/account/MFA recovery: an administrator verifies identity through an
SSDC-approved out-of-band process, resets the password using administration,
and, if required, selects the explicit MFA-reset action. Both reset and role/state
changes revoke existing sessions. Never send credentials through audit logs.
For a lost sole administrator, an authorized host operator can use Django's
interactive `changepassword` and an audited operator recovery procedure. Document
the identity decision outside the portal; operators must not bypass it casually.

Audit events contain timestamps, actor, target UUID/ID, event kind and outcome.
No contents, passwords, session tokens, MFA seeds, or request bodies are logged.
Staff cannot edit audit entries. Host/database operators can; for stronger tamper
resistance export to an organization-owned append-only sink. Retention awaits
organizational approval; physical purge is explicit, dry-run by default.

Account, permission, and document changes commit with their local audit events.
Event-store failures roll back the database mutation, including password changes,
MFA consumption at sign-in/identity confirmation, and automatic password-hash
upgrades (`password_hash_upgraded`, without recording hashes). Selected-user
session/MFA resets and administrative bulk deletion roll back the entire selection
on failure; both portal events and Django deletion history follow that result.
External audit export must not replace this local transaction.

File deletion cannot be rolled back by a database transaction. Operator orphan
cleanup durably records `started` before removing files; per-document physical
purge records `scheduled` with database deletion before removing its files.
Both record completion or failure separately. An interrupted operation or failed
completion write retains its initial event for investigation and does not claim
success. Purge is partial across documents: earlier completed documents remain
deleted if a later document fails. Maintenance/reference safeguards and richer
audit details still require the separate open deployment findings to be resolved.

Malware scanning fails closed in production. Pending uploads can be retried using
`retry_scans` or the scoped, recently authenticated **Retry document checks** action.
Monitor scanner health/signature freshness and never disable it
to clear production backlogs. Parser and ClamAV zero-days remain residual risks.
Processing is exclusive per version across uploads and retries. Fresh status
checks prevent an older attempt from altering a published/rejected result.
Rejection and its audit entry save together before original/preview cleanup;
failed or rolled-back saves preserve the files for retry. Generated previews are
replaced only after their complete contents have been written.
PDF/image validation and thumbnail generation run in a separate bounded process
without inherited credential environment. On Linux, Landlock restricts reads to
the selected input and interpreter libraries, and seccomp denies sockets and
process access. It shares the app UID and kernel; this remains a software sandbox
whose protection must be verified on the deployment host.
No office converters execute in v1. Protect operator access, patch container
images/dependencies, and monitor memory/disk pressure. A single host is a single
point of failure; capacity/availability needs organizational agreement.

Scanner-free deployment is an explicit reduced-protection option. Both
`SCAN_MODE=disabled` and its `ENABLE_CLAMAV=false` alias require
`ACCEPT_NO_MALWARE_SCANNING=1` in production. Hosting on Render does not bypass
this requirement. Structure/MIME/page/pixel validation remains enabled, but it
does not replace antivirus scanning. The operator must choose and record the
appropriate profile before deployment.

Multipart intake accepts one file per request. A streaming handler bounds file
bytes before Django's memory/disk handlers, and oversized bodies return HTTP 413.
Batch import sends individual requests. Proxy limits remain an additional boundary.

On suspected compromise: restrict proxy access, disable affected users/revoke
sessions, preserve audit/host evidence, rotate exposed credentials and keys with
a migration/recovery plan, inspect access history, notify the responsible SSDC
owner, remediate, and test restoration before resuming access. Already delivered
documents cannot be recalled. No security certification is claimed.
