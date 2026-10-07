# Security and operational responsibilities

Every document endpoint checks current server-side permissions. UUIDs only
identify records. Files are never served as media/static files. The customized
viewer omits print/download controls and overlays staff ID/time. It cannot stop
screenshots, OCR, developer tools, or an authorized recipient extracting bytes.
PDF canvas rendering omits selectable text and link/annotation layers; this
reduces accessibility for screen-reader users and needs an approved alternative.

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

Malware scanning fails closed in production. Pending uploads can be retried using
`retry_scans`. Monitor scanner health/signature freshness and never disable it
to clear production backlogs. Parser and ClamAV zero-days remain residual risks.
PDF/image validation and thumbnail generation run in a separate bounded process
without inherited credential environment. It shares the app UID and filesystem;
this is resource isolation, not a separate hardware/container trust boundary.
No office converters execute in v1. Protect operator access, patch container
images/dependencies, and monitor memory/disk pressure. A single host is a single
point of failure; capacity/availability needs organizational agreement.

On suspected compromise: restrict proxy access, disable affected users/revoke
sessions, preserve audit/host evidence, rotate exposed credentials and keys with
a migration/recovery plan, inspect access history, notify the responsible SSDC
owner, remediate, and test restoration before resuming access. Already delivered
documents cannot be recalled. No security certification is claimed.
