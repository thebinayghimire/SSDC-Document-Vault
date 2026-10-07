# Product specification (Segment 00)

SSDC staff sign in using a unique staff ID and password, browse only permitted
folders/documents, and preview PDF, JPEG, PNG, and WebP content. Public signup,
public sharing, office conversion, OCR, and email recovery are outside v1.
Screenshots, browser byte extraction, and OCR cannot be prevented by this portal.

## Identity and roles

Administrators manage accounts, grants, folders, and audit records. Managers may
upload, replace, edit, archive, and restore only within granted scopes. Staff and
restricted staff are read-only. Django superusers are administrators. Only
administrators access Django administration. Privileged roles require TOTP MFA;
all-staff MFA is configurable. Recovery uses one-use hashed codes or an audited
operator reset after identity verification. No assumed email infrastructure.

## Authorization semantics

Default deny. A folder is either inherited or restricted: restricted folders
use their own user grants, stopping ancestor inheritance, even if empty.
Inherited folders use the nearest restricted ancestor; an inherited root denies.
Documents follow their folder unless explicitly restricted to document grants.
There are view and manage grants; manage implies view, but only managers/admins
may mutate. Restricted/staff roles cannot gain write access from a grant alone.
Administrators have global access; this exceptional capability is auditable.
Search, listings, previews, thumbnails, HEAD, and byte ranges use the same policy.
Unpermitted IDs return 404. Revocation applies to the next request, including
existing sessions; already delivered content cannot be recalled.

## Lifecycle

Upload -> private quarantine -> extension/signature/structure/size validation ->
malware scan -> publication. Scan failures leave quarantine for retry; malformed
or infected uploads are rejected. Replacement publishes a new immutable version
only when ready, keeping the old version active until then. Archive hides from
readers; soft deletion preserves versions for administrator restoration. Physical
purge requires an explicit operator command and organization-approved retention.
No automatic retention period is invented.

## Proposed technical limits, not SSDC policy

25 MiB/file, 20 megapixels/image, 500 PDF pages, 1,000 folders, 10 GiB total storage, 30-minute
idle session, 8-hour absolute session, five-minute MFA challenge, bounded login
and content request rates, pagination of 24 items. Configurable before deployment.
Single Linux host, PostgreSQL, private filesystem volume, ClamAV, Nginx, Docker
Compose. Database and antivirus are never publicly published. Development is
loopback-only. Production requires explicit secrets, hosts, HTTPS, and scanning.

## Acceptance mapping

| Requirement | Evidence required |
|---|---|
| Identity and MFA | Password/TOTP/recovery/replay/disabled-account tests |
| Least privilege | Two-user endpoint matrix, overrides, inheritance, role escalation tests |
| Upload safety | Signature, extension, malformed, traversal, quota, scanner failure tests |
| Private viewing | Auth checks on GET/HEAD/range, no public media URL, viewer browser tests |
| Usable library | Search/sort/pagination/list/gallery and keyboard/responsive browser checks |
| Governance | Account/session reset, immutable audit UI, version/archive/restore tests |
| Operations | PostgreSQL migrations, container health, deployment settings check, backup restore drill |

## Organizational decisions outstanding

Hosting/domain/operator; staff counts and storage growth; which users get grants;
whether administrator global access is acceptable; retention/deletion/audit policy;
backup location, encryption-key owner, RPO/RTO; acceptable watermark identity;
supported staff devices; all-staff MFA and recovery identity verification process;
formal risk acceptance and independent security review. Technical defaults allow
local development, but do not count as organizational approval.
