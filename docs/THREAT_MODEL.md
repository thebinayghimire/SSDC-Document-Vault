# Threat model

Assets: document bytes/metadata, credentials/MFA keys, sessions, ACLs, audit trails,
database/storage backups. Actors: anonymous attacker, malicious staff member,
compromised account/device, administrator, infrastructure operator.

| Threat | Controls | Residual risk |
|---|---|---|
| Guessing IDs / broken object authorization | Shared policy on every route and query; default deny; 404 | A policy defect needs adversarial regression tests |
| Credential theft / brute force | Supported hashing, DB-backed limits, privileged MFA, generic errors | Phishing and compromised devices |
| Session theft / fixation | Rotation, secure HttpOnly SameSite cookies, expiry, revocation | Stolen active session before revocation |
| XSS / CSRF | Autoescape, CSP, CSRF on writes, no inline uploaded active content | Browser or framework defects |
| SQL injection | Django ORM, bounded filters and sort allowlist | Unsafe future raw queries |
| Malicious uploads | Signature/structure checks, limits, quarantine, ClamAV, no converters | New parser/antivirus vulnerabilities |
| Public storage exposure | Private volume, no media routing, non-root paths, endpoint checks | Operator misconfiguration |
| Extraction / screenshots | Removed controls, no-store | Authorized recipients can recover bytes or screenshot |
| Admin compromise | Mandatory MFA, reauthentication, auditable mutations | Admins intentionally have broad authority |
| Backup theft / deletion | Encrypted backups, separate keys, controlled restore/purge | Operator access and untested procedures |
| Denial of service | Request/file/page/pixel/quota/rate/resource limits | Capacity exhaustion, expensive hostile PDFs |
| Audit manipulation | No staff write/delete access; restricted DB | DBA can alter logs; remote immutable sink needed for stronger guarantees |

Trust boundaries: browser and uploaded content are untrusted; proxy is trusted
only for explicitly set forwarding headers; app controls authorization; DB holds
identity/policy; private owner Google Drive holds accepted bytes and the private
filesystem stages uploads and preserves legacy versions; antivirus sees confidential bytes
internally; host/backup operator controls infrastructure. No third-party CDN gets
document data. Antivirus signature updates require network access only for scanner.

Security review must validate proxy configuration, every delivery path, MFA and
recovery, scanner isolation, backups and operational identity verification before
real SSDC records. Technical tests do not establish complete security.
