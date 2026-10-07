# Build progress - 7 October 2026

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

- Most recent full Windows/PostgreSQL suite: all 77 tests passed, including the
  document-only manager metadata regression and destination denial check.
- Final Linux-container/PostgreSQL suite: all 77 tests passed as the non-root app
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

Release is blocked by the image findings and the pending independent/organizational
review. The next step is local review of the portal and closure of those release
gates, then deployment to an approved host following DEPLOYMENT.md.
