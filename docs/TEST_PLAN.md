# Test plan

Run unit/integration tests on a dedicated PostgreSQL test database using only
synthetic PDFs and images. Verify custom identity/MFA, expiry/revocation, inherited
and explicit ACLs, policy changes, unauthorized GET/HEAD/range/thumbnail requests,
manager scope, upload validation/quota/scanner failure, lifecycle and audit events.
Enforce CSRF using a client configured to perform actual CSRF checks.

Browser tests use Playwright Chromium against a disposable seeded environment:
login, folder navigation, search, list/gallery, PDF page render/zoom, image preview,
watermark identity, absent print/download controls, logout and unauthorized access.
No production credentials or records. Add meaningful regression tests as each
segment introduces behavior.

Checks: Django system/deployment checks, migration consistency, Ruff formatting
and linting, pip-audit, npm audit, container build/start/health, PostgreSQL migration
and restart, and synthetic backup/restore drill. Report exact results and any gaps.
Separate automated self-review from independent penetration testing.
