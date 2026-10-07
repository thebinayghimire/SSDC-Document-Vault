# SSDC Secure Document Portal: Conversation Transcript

> Export date: 6 October 2026.
> This is a partial transcript: it includes the exact user messages available in this dialog and the complete assistant build plan preserved in the supplied text file. Two earlier assistant replies could not be recovered verbatim and are marked below. No replacement replies have been invented. Tool output, system instructions, and unrelated conversation history are excluded.

## 1. User

Hi, my dad asked me whether this could be built or not... He works in SSDC (Siddhartha Social Development Centre), and wants me to build a system/website (primarily a website), where it has a link or web address right, when opened, it asks for a authorization page (where it asks id and password), then it must show the files (most likely .pdf's and images) in a list view or gallery view like it shows on a folder box. Then it should be previewed. Previewed page must be there for the supported file type, but there's this catch, no one can download the file, also the copy paste should not work on this. It's for his office, so there must not be any security flaws

## 2. Assistant

*[Exact reply unavailable in the accessible conversation context.]*

## 3. User

Okay, can you give a detailed systematic product building segments in order to give to AI agents which can do it in ease.

## 4. Assistant

Binay, build this as a sequence of controlled development phases, not one enormous prompt asking an AI agent to create the entire application at once.

For SSDC, the priority is a working document portal with security enforced by the backend. The AI agent should implement one segment, run its tests, document the result, and only then proceed to the next segment.

I recommend using Django + PostgreSQL + PDF.js + private file storage, with Docker for deployment. The instructions below are designed to be fed into Claude Code or another coding agent that can inspect, edit, and run a project in a terminal.

# SSDC Secure Document Portal: Product Build Plan

## Development sequence

## 00

Project specification and architecture

Define scope, threat model, requirements and technical decisions.

## 01

Project foundation

Create the repository, Django project, environment configuration and Docker setup.

## 02

Database and identity

Implement users, roles, permissions and authentication.

## 03

Document storage

Build private file storage, uploads, validation and malware-scanning integration.

## 04

Document library

Create folders, metadata, search, pagination and list/gallery views.

## 05

Secure document viewer

Implement PDF.js, image previews, watermarks and restricted viewer controls.

## 06

Authorization enforcement

Protect every document request, prevent insecure direct-object access and handle sessions.

## 07

Administration

Build staff management, document management, permissions and audit interfaces.

## 08

Security hardening

Configure browser policies, rate limits, security headers, logging and secure defaults.

## 09

Automated testing

Test access control, uploads, sessions, viewer behavior and common attack paths.

## 10

Production deployment

Deploy with HTTPS, backups, monitoring, secrets management and recovery procedures.

## 11

Independent security review

Validate the system against the threat model before real SSDC documents are uploaded.

## How to use these prompts

1. Create an empty Git repository for the project.
2. Give the agent the Master Instructions below.
3. Submit Segment 00 and proceed in order.
4. Require the agent to run the relevant tests and report failures before moving forward.
5. Review the security-critical changes yourself or with a qualified reviewer. Passing automated tests does not establish that the application is secure.

Each segment is intended to be a separate task in the same coding-agent session. If you start a new session, provide the master instructions and the latest project progress report.

## Master instructions and implementation prompts

Copy this master prompt into your coding agent first. Then use the individual segment prompts below it, one at a time.

# SSDC Secure Document Portal

## Master Instructions for the AI Development Agent

### 1. Project objective

Build a production-oriented, private document management and viewing web application for Siddhartha Social Development Centre (SSDC).

The application must allow authorized staff to sign in, browse documents, preview supported files, and access only the folders and documents permitted to their accounts.

The application will primarily store and display PDF files and images. It may later support read-only previews of DOCX, XLSX, PPTX, and TXT files.

The application must prioritize confidentiality, integrity, availability, maintainability, accessibility, and straightforward administration.

### 2. Required technology

Use the following stack unless a documented technical reason requires a change:

- Backend: Python with Django.
- Database: PostgreSQL.
- Frontend: Django templates, HTML, CSS, and JavaScript. Use a maintainable component system or utility CSS framework only when it genuinely helps.
- PDF viewing: PDF.js with a customized viewer.
- File storage: Private filesystem storage for the initial deployment, behind a storage abstraction that can later support private object storage.
- Background jobs: Introduce a worker and queue only where necessary, such as file conversion, malware scanning, or large batch operations.
- Reverse proxy: Nginx or an equivalent supported production proxy.
- Deployment: Docker and Docker Compose, with separate production configuration.
- Testing: Django's testing framework and pytest where useful, plus browser-based end-to-end tests.
- Version control: Git.

Pin and document dependencies. Use maintained, supported releases compatible with the deployment environment. Never assume that a package is secure simply because it is popular.

### 3. Non-negotiable security requirements

1. All document storage must be private by default.
2. Every document operation must enforce authorization on the server.
3. A document ID, filename, UUID, or URL must never function as an access credential.
4. Users must never access files merely by guessing another document's identifier.
5. No public document URLs, public storage buckets, or permanent unauthenticated download links.
6. Do not store passwords in plaintext or implement custom password hashing.
7. Do not commit secrets, passwords, production credentials, private keys, or real SSDC documents to Git.
8. Use HTTPS in production.
9. Apply secure session management, CSRF protection, input validation, rate limiting, and security headers.
10. Validate uploaded files using extension allowlists, file signatures, size limits, and safe processing. Treat all uploads as untrusted.
11. Do not render uploaded HTML, SVG, JavaScript, or other active content inline without a separately reviewed sanitization and isolation strategy.
12. Keep audit records for authentication, document access, permission changes, uploads, administrative actions, and other defined security events.
13. Avoid logging passwords, session tokens, authentication secrets, or document contents.
14. Implement appropriate backup, restoration, retention, and account-revocation procedures.
15. Never claim that hiding download buttons, disabling text selection, or blocking keyboard shortcuts prevents all copying.
16. Do not claim that the application is completely secure. Identify residual risks and obtain independent security review before production use.

### 4. Document protection model

The application should discourage ordinary downloads, printing, copying, and redistribution while allowing authorized users to view documents.

Use a customized PDF.js viewer with download and print controls omitted, an optional text-selection restriction, individualized watermarks, and suitable browser cache controls.

Do not expose original storage paths or public file URLs.

The backend may deliver authorized document bytes or pages to the viewer. This is a residual extraction risk and must be documented.

Do not build a misleading security feature that claims screenshots or all copying are impossible. If stronger controls are required, evaluate managed devices, remote desktop infrastructure, or a dedicated document rights-management solution.

### 5. Development methodology

Work in explicit, numbered segments.

For each segment:

1. Inspect the existing repository before changing anything.
2. Read the project specification and the latest progress report.
3. Identify the files that must be created or changed.
4. Implement only the scope of the current segment.
5. Write or update automated tests.
6. Run relevant tests, formatting, linting, and security checks.
7. Fix failures rather than hiding or skipping them.
8. Review the changes for security regressions.
9. Update the documentation and progress report.
10. Summarize completed work, files changed, test results, known limitations, and the exact next step.

Do not silently skip unfinished work. Do not claim tests passed unless they were actually executed.

Do not rewrite working parts of the application unnecessarily. Preserve backward compatibility where appropriate and use database migrations for schema changes.

Do not fabricate environment variables, test results, successful deployments, or security audit results.

### 6. Definition of done

A segment is complete only when:

- Its acceptance criteria are met.
- Relevant automated tests pass.
- Security implications have been reviewed.
- Documentation has been updated.
- Known limitations are recorded.
- The next segment can proceed without relying on undocumented assumptions.

### 7. Required project documentation

Maintain these documents throughout development:

- `README.md`: Project overview, prerequisites, local setup, development commands, and troubleshooting.
- `docs/PRODUCT_SPEC.md`: Functional requirements and product boundaries.
- `docs/ARCHITECTURE.md`: Application components, data flows, storage design, and deployment.
- `docs/THREAT_MODEL.md`: Threats, assumptions, trust boundaries, mitigations, and residual risks.
- `docs/SECURITY.md`: Security controls, incident response, account management, and operational guidance.
- `docs/TEST_PLAN.md`: Test strategy, coverage, and acceptance criteria.
- `docs/DEPLOYMENT.md`: Production installation, configuration, HTTPS, backups, updates, and recovery.
- `docs/PROGRESS.md`: Completed segments, outstanding work, test results, decisions, and next steps.

Start with the project specification. Do not implement the whole product in a single pass.

## Segment 00: Requirements, threat model and architecture

# Segment 00: Product Specification and Architecture

Read the master instructions and inspect the repository. Do not start implementing the entire application.

### Tasks

1. Define the product's functional and non-functional requirements.
2. Identify intended user groups:
   - System administrator
   - Document manager
   - Standard staff member
   - Read-only or restricted staff member, if required
3. Define the document lifecycle: upload, validation, processing, publication, viewing, replacement, archival, deletion, and restoration.
4. Define folder-level and document-level access rules.
5. Create a threat model covering:
   - Unauthorized document access
   - Broken object-level authorization
   - Credential theft and brute-force attacks
   - Session theft and fixation
   - Cross-site scripting and cross-site request forgery
   - SQL injection
   - Malicious or malformed uploads
   - Public storage exposure
   - Document extraction and screenshots
   - Administrative account compromise
   - Backup theft and accidental deletion
   - Denial of service and resource exhaustion
6. Establish trust boundaries between browsers, application server, database, private storage, background workers, and reverse proxy.
7. Document which controls mitigate each threat and which risks cannot be eliminated.
8. Decide the initial deployment assumptions, storage limits, file size limits, session policy, and backup expectations. Mark unknown requirements as decisions needed from SSDC.
9. Define a testable acceptance criterion for every major requirement.
10. Create or update:
    - `docs/PRODUCT_SPEC.md`
    - `docs/ARCHITECTURE.md`
    - `docs/THREAT_MODEL.md`
    - `docs/TEST_PLAN.md`
    - `docs/PROGRESS.md`

### Constraints

Do not invent SSDC policies, legal requirements, data retention periods, or compliance certifications. Record these as decisions that the organization must approve.

Do not use real organizational documents in examples or tests.

### Acceptance criteria

The documents must describe the full system, the authorization model, document handling, residual risks, and a staged development plan. A developer must be able to implement the following segments without having to guess the intended architecture.

Finish with a concise summary of decisions, unresolved questions, and the next segment. Do not build application features yet.

## Segment 01: Repository, Django foundation and Docker

# Segment 01: Project Foundation

Implement the initial application foundation using the approved Segment 00 architecture.

### Tasks

1. Create a maintainable Django project with clearly separated applications.
2. Establish a sensible structure for configuration, templates, static files, application code, tests, documentation, and deployment files.
3. Configure environment-based settings for development, testing, and production.
4. Configure PostgreSQL and database migrations.
5. Add a Dockerfile and Docker Compose configuration for local development.
6. Include a reverse proxy configuration where appropriate, without exposing internal services unnecessarily.
7. Add dependency pinning and a repeatable installation process.
8. Create `.env.example` containing placeholder values only.
9. Configure `.gitignore` to exclude secrets, virtual environments, caches, uploads, database dumps, and generated artifacts.
10. Add health-check endpoints that reveal no secrets or sensitive infrastructure information.
11. Configure structured application logging with sensitive-field redaction.
12. Document local startup, shutdown, migrations, tests, and troubleshooting.

### Security requirements

- Never hardcode production secrets.
- Do not expose PostgreSQL directly to the public internet.
- Do not store uploaded files in a publicly served static directory.
- Fail safely when required production configuration is missing.
- Ensure development-only settings cannot accidentally be used in production.

### Acceptance criteria

The application starts using the documented development procedure. PostgreSQL connectivity, migrations, health checks, and initial tests work. The repository contains no real secrets. Production settings enforce appropriate secure defaults.

Do not implement document management or advanced authentication yet. Report actual command results and proceed only when the foundation is working.

## Segment 02: Authentication, accounts and permissions

# Segment 02: Identity and Authorization Foundation

Implement account management and the authorization foundation using Django's built-in authentication and permission mechanisms.

### Features

1. Create a custom user model before the first production database migration if the architecture requires it.
2. Support unique staff identifiers and secure password authentication.
3. Allow administrators to create, disable, and manage accounts.
4. Support password changes and a secure account-recovery process appropriate to the available infrastructure.
5. Implement role-based access control.
6. Implement folder-level and document-level permissions in a way that supports future organizational requirements.
7. Define least-privilege defaults.
8. Support administrator and staff roles without granting ordinary users administrative privileges.
9. Implement login, logout, session expiry, and session invalidation.
10. Add login rate limiting or throttling.
11. Require MFA for privileged accounts, with a documented and secure recovery procedure. Make broader MFA enforcement configurable according to SSDC's policy.
12. Record security-relevant authentication and account-management events.

### Security requirements

- Use Django's supported password hashing.
- Use generic authentication and recovery responses that do not reveal unnecessary account information.
- Protect state-changing operations with CSRF defenses.
- Regenerate or rotate session identifiers appropriately after authentication and privilege changes.
- Use secure, HTTP-only cookies and appropriate SameSite settings.
- Never implement authorization solely in JavaScript or templates.
- Disabled users must lose access through existing sessions according to the approved revocation policy.
- Prevent ordinary staff from changing their roles or granting themselves permissions.

### Tests

Test valid and invalid logins, throttling, disabled accounts, role restrictions, session expiry, logout, privilege escalation attempts, password changes, and MFA flows.

### Acceptance criteria

Authentication and authorization work through the backend, privilege boundaries are tested, and account administration is usable. Do not expose documents until the authorization foundation passes its tests.

## Segment 03: Private storage and secure uploads

# Segment 03: Private Document Storage and Upload Pipeline

Implement a secure document-storage abstraction and upload workflow.

### Tasks

1. Store original documents outside the public web root.
2. Generate internal storage identifiers independently of user-supplied filenames.
3. Store document metadata in PostgreSQL, including:
   - Original filename
   - Internal identifier
   - MIME type determined through inspection
   - File size
   - Cryptographic content hash
   - Uploader
   - Upload and modification timestamps
   - Processing status
   - Parent folder and access-policy references
4. Implement a configurable extension allowlist.
5. Validate content signatures and inspect actual file types.
6. Enforce file size limits, upload quotas, and request-size limits.
7. Reject dangerous, malformed, mismatched, or unsupported uploads.
8. Add malware-scanning integration where infrastructure supports it.
9. Quarantine uploads until validation and required scanning are complete.
10. Implement safe error handling and cleanup of failed or abandoned uploads.
11. Prevent path traversal, filename collisions, symlink attacks, and arbitrary file overwrite.
12. Record upload and processing events in the audit system.
13. Provide an interface for administrators to upload and inspect document status.

### Processing requirements

Do not execute uploaded content.

Do not render uploaded HTML or SVG directly within the authenticated application's origin.

If office-document conversion is implemented later, run the converter with restricted privileges, resource limits, isolated temporary storage, and no unnecessary network access.

### Tests

Test oversized files, fake extensions, incorrect MIME declarations, malformed PDFs, suspicious filenames, duplicate names, traversal attempts, interrupted uploads, scanning failures, and unauthorized uploads.

### Acceptance criteria

Valid files are stored privately and can be identified through database metadata. Invalid files are rejected or quarantined. No unauthenticated HTTP request can retrieve an original document. Document processing failures do not leave partially published files.

## Segment 04: Document library and navigation

# Segment 04: Document Library Interface

Build the staff-facing document library using the approved design system.

### Features

1. Create a responsive, clean interface appropriate for SSDC staff.
2. Provide list and gallery views.
3. Support folders and nested folders if approved in the product specification.
4. Show filename, document type, size, modified date, and permitted metadata.
5. Add search, filtering, sorting, and pagination.
6. Provide breadcrumb navigation.
7. Display PDF thumbnails and image thumbnails only when they have been generated safely.
8. Add empty states, loading states, errors, and permission-denied messages.
9. Provide keyboard-accessible navigation and responsive layouts.
10. Allow users to open documents only when authorized.
11. Ensure folder listings and search results contain only permitted records.
12. Implement metadata updates and folder management for appropriately authorized staff.

### Security requirements

- Enforce permissions in every backend query and endpoint.
- Do not fetch every document and filter unauthorized results in the browser.
- Avoid leaking document existence, filenames, or metadata through unauthorized search results.
- Use pagination and bounded queries to prevent excessive resource consumption.
- Escape user-controlled text and use template autoescaping.
- Never trust client-supplied folder identifiers.

### Tests

Test search, pagination, folder navigation, permission-filtered results, unauthorized metadata requests, XSS payloads in filenames, and access to guessed identifiers.

### Acceptance criteria

Authorized users can efficiently browse their permitted documents. Unauthorized documents remain absent from listings, searches, thumbnails, and metadata responses. All operations enforce server-side authorization.

## Segment 05: Secure PDF and image viewer

# Segment 05: Document Preview System

Implement a read-oriented document viewer.

### PDF viewer

1. Integrate a maintained, pinned PDF.js release.
2. Render PDFs within the application interface.
3. Support page navigation, zoom, fit-to-width, and suitable keyboard navigation.
4. Remove normal download and print controls from the user-facing viewer.
5. Do not expose a direct link to the original file.
6. Deliver document content through authorization-checked backend endpoints.
7. If PDF.js requests partial content or byte ranges, ensure every relevant request independently enforces access control.
8. Disable or remove unnecessary viewer capabilities without breaking required rendering.
9. Ensure errors do not reveal filesystem paths, server internals, or sensitive document content.

### Image viewer

1. Support approved raster formats such as JPEG, PNG, and WebP.
2. Provide zoom and fit-to-screen controls.
3. Disable ordinary right-click saving and drag-to-download interactions where practical.
4. Offer an optional overlay watermark.
5. Do not assume disabling browser interactions prevents extraction.

### Watermarking

Where appropriate, overlay a visible, individualized watermark containing the authenticated user's staff identifier or approved display name.

Consider a timestamp or document reference where useful. Avoid exposing unnecessary personal information. Watermarks should not permanently modify the original file unless a separate, approved workflow requires it.

### Copying and caching

Implement text-selection restrictions as a deterrent where appropriate. Do not claim that these prevent browser inspection, screenshots, OCR, or extraction.

Apply suitable no-store cache directives to sensitive responses and review caching at the proxy, application, service-worker, and browser levels.

Do not use a service worker that persistently caches confidential document bytes.

### Tests

Test valid rendering, page navigation, range requests, unauthorized preview requests, expired sessions, disabled accounts, viewer errors, watermark identity, and absence of normal download controls.

### Acceptance criteria

Authorized users can view supported documents without ordinary download or print controls. Access is still protected by the backend, and residual extraction risks are documented.

## Segment 06: Authorization enforcement and session security

# Segment 06: Authorization and Access-Control Hardening

Conduct a focused security pass across all application routes, especially document endpoints.

### Tasks

1. Inventory every endpoint that returns documents, previews, thumbnails, metadata, search results, or exports.
2. Create a centralized authorization service or consistent policy layer.
3. Ensure every document request checks the authenticated principal and current access permissions.
4. Verify folder inheritance and explicit permission overrides behave according to the specification.
5. Prevent insecure direct-object reference vulnerabilities.
6. Verify that moving a document to a restricted folder immediately affects access.
7. Verify that revoked permissions affect subsequent requests without waiting for a long-lived signed URL to expire.
8. Apply consistent authorization to HEAD requests, range requests, alternate formats, thumbnails, and conversion outputs where supported.
9. Ensure administrative endpoints enforce both authentication and the correct role.
10. Review CSRF protection, session rotation, session expiry, logout, account disablement, and password reset behavior.
11. Add appropriate controls against brute force, enumeration, and abusive request patterns.
12. Review cross-origin policies and restrict origins where appropriate.
13. Ensure error messages reveal no secrets or unauthorized metadata.

### Adversarial tests

Create two users with deliberately different permissions. Attempt to access one user's documents as the other user by changing every relevant identifier.

Test direct endpoints, nested folders, thumbnails, range requests, metadata APIs, search, disabled accounts, revoked permissions, and expired sessions.

Test attempts to elevate privileges through modified form fields, API payloads, or manually constructed requests.

### Acceptance criteria

No protected document endpoint relies on obscurity, frontend visibility, or a previously checked UI state as its authorization mechanism.

Every unauthorized access test is rejected. Any failed security test must be fixed and rerun before proceeding.

## Segment 07: Administration, audit and retention

# Segment 07: Administration and Governance

Build the administration features required for an office document portal.

### User management

- Create, disable, and reactivate accounts.
- Assign approved roles.
- Reset credentials through a secure process.
- Review and revoke sessions where supported.
- Prevent administrators from accidentally granting inappropriate privileges.
- Protect high-impact administrative actions with reauthentication or additional controls where appropriate.

### Document management

- Upload documents.
- Organize folders and categories.
- Assign and review access permissions.
- Replace document versions with appropriate history.
- Archive and delete documents according to approved policy.
- Display processing and scanning status.
- Prevent unauthorized users from modifying metadata or document content.

### Audit dashboard

Record and make searchable relevant events such as:

- Successful and failed logins
- Document views and access denials
- Uploads, replacements, and deletions
- Permission changes
- Account creation, disabling, and role changes
- Administrative actions
- Backup and restore operations where operationally appropriate

Use timestamps, actor identifiers, target identifiers, event types, and outcomes.

Protect logs from ordinary user modification. Restrict access to audit records and avoid logging document contents, passwords, tokens, or unnecessary sensitive information.

### Retention

Implement configurable retention only after SSDC approves the relevant rules. Preserve required audit evidence while applying approved retention and deletion procedures.

### Acceptance criteria

Administrators can manage the portal through a controlled interface. Every important administrative operation is authorized and auditable. Audit data cannot be casually modified by ordinary staff. Retention and deletion behavior is documented and tested.

## Segment 08: Production security hardening

# Segment 08: Production Security Hardening

Review the application as a production system rather than a development demonstration.

### Application and HTTP configuration

- Disable Django debug mode in production.
- Restrict allowed hosts.
- Configure secure session and CSRF cookies.
- Enable HTTPS and appropriate HSTS after confirming the HTTPS deployment is correct.
- Configure Content Security Policy and other relevant browser security headers.
- Review MIME-sniffing protections, framing restrictions, referrer policy, and permitted cross-origin behavior.
- Apply secure cookie, session expiry, and CSRF settings.
- Remove development routes, sample credentials, debug pages, and unnecessary services.

### Infrastructure

- Run services with least privilege.
- Avoid running application processes as root.
- Restrict database network access.
- Keep private files outside public web roots.
- Limit container capabilities and resource consumption.
- Separate development and production secrets.
- Restrict administrative access.
- Keep dependencies and base images patched.
- Configure log rotation and disk-space monitoring.

### Application security

- Run dependency and vulnerability scans.
- Review all file-upload and conversion paths.
- Review query construction, template rendering, and exception handling.
- Ensure API and document endpoints have reasonable rate limits.
- Ensure temporary files are cleaned up.
- Ensure error responses do not disclose internal paths or secrets.
- Review caching of sensitive responses.
- Review account recovery and MFA recovery procedures.

### Acceptance criteria

The production configuration passes the agreed security checks, and deployment documentation clearly identifies required secrets, external services, firewall rules, and operational responsibilities.

Document any remaining high-risk findings. Do not declare production readiness while critical issues remain unresolved.

## Segment 09: Automated testing and security verification

# Segment 09: Test and Verify the Complete Product

Create a comprehensive test suite for the application built so far.

### Automated test categories

1. Unit tests for authorization rules, file validation, metadata, and business logic.
2. Integration tests for PostgreSQL, storage, upload processing, and document delivery.
3. Authentication tests for sessions, password changes, account disablement, MFA, and throttling.
4. Authorization tests covering every role and document permission combination.
5. Upload tests for malformed files, oversized requests, suspicious names, and content-type mismatches.
6. Viewer tests for PDF pages, range requests, image rendering, and watermarking.
7. Browser tests for login, navigation, search, list/gallery views, and access-denied states.
8. Security tests for XSS, CSRF, injection, ID manipulation, path traversal, and privilege escalation.
9. Operational tests for backups, restoration, health checks, and service restart behavior.

### Adversarial test scenarios

- An unauthenticated visitor requests a document URL directly.
- A staff member changes a document ID in a request.
- A user with access to one folder attempts to access a neighboring folder.
- A disabled user reuses an old session.
- A user attempts to obtain an unauthorized thumbnail or partial PDF response.
- A malicious upload attempts to exploit filename, MIME-type, or content-validation assumptions.
- A user submits HTML or script content through filenames or metadata.
- An ordinary staff member attempts to change their role.
- A large upload or repeated request attempts to exhaust application resources.

### Verification rules

- Run tests against a dedicated test environment and test data.
- Do not use production credentials or actual confidential SSDC documents.
- Never weaken access controls simply to make tests pass.
- Report skipped tests and explain why they were skipped.
- Distinguish automated test coverage from a genuine penetration test.
- Fix discovered defects and rerun the affected tests.

### Acceptance criteria

Produce a test report with actual results, known gaps, unresolved findings, and recommendations. No critical authorization or data-exposure issue may remain unresolved before production deployment.

## Segment 10: Deployment, backups and operations

# Segment 10: Production Deployment

Prepare a reproducible deployment for the SSDC environment approved by the organization.

### Deployment requirements

1. Document server prerequisites and supported operating systems.
2. Configure DNS and HTTPS.
3. Configure the reverse proxy and application server.
4. Configure PostgreSQL with restricted network access.
5. Configure private file storage and filesystem permissions.
6. Configure secrets through an appropriate environment or secret-management mechanism.
7. Configure migrations and a safe release procedure.
8. Establish a dedicated operational account with limited privileges.
9. Configure health checks and monitoring without exposing confidential data.
10. Configure log rotation, disk alerts, resource limits, and dependency updates.
11. Establish encrypted backups for database records and document storage.
12. Restrict backup access and protect encryption keys separately.
13. Document and test restoration, including consistency between database metadata and stored files.
14. Document incident response, credential revocation, security updates, and rollback procedures.

### Deployment testing

- Restart services and verify recovery.
- Confirm HTTPS and production security headers.
- Confirm database and file storage are not publicly accessible.
- Verify no secrets are committed to the repository or embedded in frontend assets.
- Restore a test backup and validate document integrity.
- Verify access logs and alerts work.
- Test loss of a database connection and temporary storage failure.
- Confirm deployment uses supported, patched dependencies.

### Acceptance criteria

A trained operator can deploy, update, monitor, back up, restore, and troubleshoot the application using the documentation.

Do not upload real confidential records until SSDC approves the environment and the required security review is complete.

## Segment 11: Independent review and release approval

# Segment 11: Pre-Production Security Review

Act as a skeptical security reviewer. Do not assume the application is secure because previous development segments passed.

### Review scope

1. Inspect authentication, authorization, session handling, and MFA.
2. Trace every document access path from the browser to storage.
3. Verify permissions are checked for every request.
4. Review upload validation, file conversion, and malware-scanning integration.
5. Check for direct file exposure and insecure storage permissions.
6. Review dependencies and configuration for known vulnerabilities.
7. Review CSRF, XSS, injection, path traversal, request forgery, and denial-of-service risks.
8. Review caching, watermarks, document extraction risks, and viewer limitations.
9. Review logging, audit integrity, secrets management, backups, and restoration.
10. Test administrative privilege boundaries and account revocation.
11. Review operational documentation and incident-response procedures.
12. Identify gaps that automated tests cannot establish.

### Deliverables

Create `docs/SECURITY_REVIEW.md` containing:

- Review scope and methodology
- Findings with severity and supporting evidence
- Reproduction steps for confirmed findings
- Affected components
- Remediation recommendations
- Verification results after fixes
- Residual risks and organizational decisions required
- Explicit limitations of the review

Do not claim that an automated review replaces independent penetration testing.

### Release criteria

The application must not be recommended for production use while critical or high-risk findings remain unresolved. Confirm that remaining risks have been documented and formally accepted by the responsible SSDC personnel.

End with a clear release recommendation: blocked, conditionally ready, or ready for the next formal approval stage. A coding agent cannot grant organizational approval on SSDC's behalf.

## The workflow to follow with your coding agent

Use this sequence for every segment:

1\. Submit the segment prompt

Keep the master instructions in the agent's context.

2\. Let the agent implement and test

Require actual commands, results, and fixes.

3\. Review and commit

Review the diff, check for secrets, and create a Git commit after the segment passes.

4\. Update progress

Require `docs/PROGRESS.md` to record completed work, test results, unresolved issues, and the next segment.

Important: Do not let the agent jump straight to deployment. The most consequential part is enforcing access control on every document request, not making the interface look polished. Get that right before putting real SSDC records into the system.

---

## 5. User

okay we are building this, what do you need before starting this off?

## 6. Assistant

*[Exact reply unavailable in the accessible conversation context.]*

## 7. User

can u give me the entire conversation between us (in this dialog) in a .md file

