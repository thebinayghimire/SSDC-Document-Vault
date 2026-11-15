# SSDC DOCUMENT VAULT
## Staff Self-Registration, Email Verification & Administrator Approval

**Implementation target:** Existing SSDC Document Vault repository  
**Primary stack:** Django 5.2, Python 3.13, PostgreSQL 16  
**Primary application:** `accounts`  
**Supporting applications:** `audit`, `config`  
**Implementation approach:** Incremental, backward-compatible, security-first

---

# 1. MISSION

Implement a complete staff self-registration and administrator approval workflow in the existing SSDC Document Vault.

The application currently has two distinct portals:

1. Administrator portal
2. Staff portal

Preserve both portals, their existing responsibilities, their visual identity, and their security boundaries.

The new requirement is to allow someone to create a staff account independently, verify their email address using a one-time password (OTP), and submit a request to become an authorized SSDC staff member.

An administrator must explicitly approve that request before the applicant can access the staff portal.

**The applicant must NEVER receive staff portal access simply by registering, verifying an email, or possessing a password. Administrator approval is mandatory.**

This is an extension of the existing application, not an authentication-system replacement.

# 2. NON-NEGOTIABLE ENGINEERING RULES

Before implementation, follow these rules.

1. Do not rewrite the existing authentication architecture.
2. Do not replace the custom `accounts.User` model.
3. Do not remove or weaken existing TOTP MFA.
4. Do not change the administrator login workflow.
5. Do not remove existing Staff ID login compatibility.
6. Do not change existing document permissions, folder grants, or RBAC behavior.
7. Do not change document storage, Google Drive integration, upload processing, PDF viewing, or document lifecycle functionality.
8. Do not weaken session security, CSRF protection, account revocation, or rate limiting.
9. Do not introduce a new authentication provider.
10. Do not introduce unnecessary dependencies.
11. Do not make destructive database migrations.
12. Do not modify production data or production environment settings during development.
13. Do not commit directly to `main`.
14. Do not claim a phase is complete without executing and reporting its tests.
15. Preserve English and Nepali language support.
16. Preserve the existing design system. New pages must look native to the application.

Before editing anything, inspect the current Git state and create a dedicated feature branch.

Recommended branch:

`feature/staff-registration-approval`

Record the starting commit SHA.

If the working tree contains existing uncommitted changes, preserve them. Never discard or overwrite them.

# 3. REQUIRED USER WORKFLOW

## A. Staff portal landing and authentication

The staff authentication interface must provide two clear options:

- Login
- Register

The administrator portal must remain separate.

The registration option must not appear as an administrator registration option.

## B. Staff registration

The applicant enters:

- Email address
- Password
- Confirm password

No administrator privileges, roles, permissions, Staff ID, or account activation status may be selected by the applicant.

Validate the submitted information on the server.

Requirements:

- Normalize email addresses consistently.
- Validate email syntax.
- Prevent duplicate accounts using case-insensitive email comparison.
- Apply the existing password validation policy.
- Use Django's password hashing.
- Never store plaintext passwords.
- Apply rate limiting to registration attempts.
- Return safe, understandable validation messages.
- Prevent concurrent duplicate registration.

For newly registered users, generate an internal unique username without requiring the applicant to invent a Staff ID.

Preserve the existing username field and existing administrator-created accounts.

Do not make email the new database primary key.

## C. Email OTP verification

After successful registration:

1. Create the account in an inactive state.
2. Create a registration request with the status `EMAIL_PENDING`.
3. Generate a cryptographically secure six-digit OTP.
4. Send the OTP to the submitted email address.
5. Display an OTP verification screen.
6. Allow the applicant to submit the OTP.
7. Verify the code on the server.
8. Mark the email as verified.
9. Move the request to `PENDING_REVIEW`.

Only successful verification can move an application into the administrator review queue.

### OTP security requirements

- OTP must expire after 10 minutes.
- OTP must be stored as a secure hash or keyed digest, never plaintext.
- Store an expiry timestamp.
- Store an attempt counter.
- Limit verification attempts.
- Apply resend cooldowns.
- Apply IP-based and account-based rate limits.
- Invalidate previously issued codes when a new code is issued.
- Prevent code replay.
- Prevent concurrent verification from accepting the same code twice.
- Never include OTP values in application logs or audit records.
- Never expose OTP values in URLs.
- Never expose whether an arbitrary email address already has an account through distinguishable public responses.

A reasonable initial policy is:
- 6-digit code.
- 10-minute validity.
- Maximum 5 verification attempts.
- 60-second resend cooldown.
- Maximum 5 OTP sends per account per hour.

Make these limits centrally configurable rather than scattering hardcoded values throughout views.

The OTP must be exclusively for email ownership verification. It must not replace or modify the existing TOTP authenticator MFA implementation.

## D. Waiting for administrator approval

After successful email verification, display a dedicated application-status page.

Suggested content:

**Your email has been verified.**

Your request has been submitted successfully and is waiting for administrator approval.

You will receive an email notification when your request has been reviewed.

The applicant must not be authenticated into the staff portal.

The applicant must not access:

- `/staff/`
- `/`
- `/library/`
- `/documents/`
- Document previews
- Document thumbnails
- Document content
- Management pages
- Administrative pages
- Any other protected application endpoint

A pending applicant is not an authenticated staff member.

The status page should be accessible through a secure, narrowly scoped mechanism. Do not use an unrestricted user ID or an easily guessable application number as authorization.

The applicant should also be able to return later and check their application status securely.

## E. Administrator approval interface

Extend the existing administrator interface.

Do not create a second independent administrator authentication system.

Add a clearly organized section:

**Staff Registration Requests**

Display requests with:

- Applicant email
- Registration date
- Email verification status
- Application status
- Review status

Provide filters for:

- Pending review
- Approved
- Declined

Only verified, pending requests should appear in the actionable approval queue.

Each request must provide two explicit actions:

1. Approve
2. Decline

These actions must be protected by:
- Existing administrator authentication.
- Existing administrator MFA requirements.
- Existing recent-reauthentication requirements.
- CSRF protection.
- POST-only requests.
- Server-side authorization.
- Transactional database updates.

Never trust the frontend to determine whether someone is an administrator.

### Approval behavior

When an administrator approves a request:

1. Lock the registration request and associated user row.
2. Confirm that the request is still pending review.
3. Confirm that the email was verified.
4. Confirm that the user account is still inactive and eligible.
5. Assign the normal `STAFF` role.
6. Keep `is_superuser=False`.
7. Keep Django's `is_staff` privilege disabled unless a separate, explicitly justified administrative requirement exists.
8. Activate the account.
9. Update the application status to `APPROVED`.
10. Record the reviewing administrator and review timestamp.
11. Create an audit event.
12. Create an approval notification.
13. Commit the transaction.

Only after successful approval may the user sign in.

Approval must be idempotent. Repeated requests must not grant additional privileges, create duplicate notifications, or produce inconsistent account state.

### Decline behavior

When an administrator declines a request:

1. Lock the request and account.
2. Confirm the request is still pending review.
3. Set the application status to `DECLINED`.
4. Keep the account inactive.
5. Record the administrator who declined it.
6. Record the review timestamp.
7. Record the decision in the audit log.
8. Create a decline notification.

A declined applicant must not receive access to the staff portal.

A declined request must not be approvable through a stale browser page or a replayed request.

Do not delete the applicant's account automatically.

Provide a clear policy for whether a declined applicant may submit a fresh application. Implement that policy explicitly rather than accidentally allowing duplicate accounts.

# 4. EMAIL NOTIFICATION SYSTEM

Two mandatory transactional emails are required.

## Email 1: Registration verification

Recipient: Applicant

Subject:

`Verify your email - SSDC Document Vault`

Contents:

- SSDC branding.
- Explanation that a registration request was initiated.
- Six-digit OTP.
- Expiration time.
- Security warning not to share the OTP.
- Instructions if the recipient did not initiate the request.

Do not include passwords, authentication secrets, or unnecessary personal information.

## Email 2: Administrator approval

Recipient: Applicant

Subject:

`Your SSDC Document Vault access has been approved`

Contents:

- SSDC branding.
- Confirmation that the application was approved.
- Confirmation that the account is now authorized for staff access.
- A direct link to the staff login page.
- Instructions to sign in using their registered email and password.

Send this notification only after the approval transaction commits successfully.

Also send a clear notification if an application is declined.

## Reliable delivery

Inspect the existing email configuration before introducing one.

Configure Django's email backend using environment variables or mounted secrets.

Do not hardcode SMTP credentials.

Use TLS where supported.

Do not assume that an email was delivered simply because a request to send it was made.

Implement a durable notification/outbox mechanism if the existing application does not already have one.

The approval transaction should create its notification record atomically with the approval.

Attempt immediate delivery after commit, and retain failed notifications for safe retry.

Provide a management command or equivalent operational mechanism to retry pending notifications.

Avoid introducing Celery or another background-processing platform unless the existing infrastructure genuinely requires it.

A temporary SMTP failure must not roll back an otherwise valid administrator approval or leave the account in an ambiguous state.

# 5. ACCOUNT AND DATABASE ARCHITECTURE

First inspect the existing model and migration history.

Do not assume that a new field on `User` is the best solution.

Prefer a separate registration-request model to avoid mixing application workflow state with authentication state.

A suggested model:

`StaffRegistrationRequest`

Possible fields:

- `id`
- `user` - OneToOne relationship with the custom User model
- `status`
- `email_verified_at`
- `otp_digest`
- `otp_expires_at`
- `otp_attempts`
- `otp_sent_at`
- `reviewed_by`
- `reviewed_at`
- `created_at`
- `updated_at`

Suggested statuses:

- `EMAIL_PENDING`
- `PENDING_REVIEW`
- `APPROVED`
- `DECLINED`
- `EXPIRED`

These are workflow states, not Django authentication roles.

Add any required fields for notification delivery or verification security based on the existing architecture.

Database constraints must prevent invalid states and duplicate active registration requests.

Use database-level uniqueness where appropriate.

For email uniqueness, inspect existing account data first. Existing administrator-created accounts may contain blank or duplicate email values. Do not add an unconditional uniqueness constraint without a safe data audit and migration strategy.

For newly registered accounts, enforce normalized, case-insensitive email uniqueness.

Use proper Django migrations.

Migrations must be backward-compatible with existing accounts and must not silently deactivate existing staff, managers, or administrators.

# 6. LOGIN COMPATIBILITY

The existing login flow uses `staff_id` and password.

Newly registered staff must be able to log in using their registered email address and password.

Implement this without breaking existing Staff ID authentication.

Recommended behavior:

- Existing staff and manager accounts can continue using their Staff ID.
- New self-registered accounts can use their email address.
- Existing administrators continue using their administrator ID.
- The server resolves identities safely.
- Account status and active status are always checked against current database state.
- Pending and declined accounts are always denied.
- No role or portal privileges are accepted from submitted form values.

The staff login form should clearly explain that either an email address or an existing Staff ID can be used.

Do not allow email-based login to bypass the current password authentication, MFA, session creation, or session-revocation logic.

Do not create a parallel login implementation that bypasses `finish_login()`.

Integrate the new identity resolution into the existing sign-in path.

The administrator portal must remain administrator-only.

# 7. SECURITY AND AUTHORIZATION

This is an institutional document repository. Treat account registration as a security-sensitive feature.

The following rules are mandatory:

### Authorization

- Only active, approved accounts may authenticate.
- A pending application cannot authenticate.
- A declined application cannot authenticate.
- Email verification alone never grants access.
- Only an authorized administrator can approve or decline.
- A staff applicant cannot modify their own role or approval status.
- An approved staff member receives only the existing normal staff role.
- Existing folder and document grants remain independently enforced.

### Session security

Continue using:

- Existing `auth_version`.
- Existing session expiry.
- Existing idle timeout.
- Existing session revocation.
- Existing MFA enforcement.
- Existing `SessionPolicyMiddleware`.

Approval and decline operations must not bypass the current session policy.

Any security-sensitive account change must use the established locking and authorization-version conventions where applicable.

### Concurrency

Consider these cases:

- Two administrators approve the same request simultaneously.
- One administrator approves while another declines.
- An applicant verifies an OTP while another request resends it.
- An OTP expires while it is being verified.
- A pending request is modified while an administrator reviews it.
- An administrator disables an account while an applicant attempts to sign in.
- Two registrations attempt the same email simultaneously.

Use database transactions, row locks, uniqueness constraints, and conditional updates to prevent inconsistent states.

### Audit logging

Use the existing `audit.services.record()` mechanism.

Add clear events, such as:

- `staff_registration_started`
- `staff_email_verified`
- `staff_registration_submitted`
- `staff_registration_approved`
- `staff_registration_declined`
- `staff_registration_expired`
- `staff_approval_email_sent`
- `staff_approval_email_failed`

Use the existing supported audit-detail schema. Extend it deliberately if new fields are necessary.

Never log passwords, raw OTPs, OTP hashes, session identifiers, or other secrets.

# 8. UI/UX REQUIREMENTS

Preserve the current visual design.

Do not redesign the entire application.

The new pages should reuse:

- Existing `base.html`.
- Existing authentication-card layout.
- Existing typography and spacing.
- Existing button styles.
- Existing form components.
- Existing icons.
- Existing responsive behavior.
- Existing language selector.
- Existing notification and message conventions.

Required new screens:

1. Staff registration.
2. Email OTP verification.
3. Registration submitted / waiting for approval.
4. Registration declined.
5. Registration expired or resend verification.
6. Administrator registration-request list.
7. Administrator registration-request detail or review screen.

Design requirements:

- Clear form labels.
- Accessible error messages.
- Visible OTP expiration guidance.
- Disabled or loading states during submission.
- Clear success and failure feedback.
- No unnecessary animations.
- No confusing redirects.
- No exposure of sensitive registration information.

The existing login screen must provide a Register link for the staff portal.

The admin login screen must not offer public administrator registration.

Translate all new user-facing strings into English and Nepali.

Update translation catalogues and compile translations as required.

# 9. IMPLEMENTATION PHASES

Do not implement everything in one pass.

Each phase must end with tests, a code review, and a written report.

## PHASE 0 - REPOSITORY DISCOVERY AND BASELINE

Inspect:

- `accounts/models.py`
- `accounts/views.py`
- `accounts/forms.py`
- `accounts/urls.py`
- `accounts/navigation.py`
- `accounts/mfa.py`
- `accounts/admin.py`
- `audit/models.py`
- `audit/services.py`
- `config/settings.py`
- `config/urls.py`
- `config/admin.py`
- `config/middleware.py`
- Existing authentication templates.
- Existing authentication and administration tests.
- Existing migration history.
- Existing email-related configuration.

Run the existing test suite and relevant quality checks.

Record the baseline.

Deliverables:
- Source dependency map.
- Proposed database changes.
- Existing behavior that must remain unchanged.
- Test baseline.
- Risk assessment.

Do not implement features during this phase.

## PHASE 1 - DATABASE AND REGISTRATION STATE

Implement the registration-request model and migrations.

Requirements:
- Preserve the existing User model.
- Preserve existing accounts.
- Add explicit workflow states.
- Add database constraints.
- Handle normalized email uniqueness safely.
- Add reviewer and timestamp tracking.
- Add notification persistence if required.

Tests:
- New request creation.
- Duplicate registration prevention.
- Case-insensitive email uniqueness.
- Existing accounts remain intact.
- Migration succeeds on a database containing existing accounts.
- Invalid status transitions are rejected.

Do not add public registration views yet.

## PHASE 2 - REGISTRATION AND EMAIL OTP

Implement:

- Registration form.
- Password validation.
- Safe user creation.
- OTP generation.
- OTP digest storage.
- Email delivery.
- OTP verification.
- OTP expiry.
- Resend cooldown.
- Attempt limits.
- Rate limiting.
- Registration status transitions.

Tests:
- Valid registration.
- Invalid email.
- Weak password.
- Password mismatch.
- Duplicate email.
- OTP delivery.
- Valid OTP.
- Incorrect OTP.
- Expired OTP.
- Replayed OTP.
- Replaced OTP.
- Excessive attempts.
- Resend throttling.
- Concurrent duplicate registration.
- SMTP failure.
- No accidental authentication.

At the end of this phase, a verified applicant must remain unauthenticated and inactive.

## PHASE 3 - ADMINISTRATOR REVIEW AND APPROVAL

Integrate the registration queue into the existing administrator interface.

Implement:
- Pending request list.
- Request detail.
- Approve action.
- Decline action.
- Reviewer attribution.
- Review timestamp.
- Transactional state changes.
- Audit records.
- Approval and decline notifications.

Tests:
- Authorized administrator can review.
- Non-administrator cannot review.
- Anonymous user cannot review.
- GET requests cannot perform approval or decline.
- CSRF protection works.
- Approval activates the correct account.
- Approval assigns only the staff role.
- Approval never grants administrator privileges.
- Decline keeps the account inactive.
- Double approval is safe.
- Simultaneous approval and decline cannot produce conflicting outcomes.
- Stale review pages cannot overwrite completed decisions.
- Email delivery failure does not corrupt approval.

## PHASE 4 - EMAIL LOGIN COMPATIBILITY

Integrate email login into the existing sign-in implementation.

Preserve:
- Existing Staff ID login.
- Existing administrator login.
- Existing manager login.
- Existing TOTP MFA.
- Existing recovery codes.
- Existing password hashing.
- Existing session lifecycle.
- Existing login throttling.
- Existing portal redirects.

Tests:
- Approved staff can log in using email.
- Approved staff can still use an existing Staff ID where applicable.
- Existing staff accounts still log in.
- Administrators still log in using their existing credentials.
- Managers still log in.
- Pending accounts cannot log in.
- Declined accounts cannot log in.
- Inactive accounts cannot log in.
- Staff cannot enter the administrator portal.
- Administrator cannot be misclassified as staff.
- Login cannot bypass MFA.

Do not create a second independent authentication pipeline.

## PHASE 5 - FRONTEND AND USER EXPERIENCE

Implement the registration and status screens.

Update the existing staff login screen with Login and Register navigation.

Add administrator review UI.

Preserve existing design and responsive behavior.

Complete English and Nepali translations.

Test:
- Template rendering.
- Form validation feedback.
- Mobile layout.
- Keyboard navigation.
- Screen-reader labels.
- Error states.
- Success states.
- OTP expiry.
- Registration status display.
- Admin queue usability.
- Existing portal navigation.

## PHASE 6 - SECURITY AND REGRESSION TESTING

Perform a dedicated adversarial review.

Test:

1. Direct access to the staff portal with a pending account.
2. Direct access to the document library with a pending account.
3. Direct access to document preview endpoints.
4. Direct access to thumbnail endpoints.
5. Direct access to management endpoints.
6. Direct access to administrator endpoints.
7. Forged approval requests.
8. Forged decline requests.
9. Role escalation attempts.
10. Email enumeration.
11. OTP brute-force attempts.
12. OTP replay.
13. Session fixation.
14. CSRF bypass attempts.
15. Concurrent registration.
16. Concurrent approval and decline.
17. Account revocation during sign-in.
18. Email delivery interruption.
19. Database transaction rollback.
20. Existing authentication race-condition tests.

Run the entire existing regression suite, not just the new tests.

Existing security tests must remain passing.

Investigate every failure. Never remove, skip, weaken, or rewrite an existing test simply to obtain a passing result.

## PHASE 7 - FINAL REVIEW AND RELEASE

Before declaring completion:

- Review every changed file.
- Review every migration.
- Review authorization boundaries.
- Review email handling.
- Review audit events.
- Review transaction boundaries.
- Review database constraints.
- Review English and Nepali translations.
- Review responsive UI.
- Review all test results.
- Review deployment configuration.

Run:
- Full pytest suite.
- Ruff lint.
- Ruff format check.
- Django system checks.
- Migration consistency checks.
- Existing release checks where applicable.

Produce a final report containing:

1. Features implemented.
2. Files changed.
3. Migrations created.
4. New environment variables.
5. Email configuration instructions.
6. New management commands.
7. Test results.
8. Security review results.
9. Remaining risks.
10. Deployment instructions.
11. Rollback instructions.

Do not deploy to production or modify real SSDC accounts without explicit authorization.

# 10. ACCEPTANCE CRITERIA

The feature is complete only when all the following conditions hold.

| Requirement | Expected result |
|---|---|
| Staff registration | Public registration is available |
| Email verification | OTP is required |
| Email verification expiry | Expired OTP is rejected |
| Admin approval | Explicit approval is mandatory |
| Admin decline | Explicit decline is supported |
| Pending access | No staff portal access |
| Declined access | No staff portal access |
| Approved access | Staff login is enabled |
| Email login | New staff can log in using email |
| Legacy login | Existing Staff ID login remains functional |
| Admin security | Existing administrator security remains intact |
| MFA | Existing TOTP and recovery flows remain intact |
| RBAC | Existing role and folder grants remain intact |
| Audit | Registration and review events are recorded |
| Email reliability | Failed notifications can be retried |
| Database safety | Existing accounts and data are preserved |
| UI | Existing design system is preserved |
| Localization | English and Nepali are supported |
| Regression | Existing tests remain passing |

# 11. REQUIRED FINAL USER JOURNEY

The final behavior must look like this:

```text
STAFF PORTAL
    |
    +---- LOGIN
    |       |
    |       +---- Existing Staff ID + Password
    |       |
    |       +---- Registered Email + Password
    |       |
    |       +---- Existing MFA checks where required
    |       |
    |       +---- Approved and Active?
    |                 |
    |                 +---- YES --> STAFF PORTAL
    |                 |
    |                 +---- NO  --> ACCESS DENIED
    |
    +---- REGISTER
            |
            +---- Email + Password + Confirm Password
            |
            +---- Create Inactive Account
            |
            +---- Send Email OTP
            |
            +---- Verify OTP
            |
            +---- Submit Registration Request
            |
            +---- WAITING FOR ADMIN APPROVAL
                      |
                      +---- ADMIN APPROVES
                      |        |
                      |        +---- Activate Staff Account
                      |        |
                      |        +---- Send Approval Email
                      |        |
                      |        +---- Staff Can Log In
                      |
                      +---- ADMIN DECLINES
                               |
                               +---- Keep Account Inactive
                               |
                               +---- Send Decline Email
```

# 12. INSTRUCTIONS TO DEEPSEEK

Work as a senior Django security engineer.

Prioritize correctness, backwards compatibility, and maintainability over speed.

Do not assume the existing implementation is incorrect just because it differs from your preferred architecture.

Read the relevant source before making each change.

Use the smallest safe change that achieves the requirement.

Keep business logic out of templates.

Keep authorization checks on the server.

Use database constraints as well as application validation.

Do not trust user-supplied roles, IDs, statuses, or approval flags.

Do not implement the entire feature in one response.

Complete one phase at a time.

At the end of each phase, report:

- What changed.
- Why it changed.
- Which files were modified.
- Which migrations were created.
- Which tests were executed.
- Exact test results.
- Security considerations.
- Any unresolved issues.

Stop if a phase reveals an architectural conflict, migration risk, security regression, or failing existing test that cannot be explained.

Do not silently make architectural decisions that change the intended behavior.

Do not proceed to the next phase until the current phase has been reviewed and its acceptance criteria have been met.

**Final objective: a smooth, reliable, secure staff registration and approval experience that fits naturally into the existing SSDC Document Vault without damaging any existing functionality.**