# Final Report: Staff Self-Registration, Email OTP Verification, and Administrator Approval

**Branch:** `phase3/staff-registration-review`  
**Branch base:** `886c4809b185f3e60300a8dfdbf4c90fa421b55a`  
**Status:** implementation complete; all automated checks pass; **not committed and not deployed**  
**Date:** 17 November 2026

---

## 1. Features Implemented

### 1.1 Public staff registration

- Public registration form at `/accounts/register/` with email, password, and confirmation.
- Registration is gated by `STAFF_SELF_REGISTRATION_ENABLED` (default `0`); the route returns the existing unavailable response while disabled.
- Creates an inactive, non-staff, non-superuser applicant account with an unusable password and a reserved normalized email claim.
- Password is validated with Django's configured validators and staged as a hash until approval. The applicant cannot authenticate before approval.
- Per-IP and per-email registration rate limits are enforced.
- Duplicate or already-existing addresses receive the same generic "check your email" response as a new registration. No token, session binding, account status, or application status is exposed.

### 1.2 Mandatory email OTP verification

- Six-digit OTP, valid for **10 minutes**, maximum **5 attempts**, **60-second resend cooldown**, and **5 sends per hour**.
- OTP is generated with a cryptographically secure random source, bound to the registration purpose/ID, stored only as an HMAC digest, and encrypted in the email outbox payload.
- OTP comparison is constant-time; a successful verification is single-use and moves the application to `pending_review`.
- A failed fifth attempt locks the code. Replaced/expired codes are rejected.
- Verification requires the OTP. **Opening an emailed link alone never marks an email verified.**
- Email-only OTP entry is rate-limited and returns generic feedback, so it cannot be used as an application-state oracle.

### 1.3 Secure link tokens

- Links use a database-backed random token; only its SHA-256 hash is stored.
- Tokens expire after **24 hours**, are single-use, and are superseded when a newer link is issued.
- A link proves mailbox control only. It is used to open the OTP form and to bind a status page to a server-side session; it is not a verification credential.
- Verified or decided applicants receive a `registration_status_link` email on resend/status lookup instead of an unusable OTP.
- Legacy signed-token routes are rejected with the generic invalid-link page.
- Status, resend, and verification responses are enumeration-safe. Status lookup never binds a session without mailbox proof.

### 1.4 Administrator review and decisions

- Django admin review queue with pending count, status badges, applicant email, verification state, password-staged flag, reviewer, and decision timestamp.
- **Approve** and **Decline** are POST-only and CSRF-protected. The admin site additionally requires administrator role, confirmed MFA where required, and reauthentication within 10 minutes.
- Decisions run in database transactions with row locks; stale approval/decline attempts cannot overwrite a newer decision.
- Approval is idempotent: repeated approval does not duplicate notifications or change state.
- Approval activates only the staff role (`is_active=True`, `is_staff=False`, `is_superuser=False`), assigns a generated `SSDC-######` Staff ID for self-registered applicants, and installs the staged password hash.
- Decline keeps the account inactive. An administrator may explicitly allow reapplication; only a declined application with that flag can be resubmitted.
- Reapplication reuses the applicant account and requires a fresh OTP.
- Every registration, verification, resend, approval, decline, reapplication grant, and expiry event is written to the existing audit log. Tokens and OTPs are never written to audit details.

### 1.5 Durable email delivery

- OTP, approval, decline, reapplication, expiry, status-link, and email-change messages are written to a durable `EmailNotification` outbox.
- Email delivery never runs inside the decision transaction: an SMTP failure cannot roll back an approval or decline.
- Retries use bounded exponential backoff, leases to prevent double sends, and a dead-letter state after the configured maximum attempts.
- Decision notifications supersede older undelivered messages for the same application.
- Failed/dead-letter messages can be requeued and retried with the new management command.

### 1.6 Login, security, and compatibility

- Approved self-registered staff can sign in with email + password; existing Staff ID + password login remains functional.
- Pending and declined applicants remain inactive and are denied protected endpoints.
- Existing TOTP MFA, recovery, role checks, folder grants, document permissions, admin workflow, and session policy are unchanged.
- Existing English and Nepali interfaces are preserved; all new strings are translated and the Nepali catalogue is compiled.

### 1.7 Lifecycle and operations

- Email-pending applications expire after **3 days**; pending-review applications expire after **30 days** (configurable).
- Expiry is idempotent, audited, notifies the applicant, and supports dry runs.
- Production Compose files now pass the registration/email flags, SMTP settings, `EMAIL_HOST_PASSWORD_FILE`, and `PUBLIC_BASE_URL` into the application container.
- Deployment documentation now covers enabling the feature, scheduling the outbox worker, and expiring stale applications.

---

## 2. Files Changed

### Core application

| File | Purpose |
|---|---|
| `accounts/models.py` | `StaffRegistrationRequest` constraints and `StaffRegistrationToken` (hashed, single-use, expiring) |
| `accounts/services/registration.py` | Registration, OTP issuance/verification, resend, status links, approval/decline, reapplication, expiry |
| `accounts/services/registration_tokens.py` | SHA-256 token storage, lookup, atomic consumption, verification/status URLs |
| `accounts/services/notifications.py` | Durable outbox, template/subject mapping, retries, leases, dead letters, status-link template |
| `accounts/services/email_claims.py` | Normalized email claim locking and conflict handling |
| `accounts/services/email_changes.py` | Email-change workflow compatibility with the outbox and notifications |
| `accounts/views.py` | Registration, tokenless/OTP verification, status, resend, email login integration |
| `accounts/urls.py` | Registration, tokenless verify, status, resend, and legacy-rejection routes |
| `accounts/admin.py` | Review queue, approve/decline/reapplication views, admin templates (from the Phase 3 implementation) |
| `accounts/management/commands/process_email_notifications.py` | Outbox delivery, dry run, dead-letter requeue |
| `accounts/management/commands/expire_staff_registrations.py` | Lifecycle expiry with dry run and base URL |
| `config/settings.py` | Feature flags, SMTP/password-file settings, OTP/outbox limits, `PUBLIC_BASE_URL` |
| `config/context_processors.py`, `config/middleware.py` | Existing feature-flag/UI support and cross-cutting request security |

### Templates and UI

- `templates/accounts/register.html`
- `templates/accounts/registration_submitted.html`
- `templates/accounts/registration_verify.html`
- `templates/accounts/registration_status.html`
- `templates/accounts/registration_status_lookup.html`
- `templates/accounts/registration_resend.html`
- `templates/accounts/registration_link_invalid.html`
- `templates/admin/accounts/staffregistrationrequest/change_list.html`
- `templates/admin/accounts/staffregistrationrequest/change_form.html`
- `templates/email/registration_otp.html` / `.txt`
- `templates/email/registration_status_link.html` / `.txt`
- `templates/email/registration_approved.html`
- `templates/email/registration_declined.html`
- `templates/email/registration_reapplication_allowed.html`
- `templates/email/registration_expired.html`
- `templates/email/email_change_otp.html` / `.txt` and related email-change notices
- `static/css/admin.css`, `static/css/app.css`, `static/js/session.mjs` (existing design/session work retained)

### Localization

- `locale/ne/LC_MESSAGES/django.po`
- `locale/ne/LC_MESSAGES/django.mo`

### Deployment and documentation

- `.env.example`
- `deploy/production.env.example`
- `compose.prod.yaml`
- `compose.pilot.yaml`
- `compose.oracle.yaml`
- `deploy/nginx.prod.conf`, `deploy/nginx.prod.conf.template`
- `scripts/production_smoke.py`
- `docs/DEPLOYMENT.md`

### Tests

- `tests/test_staff_registration_views.py`
- `tests/test_staff_registration_workflow.py`
- `tests/test_staff_registration_config.py`
- `tests/test_staff_registration_migration.py`
- `tests/test_staff_registration_admin.py`
- `tests/test_phase1_security.py`
- `tests/test_phase2_security.py`
- `tests/test_email_templates.py`
- `tests/test_email_changes.py`
- `tests/test_portals.py`
- `tests/test_accounts.py`
- `tests/test_password_only_login.py`
- `tests/test_render_deployment.py`
- `tests/test_ui.py`

The working tree also carries the previously reviewed cross-cutting security-hardening edits (secure cookie transport, session guard, proxy headers, branding). They were preserved and verified, not removed.

---

## 3. Migrations

No new migration was required in this pass. The feature depends on the existing additive migrations:

| Migration | Contents |
|---|---|
| `accounts/migrations/0002_staff_registration_core.py` | `EmailClaim`, `StaffRegistrationRequest`, status/OTP constraints, indexes |
| `accounts/migrations/0003_staff_registration_workflows.py` | `EmailChangeRequest`, `EmailNotification`, notification constraints and indexes |
| `accounts/migrations/0004_staffregistrationtoken.py` | `StaffRegistrationToken` with hashed token and expiry |

`python manage.py makemigrations --check --dry-run` reports **No changes detected**. All migrations are additive; no existing account or document table is rewritten or dropped.

---

## 4. New Environment Variables

| Variable | Default | Notes |
|---|---|---|
| `STAFF_SELF_REGISTRATION_ENABLED` | `0` | Public registration route |
| `EMAIL_LOGIN_ENABLED` | `0` | Email + password staff login |
| `SELF_REGISTERED_EMAIL_CHANGE_ENABLED` | `0` | Self-service email change |
| `EMAIL_DELIVERY_ENABLED` | `0` | Allow the outbox worker to send |
| `EMAIL_BACKEND` | locmem (settings), SMTP in Compose | Use `django.core.mail.backends.smtp.EmailBackend` for real delivery |
| `EMAIL_HOST` | `localhost` | SMTP host |
| `EMAIL_PORT` | `587` | SMTP port |
| `EMAIL_USE_TLS` | `1` | STARTTLS |
| `EMAIL_USE_SSL` | `0` | Implicit TLS; do not enable together with `EMAIL_USE_TLS` |
| `EMAIL_HOST_USER` | empty | SMTP username |
| `EMAIL_HOST_PASSWORD` | empty | SMTP password; prefer `EMAIL_HOST_PASSWORD_FILE` |
| `EMAIL_HOST_PASSWORD_FILE` | empty | Path to a mounted password secret |
| `EMAIL_FROM_ADDRESS` | `SSDC Document Vault <no-reply@localhost>` | From address |
| `EMAIL_TIMEOUT` | `10` | SMTP timeout in seconds |
| `PUBLIC_BASE_URL` | empty | Absolute origin used by command-generated links |
| `STAFF_REGISTRATION_OTP_MINUTES` | `10` | OTP lifetime |
| `STAFF_REGISTRATION_OTP_MAX_ATTEMPTS` | `5` | Attempts before lockout |
| `STAFF_REGISTRATION_OTP_RESEND_SECONDS` | `60` | Resend cooldown |
| `STAFF_REGISTRATION_OTP_HOURLY_LIMIT` | `5` | OTP emails per hour |
| `STAFF_REGISTRATION_IP_LIMIT` | `20` | Per-IP registration attempts per hour |
| `STAFF_REGISTRATION_EMAIL_EXPIRY_DAYS` | `3` | Email-pending lifetime |
| `STAFF_REGISTRATION_REVIEW_EXPIRY_DAYS` | `30` | Pending-review lifetime |
| `EMAIL_NOTIFICATION_MAX_ATTEMPTS` | `5` | Outbox attempts before dead letter |
| `EMAIL_NOTIFICATION_BACKOFF_BASE_SECONDS` | `60` | Initial retry delay |
| `EMAIL_NOTIFICATION_BACKOFF_MAX_SECONDS` | `3600` | Retry delay ceiling |
| `EMAIL_NOTIFICATION_LEASE_SECONDS` | `900` | Worker lease |

Keep `EMAIL_DELIVERY_ENABLED` at `0` until SMTP has been verified.

---

## 5. Email Configuration Instructions

1. Create a dedicated SMTP account/API key for the vault. Do not reuse a personal mailbox.
2. Set the SMTP host, port, TLS/SSL mode, username, from address, and either `EMAIL_HOST_PASSWORD` or a mounted `EMAIL_HOST_PASSWORD_FILE`.
3. Set `EMAIL_DELIVERY_ENABLED=1` only after the settings are present.
4. Keep the SMTP password out of source control and the image. On Compose, prefer a mounted secret and `EMAIL_HOST_PASSWORD_FILE`.
5. Run the outbox worker on a schedule (every minute):

```sh
docker compose --env-file .env.production -f compose.prod.yaml \
  run --rm app python manage.py process_email_notifications --limit 50
```

6. Check the summary line (`due=… recovered=… sent=… failed=…`). For a safe first run, use `--dry-run` to see how many messages are due.
7. Requeue exhausted messages after correcting SMTP:

```sh
docker compose --env-file .env.production -f compose.prod.yaml \
  run --rm app python manage.py process_email_notifications --requeue-dead-letter
```

8. Inspect failed/dead-letter rows before requeueing:

```sh
docker compose --env-file .env.production -f compose.prod.yaml \
  run --rm app python manage.py shell -c \
  "from accounts.models import EmailNotification; print(list(EmailNotification.objects.filter(status__in=['failed','dead_letter']).values('id','kind','recipient_email','attempts','last_error')))"
```

9. Run the expiry job daily:

```sh
docker compose --env-file .env.production -f compose.prod.yaml \
  run --rm app python manage.py expire_staff_registrations --limit 100 \
  --base-url https://vault.example.org
```

Both commands support `--dry-run`. A failed send leaves the approval/decline committed and the message queued; it is never rolled back.

---

## 6. New Management Commands

### `process_email_notifications`

```text
--limit N              Maximum messages to attempt (default 50)
--dry-run              Report due messages without sending or updating
--requeue-dead-letter  Reset all dead-letter rows to pending first
--requeue ID           Reset one failed/dead-letter ID; may be repeated
```

### `expire_staff_registrations`

```text
--limit N   Maximum applications to expire (default 100)
--dry-run   Report due applications without changing state
--base-url  Public origin for links in expiry notifications
```

---

## 7. Test Results

All commands were run against local PostgreSQL with `APP_ENV=test` and empty `DATABASE_URL`/`DATABASE_URL_UNPOOLED` overrides.

| Check | Result |
|---|---|
| Full pytest suite | **756 passed, 3 subtests passed, 0 failed, 0 skipped** in **216.79 s** |
| Ruff lint | **All checks passed** |
| Ruff format check | **186 files already formatted** |
| Django `check` | **No issues** |
| `makemigrations --check --dry-run` | **No changes detected** |
| Nepali catalogue | `msgfmt --check` OK; **0 untranslated** entries |
| Compose/deployment configuration | **35 passed** |

The earlier baseline failure (`test_resend_cooldown_and_earlier_token_invalidation`, caused by cooldown timing and earlier-token invalidation expectations) is resolved. The suite was re-run after the final settings and Compose edits.

`manage.py check --deploy` reports only the expected local-development warnings (`security.W004` HSTS, `security.W008` SSL redirect, `security.W009` development secret). Production supplies HSTS/TLS and generated secrets; these warnings are not suppressed or “fixed” by weakening configuration.

Targeted registration coverage includes:

- Duplicate registration non-disclosure and identical generic response.
- OTP-required verification; link alone does not verify.
- Tokenless session OTP entry.
- OTP replay, expiry, attempt lockout, cooldown, hourly cap, and earlier-token invalidation.
- Status lookup without session does not bind or reveal existence.
- Decided-email oracle resistance.
- Cross-device status link, generic expired/tampered/legacy token pages.
- Approval idempotency and stale approval/decline conflicts.
- Role escalation denial; only administrators may decide.
- Concurrent registration and concurrent OTP verification.
- Delivery failure does not roll back approval.
- Expiry dry run and lifecycle windows.
- Email template rendering in English and Nepali.

---

## 8. Security Review Results

| Area | Result |
|---|---|
| Pending/declined portal and document access | Denied; accounts remain inactive and existing permission checks run |
| Direct preview/thumbnail/management/admin endpoints | Existing authentication and authorization tests pass |
| Forged approval/decline | `require_POST`; CSRF; admin role + MFA + 10-minute reauthentication; row-locked transaction |
| Role escalation | Approval sets staff role only; `is_staff`/`is_superuser` are forced false |
| Email enumeration | Generic responses for duplicate registration, status lookup, and resend; constant-time dummy work; no status bound without mailbox proof |
| OTP brute force | 5 attempts, per-registration and per-IP limits, lockout, encrypted/hashed storage |
| OTP replay | Digest cleared under row lock; single-use; earlier code/link invalidated |
| Session fixation | Session is bound only after OTP or valid mailbox-link proof; existing session policy retained |
| CSRF | Django CSRF middleware; review endpoints are POST-only forms |
| Concurrent registration/approval | Email claim lock, unique active-registration constraint, `select_for_update` |
| Revocation during sign-in | Existing `auth_version`/session policy checks remain active |
| Email delivery interruption | Outbox decoupled from transactions; retries, leases, dead letters; approval survives SMTP failure |
| Database rollback | Decisions and audit records commit together; failures leave prior state intact |
| Token leakage | Raw tokens never stored; hashed only; status URLs tokenless; `Referrer-Policy: no-referrer` and private cache headers on registration pages |
| Audit integrity | Registration/review events recorded; test confirms tokens do not appear in audit events |

No production deployment or real SSDC account changes were performed. No manual penetration test or live SMTP deliverability test was performed in this environment.

---

## 9. Remaining Risks and Operational Notes

1. **SMTP deliverability** depends on the provider, sender reputation, SPF/DKIM/DMARC, and the scheduled outbox worker. Monitor dead letters and the worker summary.
2. **Outbox scheduling is external.** The application does not run a built-in scheduler. Configure cron/systemd (every minute) or the deployment will leave messages queued.
3. **`PUBLIC_BASE_URL` must be set** for command-generated links. Without it, expiry/admin links built outside a request are relative or empty.
4. **SMTP password exposure:** Compose supports an environment value for compatibility, but a mounted `EMAIL_HOST_PASSWORD_FILE` is preferred. Use a private operator environment and restrict file permissions.
5. **Localization maintenance:** JavaScript strings live in `static/js/*.mjs`. Django's default `makemessages` Python-domain extraction does not scan `.mjs`; the current `django.po` retains those entries and the JS catalogue test guards them. After any future `makemessages` run, re-run `tests/test_language_support.py` and restore/re-extract the `.mjs` strings before compiling.
6. **Email-claim change between registration and approval** is detected at approval and produces a conflict; the applicant must restart. This is intentional.
7. **Manual browser/accessibility and live email tests** remain a release activity; this pass verifies automated rendering, responsive CSS, and template compilation only.
8. **No commit or deployment** was made. The branch and working tree are left for review.

---

## 10. Deployment Instructions

1. **Back up** the database and private storage; review the release diff and run the full checks in CI.
2. **Apply migrations once** during maintenance:

```sh
docker compose --env-file .env.production -f compose.prod.yaml run --rm migrate
docker compose --env-file .env.production -f compose.prod.yaml run --rm migrate \
  python manage.py configure_runtime_role
```

3. **Configure the environment** in the private `.env.production`:

```dotenv
STAFF_SELF_REGISTRATION_ENABLED=1
EMAIL_LOGIN_ENABLED=1
SELF_REGISTERED_EMAIL_CHANGE_ENABLED=0   # enable only if approved
EMAIL_DELIVERY_ENABLED=1
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.example.org
EMAIL_PORT=587
EMAIL_USE_TLS=1
EMAIL_USE_SSL=0
EMAIL_HOST_USER=no-reply@example.org
# EMAIL_HOST_PASSWORD_FILE=/run/secrets/email_password
EMAIL_FROM_ADDRESS=SSDC Document Vault <no-reply@example.org>
PUBLIC_BASE_URL=https://vault.example.org
```

4. Build and replace the application/proxy images using the approved release process; keep the previous image for rollback.
5. Verify `manage.py check --deploy`, health checks, HTTPS, MFA, and an administrator login.
6. Schedule `process_email_notifications` every minute and `expire_staff_registrations` daily.
7. Smoke-test with a controlled mailbox (not a real SSDC staff account): register, receive OTP, verify, confirm the application appears in the admin queue, approve, sign in, and confirm the approval email.
8. Confirm a pending applicant is denied staff/document access before approval.
9. Monitor the outbox summary and audit events for the first registration/review cycle.

---

## 11. Rollback Instructions

**Fast rollback (recommended):**

1. Set `STAFF_SELF_REGISTRATION_ENABLED=0`, `EMAIL_LOGIN_ENABLED=0`, and `SELF_REGISTERED_EMAIL_CHANGE_ENABLED=0`.
2. Set `EMAIL_DELIVERY_ENABLED=0` to stop outbound mail.
3. Restart the application. Existing Staff ID login, MFA, admin, documents, and permissions continue to work; no schema rollback is required.
4. Preserve pending `EmailNotification` rows and audit records for investigation.

**Image rollback:**

1. Redeploy the previous pinned image digest.
2. Keep migrations `0002`–`0004` applied; they are additive and harmless to the previous application version.
3. Restore the database and private storage from the paired backup only if a destructive schema change or data corruption is confirmed. Do not reverse migrations casually: doing so drops registration/outbox tables and their audit context.
4. Re-run `configure_runtime_role` after any migration/restore operation and verify health, MFA, and denied cross-user access before restoring traffic.

No production system was modified during this work, so no live rollback was executed.

---

## 12. Acceptance Criteria

| Requirement | Result |
|---|---|
| Staff registration | Public registration available behind a feature flag |
| Email verification | OTP mandatory; link alone does not verify |
| OTP expiry | Expired code rejected and replaceable until application expiry |
| Admin approval | Explicit POST approval required |
| Admin decline | Supported with optional reapplication grant |
| Pending/declined access | Denied |
| Approved access | Staff login enabled with staged password and Staff ID |
| Email login | Enabled behind `EMAIL_LOGIN_ENABLED`; Staff ID login preserved |
| Admin security | Existing role, MFA, reauthentication, and CSRF intact |
| MFA | Existing TOTP/recovery flows unchanged |
| RBAC | Existing roles and folder grants unchanged |
| Audit | Registration and review events recorded without secrets |
| Email reliability | Durable outbox, retries, dead-letter requeue |
| Database safety | Additive migrations only; existing data preserved |
| UI | Existing design system and Nepali/English support preserved |
| Regression | 756 tests and 3 subtests pass; no weakened security test |

---

**Prepared for review. No commit was made to `main`; all work remains on `phase3/staff-registration-review`.**
