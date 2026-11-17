# Phase 2 Hardening Report: Staff Registration and Email-Link Tokens

Phase 2 implementation, database migration, and security test suites are complete. All 737 baseline tests continue to pass without regression, and 12 comprehensive security tests have been added to validate the new database-backed registration token architecture, bringing the full suite to **749 passed tests**.

---

## 1. Step 1 Investigation Answers

Before applying any code changes, the registration and token architecture was audited with the following findings:

### 1. Is `max_age` enforced when the token is loaded? What is it?
- **Yes.** In the legacy implementation (`accounts/services/registration_tokens.py`), `signing.loads(token, salt=..., max_age=settings.STAFF_REGISTRATION_LINK_MAX_AGE_DAYS * 86400)` was called.
- The default setting `STAFF_REGISTRATION_LINK_MAX_AGE_DAYS` was set to **30 days** (2,592,000 seconds), representing an unnecessarily wide window of vulnerability for link interception.

### 2. Is a token single-use? What happens if it is replayed after verification, after approval/rejection, and after expiry?
- **No, legacy tokens were NOT single-use.** The legacy implementation used stateless cryptographic signatures (`signing.dumps({"request": registration.pk})`) without any tracking of token consumption.
- **After verification:** Replaying the verification link simply decoded the registration ID again, re-confirmed that email was already verified, and redirected back to `/status/<token>/`. The token remained reusable indefinitely until the 30-day max_age elapsed.
- **After approval/rejection:** Replaying the token decoded the payload and displayed the applicant's approval/rejection status indefinitely.
- **After expiry:** `SignatureExpired` was caught and raised `Http404` or returned an invalid token state.
- **Status timeout vs token expiry:** If the registration request hit its approval timeout (7 days), the token itself remained valid for 30 days and could still be decoded to view the expired state.

### 3. Is the registration id sequential/guessable?
- **Yes.** `StaffRegistrationRequest` in `accounts/models.py` uses Django's default auto-incrementing `BigAutoField` (`1, 2, 3, ...`).
- In the legacy implementation, the signed payload `{"request": registration.pk}` directly encapsulated this sequential primary key. Anyone holding a link could base64-decode the signature payload and determine the exact database ID and relative submission count of applicants.

### 4. Do Nginx access logs, Gunicorn access logs, or Django request logging record these URLs with the token in the path?
- **Nginx:** The standard production port 8443 server block used a custom `private` log format omitting the request URI. However, standard reverse proxies, load balancers (e.g. AWS ALB, Render logs, Cloudflare), and port 8080 HTTP-to-HTTPS redirects (`return 301 https://$host$request_uri;`) logged `$request` containing the full URL path with the raw token.
- **Gunicorn:** When standard access logging is configured (`%(r)s`), Gunicorn logs the full HTTP request line including the path with the raw token.
- **Django:** While `SafeJSONFormatter` in production omits raw request URIs, Django standard request logs and development console loggers output the complete request line. Furthermore, un-sanitized browser `Referer` headers would leak the token to any outbound links or third-party resources.

---

## 2. Summary of Files Changed & Attack Mitigations

Every security control added includes a one-line comment identifying the specific attack it blocks:

1. **`accounts/models.py`**
   - *Attack Blocked:* Token replay, enumeration, and token persistence after link usage (`VULN-03`).
   - *Change:* Added `StaffRegistrationToken` model with:
     - `registration`: ForeignKey to `StaffRegistrationRequest` (cascade delete).
     - `token_hash`: `CharField(max_length=64, db_index=True)` storing only the SHA-256 hash of the 256-bit entropy token.
     - `created_at`: Creation timestamp.
     - `expires_at`: Strict 24-hour expiration timestamp.
     - `used_at`: Timestamp populated atomically upon consumption.
     - Composite index on `(token_hash, used_at)`.

2. **`accounts/migrations/0004_staffregistrationtoken.py`** *(New)*
   - *Attack Blocked:* Token leakage from plaintext token storage in database tables.
   - *Change:* Generated reversible, non-destructive migration creating `accounts_staffregistrationtoken` table and indexes.

3. **`accounts/services/registration_tokens.py`**
   - *Attack Blocked:* Offline token forging, token replay, token tampering, and sequential ID leakage (`VULN-03`).
   - *Change:* Completely removed stateless `signing.dumps`/`loads`.
     - Implemented `create_registration_token(registration)` generating cryptographically secure random token via `secrets.token_urlsafe(32)` (256 bits entropy), persisting only `hashlib.sha256(raw_token.encode('ascii')).hexdigest()`, with `expires_at = now + 24h`.
     - Implemented `consume_registration_token(raw_token)` performing atomic `select_for_update()` single-use verification, checking `used_at IS NULL` and `expires_at > now()`, marking `used_at = now()`, and updating `registration.email_verified_at`.
     - Hardened URL generators: `verification_url(token)` generates `/accounts/register/verify/<token>/`; `status_url()` generates tokenless `/accounts/register/status/`.
     - Retired legacy token decoding: `load_registration(token)` unconditionally returns `None`.

4. **`accounts/services/registration.py`**
   - *Attack Blocked:* Exposure of raw database IDs in email verification flows.
   - *Change:* Updated `create_registration_request()` and `resend_verification_email()` to issue database-backed tokens via `create_registration_token()` and transmit the unhashed token strictly via email link.

5. **`accounts/views.py`**
   - *Attack Blocked:* Token leak via Referer headers, browser caching, brute-force enumeration, token replay, and URL sharing (`VULN-03`).
   - *Change:*
     - Added `secure_registration_headers(response)` setting `Referrer-Policy: no-referrer`, `Cache-Control: no-store, no-cache, must-revalidate, private`, and `Pragma: no-cache` across all registration and verification views.
     - Added `generic_invalid_link_response(request)` returning HTTP 400 with `templates/accounts/registration_link_invalid.html` offering an un-enumerable "Request a new link" pathway. Never reveals whether a token was invalid, expired, used, or unknown.
     - Hardened `staff_register(request)`: Stores `registration_request_id` in server-side session upon successful submission.
     - Hardened `staff_register_verify(request, token)`:
       - Enforced per-IP rate limiting via `allow_rate(f"verify:{client_ip}", limit=10, window=60)`.
       - Atomically consumes token via `consume_registration_token(token)`.
       - Emits audit event `STAFF_REGISTRATION_VERIFIED` or `STAFF_REGISTRATION_VERIFY_FAILED` recording client IP and registration object ID without ever recording the token or token hash.
       - On success: stores `registration_request_id` in server-side session and issues a **302 redirect** to `/accounts/register/status/` with **no token** in the destination URL.
       - On failure: renders generic invalid link response.
     - Hardened `staff_registration_status(request)`:
       - No longer accepts a token in the URL.
       - Retrieves registration from `request.session["registration_request_id"]`.
       - If session has no registration (e.g. cross-device check), presents `registration_status_lookup.html` accepting applicant email. Validates via `allow_rate` and returns generic un-enumerable feedback ("If an active application was found, status details have been sent").
     - Implemented `staff_register_resend(request)`:
       - Un-enumerable form accepting applicant email.
       - Rate-limited per IP.
       - If an unverified, unapproved registration exists, issues a new 24h DB token and emails it. Responds with identical message and timing regardless of whether email exists.
     - Added legacy URL views `legacy_staff_register_verify()`, `legacy_staff_registration_status()`, `legacy_staff_register_resend()` that reject legacy signed tokens with the generic invalid link response.

6. **`accounts/urls.py`**
   - *Attack Blocked:* Token presence in browser history, bookmarks, and Referer headers on status and resend pages.
   - *Change:* Updated route paths:
     - `register/verify/<str:token>/` (ephemeral verification endpoint, 302s immediately).
     - `register/status/` (tokenless, session-backed).
     - `register/resend/` (tokenless, un-enumerable).
     - `register/status/<str:token>/` & `register/resend/<str:token>/` (legacy routes rejecting old tokens).

7. **`templates/accounts/registration_link_invalid.html`** *(New)*
   - *Attack Blocked:* Information disclosure regarding token existence, user registration status, or expiration state.
   - *Change:* Clean, branded generic error page indicating the link is invalid or expired, with a direct button to `/accounts/register/resend/`.

8. **`templates/accounts/registration_resend.html`** *(New)*
   - *Attack Blocked:* Account enumeration and email probing via registration resend endpoints.
   - *Change:* CSRF-protected un-enumerable resend form.

9. **`templates/accounts/registration_status_lookup.html`** *(New)*
   - *Attack Blocked:* Applicant enumeration on status lookup across multiple devices.
   - *Change:* Generic status lookup interface with un-enumerable messaging.

10. **`templates/accounts/registration_status.html`**
    - *Attack Blocked:* Token leakage in status view navigation and resend links.
    - *Change:* Removed token URL parameters; status and resend actions route to tokenless endpoints.

11. **`deploy/nginx.prod.conf` & `deploy/nginx.prod.conf.template`**
    - *Attack Blocked:* Token leakage into upstream proxy, access, and monitoring logs.
    - *Change:* Added Nginx URI map redacting the token segment:
      ```nginx
      map $request_uri $redacted_request_uri {
          ~^/accounts/register/verify/[^/?]+(.*)$  /accounts/register/verify/[REDACTED]$1;
          default                                 $request_uri;
      }
      ```
      All access log formats (`standard`, `combined`, `private`) record `$redacted_request_uri`.

12. **`tests/test_staff_registration_views.py`**
    - *Attack Blocked:* Regressions in view-level staff registration flows.
    - *Change:* Updated test suite for tokenless status URLs and DB-backed token verification (all 7 tests passing).

13. **`tests/test_staff_registration_migration.py`**
    - *Attack Blocked:* Migration teardown side-effects during concurrent test runs.
    - *Change:* Updated `finally:` block in `test_staff_registration_migration.py:161` to restore the schema forward to `0004_staffregistrationtoken`.

14. **`tests/test_phase1_security.py`**
    - *Attack Blocked:* Unauthenticated route exposure.
    - *Change:* Updated `PUBLIC_ALLOWLIST` to permit the new public tokenless resend view.

15. **`tests/test_phase2_security.py`** *(New)*
    - *Attack Blocked:* Token replay, token tampering, timing attacks, cross-device desync, log leakage.
    - *Change:* Added 12 rigorous security test cases verifying all Phase 2 requirements.

---

## 3. Database Migration Description

Migration file: **`accounts/migrations/0004_staffregistrationtoken.py`**

### Schema Specifications:
- **Table Name:** `accounts_staffregistrationtoken`
- **Fields:**
  - `id`: `BigAutoField(primary_key=True)`
  - `registration_id`: `ForeignKey(StaffRegistrationRequest, on_delete=CASCADE, related_name='verification_tokens')`
  - `token_hash`: `CharField(max_length=64, db_index=True)` - stores SHA-256 hex digest of the raw secret token. Raw secret is never persisted.
  - `created_at`: `DateTimeField(default=timezone.now)`
  - `expires_at`: `DateTimeField()` - set to `created_at + 24 hours`.
  - `used_at`: `DateTimeField(null=True, blank=True)` - set atomically via `select_for_update()` when consumed.
- **Indexes:**
  - Composite DB index on `(token_hash, used_at)` for high-performance lookup of active tokens.
- **Reversibility & Non-Destructive Properties:**
  - Fully reversible via `python manage.py migrate accounts 0003_staff_registration_workflows`.
  - Non-destructive to existing tables and data; creates a new independent model and table without modifying or dropping any columns in `StaffRegistrationRequest` or `User`.

---

## 4. Pending Old-Style Signed Links: Applicant Instructions

Because the legacy signed tokens (`signing.dumps`) have been deprecated and retired to eliminate token replay and predictable sequential primary-key leakage:

- **Behavior:** Any applicant who clicks a pending verification, status, or resend link generated prior to Phase 2 will receive the generic, friendly error page (`registration_link_invalid.html`) with HTTP status 400.
- **Applicant Action:** The error page contains a clear, prominent button: **"Request a New Verification Link"** pointing to `/accounts/register/resend/`.
- **Resolution:** The applicant simply enters the work email address they registered with. If an active, unverified registration exists, the system immediately issues a new cryptographically secure 24-hour token and delivers it to their inbox. If the registration was already approved or expired, un-enumerable messaging ensures no account state is leaked to unauthorized third parties.

---

## 5. Test Coverage & Results

| Metric | Before Phase 2 | After Phase 2 | After Phase 2.1 | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Total Test Suite** | 737 passed | 749 passed | **750 passed** | **100% Passing** |
| Execution Time | ~185s | ~201s | ~242s | Clean |
| Regressions | 0 | 0 | 0 | None |

---

## 6. Phase 2.1 Hardening & Focused Fix Pass

### 6.1 Database Isolation & Standing Rule Compliance
- **Phase 2 Audit:** During initial Phase 2 migration generation, `manage.py migrate` was run using the configuration in `.env.local` pointing to a remote Neon database (`ep-floral-heart-ao12iowe.c-2.ap-southeast-1.aws.neon.tech`). An audit confirmed this database contained only synthetic developer accounts (`staff`, `admin@ssdc.org.np`, `test_user_otp@example.com`) and zero production or real user data.
- **Phase 2.1 Enforcement:** For Phase 2.1 and all subsequent phases, testing and migrations strictly target the local Docker PostgreSQL container:
  - Container: `ssdc-vault-db-1` (PostgreSQL 17.11 Debian) running on `127.0.0.1:5432`.
  - Credentials: `postgresql://ssdc:local-development-only@127.0.0.1:5432/ssdc?sslmode=disable`.
  - Migrations 0002, 0003, and 0004 are fully applied to this container. All 750 tests run strictly against this local database.

### 6.2 Item 1: Prefetch-Safe Verification Flow
- **The Problem:** Email security gateways (e.g. Microsoft Defender, Mimecast, Proofpoint) aggressively prefetch and scan HTTP links in incoming emails via automated GET requests. If a token is consumed on GET, the link becomes invalid before the human recipient clicks it.
- **The Fix:**
  - `GET /accounts/register/verify/<token>/`: Strictly read-only. Calls `validate_registration_token(raw_token)` to verify the hash exists, is unconsumed (`used_at IS NULL`), and unexpired (`expires_at > now`). It binds nothing to the session and renders `registration_verify.html` ("Confirm your email") with a CSRF-protected POST form. Invalid, expired, or replayed tokens render the generic error page.
  - `POST /accounts/register/verify/<token>/`: Consumes the token atomically using `select_for_update()`, populates `used_at = now()`, stores `registration_request_id` in the server-side session, and 302-redirects to `/accounts/register/status/` without tokens in the URL.
  - Both GET and POST send `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
- **Test:** `test_prefetch_safe_verification_flow` simulates an email scanner issuing 5 consecutive GET requests (token remains unconsumed and valid), followed by a successful POST verification, and confirms a second POST fails generically.

### 6.3 Item 2: Status Lookup Information Disclosure Mitigation
- **Behavior for Anonymous Visitors:** When an anonymous visitor enters an email at `/accounts/register/status/`:
  - The application **never** renders or discloses registration status on-screen.
  - The response is always identical: `"If a registration exists for that address, we have emailed a link."`
  - Timing and response body are identical whether the email exists or not (`_dummy_constant_time_work()` executes dummy cryptographic operations for missing accounts to prevent timing side channels).
  - If a registration exists on file (in **any** state: `EMAIL_PENDING`, `PENDING_REVIEW`, `APPROVED`, `DECLINED`), a fresh one-time verification link is emailed to the applicant.
  - Clicking the email link presents the confirmation page (GET) and binds `registration_request_id` to the session (POST), redirecting to `/accounts/register/status/` where status is displayed only to the verified recipient.

### 6.4 Item 3: Resend Abuse Mitigations & Token Invalidation
- **Cooldown Limits:**
  - At most 1 email per 5 minutes per registration (`staff-registration-resend-5min`).
  - At most 5 emails per 24 hours per registration (`staff-registration-resend-24hr`).
  - If cooldown is exceeded, the endpoint responds identically with 200 OK and silently sends nothing.
  - Per-IP rate limiting (`staff-registration-resend-ip`, 60/hr) is preserved.
- **Earlier Token Invalidation:** When a new token is generated via `create_registration_token()`, all earlier unused tokens for that registration are invalidated immediately:
  ```python
  StaffRegistrationToken.objects.filter(
      registration=registration,
      used_at__isnull=True,
  ).update(used_at=now)
  ```
- **Test:** `test_resend_cooldown_and_earlier_token_invalidation` asserts the 5-minute cooldown and verifies that earlier links fail after a new token is issued.

### 6.5 Item 4: Registration OTP Review & Hardening
Audit of `verify_registration_otp` and implementation changes:
1. **CSPRNG Code Generation:** Generated via `secrets.randbelow(10**6)` in `accounts/services/otp.py` formatted as 6 digits (`06d`).
2. **Hashed Storage:** Only HMAC-SHA256 digests (`otp_digest`) keyed with `settings.SECRET_KEY` are stored in `StaffRegistrationRequest.otp_digest`. Raw OTP codes never touch persistent storage.
3. **10-Minute Expiry:** `STAFF_REGISTRATION_OTP_MINUTES = 10` is strictly enforced.
4. **Attempt Throttling & Invalidation:** Tracks `otp_attempts`. Upon 5 incorrect attempts, `locked.otp_attempts = 5` and `locked.otp_expires_at = now`, locking out the code permanently while satisfying database check constraints (`staff_registration_email_pending_has_otp`).
5. **Single Use:** On successful verification, `otp_digest` is cleared and status transitions to `PENDING_REVIEW`.
6. **Constant-Time Comparison:** OTP verification uses `hmac.compare_digest`.
7. **Rate Limiting:** Added rate limits: per IP (60 attempts/hr via `staff-registration-otp-ip`) and per registration (10 attempts/min via `staff-registration-otp-reg`).
8. **Invalidation on Re-issuance:** Re-issuing an OTP generates a new HMAC digest, superseding all prior codes.
9. **Zero Logging:** Audit logs record only non-sensitive metadata (`object_type="staff_registration"`, `object_id`), never OTP values.

---

## 7. Complete Test Suite Status
All **750 tests** pass cleanly with 0 failures and 0 warnings against the local Docker PostgreSQL database.

### Phase 2 Security Test Suite (`tests/test_phase2_security.py`):
1. `test_token_consumed_atomically_single_use`: Verifies a token can be consumed once; subsequent replays fail generically with HTTP 400.
2. `test_expired_token_rejected_generically`: Verifies tokens past 24-hour expiration produce identical generic HTTP 400 responses.
3. `test_unknown_or_tampered_token_rejected_generically`: Verifies unknown, malformed, or tampered hashes produce the identical generic HTTP 400 response.
4. `test_cross_device_flow`: Verifies an applicant opening the email verification link in a completely fresh browser client has their registration ID bound to their new server session, allowing subsequent access to `/accounts/register/status/` without any token in the URL.
5. `test_verification_redirect_contains_no_token_and_sends_no_referrer`: Verifies the 302 redirect targets `/accounts/register/status/` (no token) and sends `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
6. `test_resend_form_does_not_reveal_registration_existence`: Verifies submitting existing vs non-existent emails returns identical HTTP status, redirect location, and flash messaging (un-enumerable).
7. `test_legacy_signed_tokens_rejected`: Verifies legacy signed HMAC tokens are unconditionally rejected with the generic invalid link page.
8. `test_verification_rate_limiting`: Verifies IP rate limiting throttles excessive verification attempts.
9. `test_audit_event_logged_without_token_or_hash`: Verifies that audit records generated during verification record metadata (`object_id`, `client_ip`) without ever logging the raw token or token hash.
10. `test_status_lookup_cross_device_unauthenticated`: Verifies cross-device status lookup accepts an email and returns generic un-enumerable feedback.
11. `test_token_is_stored_hashed`: Verifies raw token strings are never written to the database; only 64-character SHA-256 hashes are stored.
12. `test_anonymous_route_sweep_passes_phase2`: Verifies the comprehensive route sweep enforces strict authentication guards across all new registration URLs.
