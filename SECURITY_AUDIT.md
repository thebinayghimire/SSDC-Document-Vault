# SECURITY AUDIT: SSDC DOCUMENT VAULT

**Target:** SSDC Document Vault  
**Author:** Senior Application-Security Engineer & Full-Stack Developer  
**Status:** Phase 0 — Audit Only (No code changes applied)  
**Baseline Test Status:** 723 passed, 0 failed  

---

## 1. Detected Stack and Ecosystem Versions

The project's technology stack was identified through direct repository inspection, dependency manifests, lockfiles, and virtual environment package analysis:

| Layer / Component | Technology | Detected Version | Purpose & Security Controls |
| :--- | :--- | :--- | :--- |
| **Language** | Python | 3.13.17 (`pyproject.toml` targets `py313`) | Core runtime |
| **Web Framework** | Django | 5.2.18 (`Django>=5.2,<5.3`) | Web application, ORM, security middleware |
| **Database** | PostgreSQL | 16 (libpq / `psycopg` 3.3.6) | Relational storage, row-level & advisory locking |
| **Password Hashing** | Argon2id + PBKDF2 | `argon2-cffi` 25.1.0 | Primary password hasher via `Argon2PasswordHasher` |
| **Multi-Factor Auth** | PyOTP + Cryptography | `pyotp` 2.10.0, `cryptography` 50.0.2 | TOTP MFA with Fernet-encrypted secrets at rest |
| **PDF Engine** | PDF.js + pypdf | PDF.js (v2/v3/v4 vendor), `pypdf` 6.21.4 | In-browser canvas rendering & PDF sanitization |
| **Image Processing** | Pillow | 13.0.0 | Thumbnail generation, format verification |
| **Antivirus Scanner** | ClamAV (`clamd`) | Network daemon via TCP 3310 | Stream-based file quarantine & antivirus scanning |
| **Storage Backends** | Dual Provider | Filesystem (`private-media/`) & Google Drive API (`google-auth` 2.60.0) | Zero-trust private storage; no public exposure |
| **WSGI / Static** | Gunicorn + WhiteNoise | `gunicorn` 26.2.0, `whitenoise` 6.12.0 | WSGI process execution & static asset delivery |
| **Containerization** | Docker Compose | Compose files (`compose.yaml`, `compose.prod.yaml`) | Container isolation, Nginx reverse proxy |

---

## 2. Current Authentication & Authorization Flow

Below is the current end-to-end authentication lifecycle from sign-in through token distribution, route protection, and sign-out:

```
[ USER / BROWSER ]
       |
       | 1. POST /accounts/(staff|admin)/login/
       |    { staff_id, password }
       v
+---------------------------------------------------------------------------------+
| DJANGO APPLICATION SERVER                                                       |
|                                                                                 |
| 1. Rate Limiting:                                                               |
|    allow_rate("login-ip") <= 30/300s & allow_rate("login-account") <= 5/300s    |
|                                                                                 |
| 2. Credential Verification:                                                     |
|    authenticate() -> Argon2id hash comparison against accounts_user.password    |
|                                                                                 |
| 3. Portal Authorization Check:                                                  |
|    - admin_login requires User.is_portal_admin == True                          |
|    - staff_login requires User.is_portal_admin == False                         |
|                                                                                 |
| 4. MFA Evaluation:                                                              |
|    +-----------------------------------------------------------------------+    |
|    | If requires_authenticator (Admins, Managers, or enrolled users):      |    |
|    | - Session flushed; pending_user & pending_auth_version stashed         |    |
|    | - 302 Redirect -> /accounts/mfa/                                      |    |
|    | - User submits 6-digit TOTP code or backup code                       |    |
|    | - PyOTP decrypts user.mfa_secret via Fernet and verifies code          |    |
|    +-----------------------------------------------------------------------+    |
|                                                                                 |
| 5. Session Establishment (`finish_login`):                                     |
|    - SELECT FOR UPDATE on accounts_user (auth_version validated)                |
|    - django.contrib.auth.login() writes session to `django_session` table       |
|    - Stashes: auth_version, auth_started, last_seen, reauth_at, mfa_verified    |
|    - Generates: request.session["portal_session"] = secrets.token_hex(16)      |
|    - Sets-Cookie: sessionid=<session_key>; HttpOnly; SameSite=Lax              |
+---------------------------------------------------------------------------------+
       |
       | 2. Set-Cookie: sessionid=... (HttpOnly, SameSite=Lax)
       |    Redirect -> 302 / (Admin) or /staff/ (Staff)
       v
[ BROWSER ENGINE ]
       |
       | [!] VULNERABILITY INJECTED HERE:
       | Server embeds session marker in DOM:
       | <meta name="vault-session" content="<user_id>:<auth_version>:<portal_session>">
       |
       | JavaScript (`static/js/session.mjs`) reads DOM marker and writes:
       | localStorage.setItem('ssdc-vault-session', marker);
       |
       v
[ PROTECTED REQUEST FLOW (e.g. GET /documents/<uuid>/content/) ]
       |
       | Cookie: sessionid=...
       v
+---------------------------------------------------------------------------------+
| DJANGO MIDDLEWARE & VIEW PIPELINE                                               |
|                                                                                 |
| 1. RequestReferenceMiddleware: Generates or propagates X-Request-ID            |
| 2. SecurityMiddleware & WhiteNoise: Static serving & TLS policies               |
| 3. SessionMiddleware: Reads sessionid cookie -> loads session from DB           |
| 4. CsrfViewMiddleware: Enforces CSRF token check on mutating verbs              |
| 5. AuthenticationMiddleware: Resolves request.user from session               |
| 6. SessionPolicyMiddleware:                                                    |
|    - Validates request.user.is_active == True                                   |
|    - Validates session.auth_version == user.auth_version                        |
|    - Validates session age <= 28800s (8h) & idle time <= 1800s (30m)            |
|    - Validates mfa_verified == True for privileged accounts                     |
|    - On failure: triggers django.contrib.auth.logout()                          |
| 7. View Guard: @login_required                                                  |
| 8. Permission Check: permitted_documents(request.user) via Folder/Doc grants    |
| 9. PrivateHeadersMiddleware:                                                    |
|    Cache-Control: no-store, private, max-age=0                                 |
|    Pragma: no-cache                                                             |
|    Content-Security-Policy: default-src 'self' ... frame-ancestors 'none'       |
+---------------------------------------------------------------------------------+
       |
       v
[ LOGOUT FLOW (POST /accounts/logout/) ]
       |
       | 1. POST /accounts/logout/ with CSRF token
       v
+---------------------------------------------------------------------------------+
| SERVER TERMINATION                                                              |
| - Audit Event logged: Event.objects.create(kind="logout", actor=user)           |
| - request.session.flush() drops session row from `django_session` table         |
| - Set-Cookie: sessionid=; expires=Thu, 01 Jan 1970 00:00:00 GMT                 |
| - Redirects to /accounts/staff/login/ or /accounts/admin/login/                 |
+---------------------------------------------------------------------------------+
       |
       v
[ CLIENT-SIDE CROSS-TAB SYNC ]
  Other tabs listening to `storage` event or `/accounts/session/` detect
  unauthenticated status, hide documentElement, and redirect to login.
```

---

## 3. Inventory of Tokens and Session Identifiers

Every token, cookie, session identifier, and state variable present in the codebase was mapped along with its transport vector, storage mechanism, and security flags:

| Token / Identifier | Generation & Type | Storage Location | Transmission Vector | Security Flags / Attributes | Assessment |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`sessionid`** | Django DB Session Key (32-char hex string) | Server DB (`django_session`), Browser Cookie | HTTP Request Header (`Cookie: sessionid=...`) | `HttpOnly=True`<br>`SameSite=Lax`<br>`Secure=PRODUCTION`<br>`Path=/` | **Compliant** with core requirement (server-validated HttpOnly session). Note: `Secure` is conditional on `PRODUCTION`. |
| **`csrftoken`** | Django CSRF Token (64-char alphanumeric) | Browser Cookie | HTTP Request Header (`X-CSRFToken`) / Form POST | `HttpOnly=False`<br>`SameSite=Strict`<br>`Secure=PRODUCTION`<br>`Path=/` | **Standard** Django CSRF design; accessible to JS for AJAX POSTs. |
| **`portal_session`** | Cryptographic Token (`secrets.token_hex(16)`) | Server Session (`request.session`) **AND** Client DOM **AND** Browser `localStorage` | HTML DOM (`<meta name="vault-session">`) & `localStorage` (`ssdc-vault-session`) & JSON Body (`/accounts/session/`) | **None** (Exposed to JavaScript in DOM and `localStorage`) | **NON-COMPLIANT (VULN-01).** Session token must never appear in `localStorage` or DOM. |
| **Registration Tokens** | Django `signing.dumps({"request": id})` | None (Stateless signed token) | URL Path (`/accounts/register/verify/<token>/`, `/accounts/register/status/<token>/`) | **None** (Exposed in URL, browser history, server logs, referrer) | **NON-COMPLIANT (VULN-03).** Tokens appear in URLs. |
| **MFA Enrollment Secret** | Base32 Random String (`pyotp.random_base32()`) | Server Session (Fernet-encrypted), then DB `accounts_user.mfa_secret` | One-time HTML display during enrollment (`mfa_enroll.html`) | Encrypted at rest using `MFA_ENCRYPTION_KEY` | **Compliant**; transient during enrollment. |
| **Re-authentication Marker** | Unix timestamp (`time.time()`) | Server Session (`request.session["reauth_at"]`) | Server-side only | Never transmitted | **Compliant**; strictly server-side. |
| **OAuth State & PKCE** | `secrets.token_urlsafe(32)` + SHA-256 verifier | DB `vault_driveoauthattempt` (hashed/encrypted) | Outgoing GET query param to `accounts.google.com` | Transient, single-use, 600s TTL | **Compliant**; industry standard OAuth 2.0 PKCE. |
| **Request ID** | `secrets.token_hex(16)` | `ContextVar` | HTTP Header (`X-Request-ID`) | Non-sensitive tracing ID | **Compliant**. |

---

## 4. Document Storage and Serving Architecture

### Storage Mechanism
- **Physical Location:** Confidential files are stored in `settings.PRIVATE_STORAGE_ROOT` (`private-media/` directory on disk) or in private Google Drive folders.
- **Isolation from Web Root:** `config/settings.py` (lines 188-192) programmatically enforces that `PRIVATE_STORAGE_ROOT` **cannot reside inside or relative to** `STATIC_ROOT` or `STATICFILES_DIRS`. If misconfigured, startup halts with `ImproperlyConfigured`.
- **Path Traversal Defenses:** `vault/storage.py` (`path_for` function):
  - Strictly rejects absolute paths, empty parts, and any component containing `..`.
  - Inspects every path component with `is_symlink()` and raises `SuspiciousFileOperation` if any symlink is found.
  - Verifies `target.resolve().is_relative_to(root)` before any filesystem operation.
  - Files are written exclusively with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode `0600`.
- **Zero Public Access:** There is **NO** public folder, direct web URL, Nginx alias, or static bypass to documents.

### Serving Mechanism
- **Authenticated Endpoint:** Documents are served exclusively through `vault.views.content` at:
  - Full document content: `/documents/<uuid:document_id>/content/`
  - Thumbnail preview: `/documents/<uuid:document_id>/thumbnail/`
- **Access Verification:**
  - Requires active authenticated session: `@login_required` decorator.
  - Rate limited: `request_limit(request, scope="content", limit=240)`.
  - Granular RBAC: `authorized_document()` queries `permitted_documents(request.user)`, joining `FolderGrant` and `DocumentGrant` tables. If unauthorized, emits an audit event (`record(..., outcome="denied")`) and raises `Http404` (preventing ID enumeration).
  - Version integrity: Checks file existence, byte size integrity (`total == expected_size`), and MIME type allowlist (`application/pdf`, `image/jpeg`, `image/png`, `image/webp`).
- **Response Headers & Leak Mitigation:**
  - `Content-Disposition: inline; filename="preview"`
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: no-store, private, max-age=0`
  - `Pragma: no-cache`
  - `Content-Security-Policy: ... frame-ancestors 'none';` (prevents iframe clickjacking)
- **Viewer Layer:** Rendered on client-side HTML5 canvas via self-hosted PDF.js (`viewer.mjs`). Context menus, dragging, and print/copy shortcuts are intercepted and prevented.

---

## 5. Portal Separation Analysis: Staff vs Admin

The application separates staff and administrative responsibilities across identity, URL namespaces, views, and session boundaries:

### 1. Identity & Role Models
- Defined in `accounts.models.User.Role`:
  - `ADMIN` (`admin`): Institutional system administrator.
  - `MANAGER` (`manager`): Document manager with upload/replace/grant management rights.
  - `STAFF` (`staff`): Standard reader with access restricted to explicitly granted folders.
  - `RESTRICTED` (`restricted`): Read-only access restricted to specific documents.
- Evaluated via model properties:
  - `is_portal_admin`: `self.is_active and (self.is_superuser or self.role == Role.ADMIN)`
  - `can_manage`: `self.is_active and (self.is_portal_admin or self.role == Role.MANAGER)`

### 2. URL Routes & Landing Pages
- **Admin Portal:** `/admin/` (custom `VaultAdminSite`), Admin Sign-in: `/accounts/admin/login/`
- **Staff Portal:** `/staff/` (`vault.views.staff_portal`), Staff Sign-in: `/accounts/staff/login/`
- **Shared / Neutral Sign-in:** `/accounts/login/` (inspects account role post-authentication and redirects to respective home)
- **Library Root:** `/` (for admins and managers, displays root library; for unauthenticated users, displays `home.html`)

### 3. Portal Enforcement Controls
- **Cross-Portal Sign-In Protection (`accounts.views.sign_in`):**
  - If a user signs in at `/accounts/admin/login/`, the server strictly rejects any account where `user.is_portal_admin` is False.
  - If a user signs in at `/accounts/staff/login/`, the server strictly rejects any account where `user.is_portal_admin` is True.
  - If an already-authenticated admin accesses `/accounts/staff/login/`, their session is terminated with an explanatory flash message and redirect.
- **Admin Site Enforcement (`config.admin.VaultAdminSite`):**
  - Overrides `has_permission(request)`: Requires `user.is_portal_admin`, `mfa_verified == True`, and `time.time() - session["reauth_at"] <= 600` (mandatory re-authentication within 10 minutes).
  - Non-admins attempting to access `/admin/` are redirected to `/staff/`.
- **Navigation Sanitization (`accounts.navigation.safe_portal_destination`):**
  - Prevents path-traversal escapes, open redirects, or portal crossovers via `?next=` parameters.

---

## 6. Vulnerabilities Found and Phase Mapping

The following security vulnerabilities and compliance deviations were identified, ranked by severity:

### Summary Matrix

| ID | Severity | Title | Location | Phase Mapped |
| :--- | :--- | :--- | :--- | :--- |
| **VULN-01** | **HIGH** | Session Token / Identifier Exposed in HTML DOM & `localStorage` | `components/session_guard.html`<br>`static/js/session.mjs` | **Phase 1** |
| **VULN-02** | **HIGH** | Missing Authentication Enforcement on Folder URLs (Renders Home instead of Login Redirect) | `vault/views.py:library`<br>`vault/urls.py:folder` | **Phase 1** |
| **VULN-03** | **MEDIUM** | Authorization / Registration Tokens Exposed in URL Paths | `accounts/services/registration_tokens.py`<br>`accounts/urls.py` | **Phase 2** |
| **VULN-04** | **MEDIUM** | CSRF Token Disclosed via JSON API Endpoint | `vault/views.py:import_documents` | **Phase 3** |
| **VULN-05** | **MEDIUM** | Insecure Cookie Defaults in Non-Production Environments | `config/settings.py` | **Phase 1** |
| **VULN-06** | **LOW** | Live Cloud & Mail Credentials Present in Development File | `.env.local` | **Phase 1 / 4** |
| **VULN-07** | **LOW** | Missing Explicit Cache-Control Directives on Error / Fallback Pages | Web server / Error handlers | **Phase 3** |

---

### Detailed Vulnerability Analysis

#### [VULN-01] HIGH — Session Token / Identifier Exposed in HTML DOM & `localStorage`
- **Core Requirement Violation:** *"Session tokens must never appear in URLs, localStorage, or sessionStorage."*
- **Description:** During sign-in, the server generates a 32-character hex secret `request.session["portal_session"] = secrets.token_hex(16)`. In `templates/components/session_guard.html`, this token is rendered into the DOM:
  ```html
  <meta name="vault-session" content="{{ request.user.pk }}:{{ request.user.auth_version }}:{{ request.session.portal_session }}">
  ```
  `static/js/session.mjs` extracts this content and writes it directly to browser storage:
  ```javascript
  localStorage.setItem('ssdc-vault-session', marker);
  ```
  Additionally, `/accounts/session/` returns this secret token in JSON response payloads.
- **Risk / Attack Vector:** Any client-side XSS vulnerability, rogue browser extension, or malicious script in dependencies can read `localStorage.getItem('ssdc-vault-session')` and the DOM, bypassing HttpOnly protections intended for session markers.
- **Remediation Phase:** **Phase 1**. Remove `portal_session` from the DOM, `localStorage`, and JSON endpoints. Replace cross-tab synchronization with an ephemeral `BroadcastChannel` mechanism or state-free storage event (e.g. integer timestamp), and let the server validate session state exclusively via the HttpOnly `sessionid` cookie.

---

#### [VULN-02] HIGH — Missing Authentication Enforcement on Folder URLs
- **Core Requirement Violation:** *"Copying a URL from a logged-in page and opening it in another browser, an incognito window, or another device must NEVER grant access. It must redirect to the login page."*
- **Description:** In `vault/urls.py`, the route `path("folders/<uuid:folder_id>/", views.library, name="folder")` points to `views.library`. In `vault/views.py` (line 93):
  ```python
  def library(request, folder_id=None):
      if not request.user.is_authenticated:
          return render(request, "home.html")
  ```
  If an authenticated staff member or manager copies a folder URL (e.g., `https://vault.ssdc.org/folders/4c1b9201-9a4f-44e2-8ad0-128a1c97a512/`) and opens it in an incognito window, another browser, or an unauthenticated session, the server returns HTTP 200 with `home.html` instead of redirecting (HTTP 302) to the login page with a `?next=` return target.
- **Risk / Attack Vector:** Inconsistent access control; users are not redirected to authenticate, violating core session access expectations and breaking navigation continuity.
- **Remediation Phase:** **Phase 1**. Enforce `@login_required` or explicit redirect on all folder URLs (`folders/<uuid>/`), redirecting unauthenticated requests to the appropriate login portal (`/accounts/login/?next=...` or `/accounts/staff/login/?next=...`).

---

#### [VULN-03] MEDIUM — Authorization / Registration Tokens Exposed in URL Paths
- **Core Requirement Violation:** *"Session tokens must never appear in URLs..."*
- **Description:** Staff self-registration uses `signing.dumps({"request": registration.pk}, salt=SALT, compress=True)` to create signed tokens that are passed directly as URL path parameters:
  - `/accounts/register/verify/<str:token>/`
  - `/accounts/register/resend/<str:token>/`
  - `/accounts/register/status/<str:token>/`
- **Risk / Attack Vector:** URLs containing tokens are retained in browser history, proxy access logs, web server logs, and referrer headers if external links or static assets are requested. While these tokens are scoped to applicant registration, carrying authorization tokens in URLs is an anti-pattern.
- **Remediation Phase:** **Phase 2**. Store registration flow state in the user's server-side session or short-lived signed HttpOnly cookie rather than in URL paths.

---

#### [VULN-04] MEDIUM — CSRF Token Disclosed via JSON API Endpoint
- **Description:** In `vault/views.py` (`import_documents`, lines 166-167):
  ```python
  if request.method == "GET" and wants_json:
      return JsonResponse({"csrf_token": get_token(request)})
  ```
  This endpoint vends CSRF tokens in JSON format over GET requests.
- **Risk / Attack Vector:** Unnecessary API surface exposing anti-forgery tokens.
- **Remediation Phase:** **Phase 3**. Rely on standard Django template CSRF tokens and the standard `csrftoken` cookie.

---

#### [VULN-05] MEDIUM — Insecure Cookie Defaults in Non-Production Environments
- **Description:** In `config/settings.py` (lines 198-199):
  ```python
  SESSION_COOKIE_SECURE = PRODUCTION
  CSRF_COOKIE_SECURE = PRODUCTION
  ```
  If the application is deployed to a staging or pilot environment without `APP_ENV=production`, session and CSRF cookies are issued without the `Secure` attribute, allowing transmission over cleartext HTTP.
- **Remediation Phase:** **Phase 1**. Enforce `Secure=True` whenever HTTPS is present or make it opt-out only for explicit local loopback development.

---

#### [VULN-06] LOW — Live Database and SMTP Credentials in Local Configuration File
- **Description:** The local `.env.local` file contains an active third-party connection string for a cloud-hosted Neon database (`ep-floral-heart-ao12iowe.c-2.ap-southeast-1.aws.neon.tech`) and an active Gmail SMTP application password.
- **Remediation Phase:** **Phase 1 / Phase 4**. Rotate credentials, document placeholders in `.env.example`, and ensure no production secrets reside in local development environments.

---

#### [VULN-07] LOW — Missing Explicit Cache-Control Directives on Error / Fallback Pages
- **Description:** While `PrivateHeadersMiddleware` applies `Cache-Control: no-store, private` to all standard responses, error responses generated outside the middleware chain (e.g., web server 502/504 errors or static error pages) could be cached by aggressive intermediate caches.
- **Remediation Phase:** **Phase 3**. Audit custom 400/403/404/500 handlers and Nginx error response headers.

---

## 7. Proposed Implementation Roadmap

To systematically harden the application without breaking functionality or destabilizing the 723 existing tests, the work is structured into the following distinct phases:

### Phase 1: Core Session Hardening & Navigation Access Control *(Next Step upon Approval)*
- **Objective:** Fulfill the core requirement: strictly enforce HttpOnly cookie sessions, eliminate `localStorage` session storage, remove session tokens from the DOM, and guarantee all protected URLs (including folders) redirect to login.
- **Scope of Work:**
  1. Remove `<meta name="vault-session">` token rendering in `templates/components/session_guard.html` and `templates/admin/base_site.html`.
  2. Refactor `static/js/session.mjs` to eliminate `localStorage.setItem('ssdc-vault-session', marker)`. Replace cross-tab notification with a privacy-preserving mechanism (`BroadcastChannel('ssdc-vault-auth')` posting an ephemeral event such as `"account_changed"` or timestamp, coupled with cookie-backed `/accounts/session/` checks that return only `{"authenticated": bool}`).
  3. Update `/accounts/session/` in `accounts/views.py` to stop returning sensitive marker strings (`portal_session` and `user.pk`).
  4. Fix `vault/views.py` (`library` view): When `folder_id` is supplied and user is unauthenticated, redirect to `LOGIN_URL` with `?next=/folders/<folder_id>/` instead of rendering `home.html`.
  5. Audit all vault routes to ensure incognito / unauthenticated copy-pasting reliably redirects to login.
  6. Add security comments on every modified control explaining which attack it mitigates.
  7. Run full test suite (`pytest`) and update test assertions that checked `portal_session` in DOM/localStorage to verify the hardened behavior.

### Phase 2: Registration Workflow & Token Security Hardening
- **Objective:** Eliminate authorization and status tokens from URLs.
- **Scope of Work:**
  1. Refactor `staff_register_verify`, `staff_register_resend`, and `staff_registration_status` to use server-side session or short-lived signed HttpOnly cookies for pending registration references instead of `<str:token>` in URLs.
  2. Ensure registration links sent via email point to clean endpoints.

### Phase 3: Endpoint & Document Delivery Hardening
- **Objective:** Harden API endpoints and document streaming.
- **Scope of Work:**
  1. Remove JSON CSRF token vending from `vault.views.import_documents`.
  2. Audit range-header processing and streaming generators in `vault.views.content`.
  3. Ensure explicit `no-store` headers on all custom HTTP error views (400, 403, 404, 500).

### Phase 4: Secrets, Logging & Final Verification
- **Objective:** Eliminate secret exposure risks, verify logging compliance, and run comprehensive end-to-end regression tests.
- **Scope of Work:**
  1. Audit `.env.example` against all configuration settings.
  2. Verify that passwords, session IDs, tokens, or OTPs are never logged.
  3. Execute full end-to-end test suite and browser UI tests.

---

## 8. Proposed Plan for Phase 1 (Detailed Specification)

### A. Proposed Code Changes for Phase 1

1. **`templates/components/session_guard.html`:**
   - Remove `content="...{{ request.session.portal_session }}..."`.
   - The `<meta>` tag will only contain safe endpoint URLs or be replaced by script initialization parameters. No session tokens or user IDs will exist in DOM attributes.
   - *Comment added:* `# Mitigates XSS-based session token harvesting from DOM attributes.`

2. **`static/js/session.mjs`:**
   - Remove `localStorage.setItem(storageKey, marker)`.
   - Use standard `BroadcastChannel('ssdc-session')` (supported in all modern browsers) to notify other tabs when a sign-out occurs.
   - On storage/visibility/focus events, perform a background `fetch('/accounts/session/')`. The server validates the HttpOnly cookie and returns only `{"authenticated": true/false}`.
   - If unauthenticated, redirect immediately to login.
   - *Comment added:* `// Mitigates token leakage via localStorage while preserving cross-tab session termination.`

3. **`accounts/views.py` (`session_status` view):**
   - Refactor `session_status(request)`:
     ```python
     @require_http_methods(["GET", "HEAD"])
     def session_status(request):
         # Mitigates session identifier disclosure in API response bodies
         if not request.user.is_authenticated:
             return JsonResponse({"authenticated": False, "home_url": "/accounts/login/"})
         return JsonResponse({"authenticated": True, "home_url": portal_home(request.user)})
     ```
   - No `portal_session`, `auth_version`, or user IDs will be returned in JSON.

4. **`vault/views.py` (`library` view):**
   - Enforce authentication on folder views:
     ```python
     @require_http_methods(["GET", "HEAD"])
     def library(request, folder_id=None):
         # Mitigates unauthorized access and ensures copied folder URLs redirect to login
         if not request.user.is_authenticated:
             if folder_id:
                 from django.contrib.auth.views import redirect_to_login

                 return redirect_to_login(request.get_full_path(), login_url="staff_login")
             return render(request, "home.html")
     ```
   - When an unauthenticated user opens `https://vault/folders/<id>/`, they are immediately redirected to `/accounts/staff/login/?next=/folders/<id>/`.

5. **`config/settings.py`:**
   - Review and ensure cookie security flags reflect best practices for transport security.

### B. Schema Migrations Assessment
- **Are database schema migrations required for Phase 1?**
  **NO.** 
  - Django sessions are already managed server-side in the existing `django_session` table.
  - The `accounts_user` table already possesses `auth_version` (used by `SessionPolicyMiddleware` to invalidate sessions on security changes).
  - `portal_session` was solely a transient session dictionary key (`request.session["portal_session"]`), not a database column.
  - Therefore, Phase 1 requires **zero database schema modifications and zero migration files**, ensuring zero risk of data loss or schema drift.

### C. Test Verification Strategy
- **Baseline Test Count:** 723 passed tests.
- **Target Post-Phase 1:** 723 passed tests.
- Existing tests asserting `client.session["portal_session"]` will continue to pass because `portal_session` remains inside the server-side session dictionary if desired, but is simply withheld from the DOM, `localStorage`, and JSON outputs.
- UI tests in `tests/test_ui.py` (`test_sign_out_clears_other_tabs_and_browser_history`) will be adjusted to verify cross-tab clearing via the privacy-preserving channel without asserting DOM token attributes.
- New unit and integration tests will be added to confirm that:
  1. Opening a folder URL without a session cookie returns HTTP 302 to the staff login portal.
  2. Opening a preview URL without a session cookie returns HTTP 302 to the login portal.
  3. `localStorage` and DOM do not contain session tokens or user identifiers.
  4. Multi-tab logout continues to automatically clear and redirect other tabs.

---

## 9. Current Phase Status

In strict accordance with the Working Rules:
- **Phase 0 (Audit Only):** COMPLETE.
- **Code Modifications:** NONE applied.
- **Next Step:** Awaiting user review and explicit approval before initiating Phase 1.
