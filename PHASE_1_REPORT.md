# Phase 1 Hardening Report: Transport, Sessions, and Anonymous Route Lockdown

Phase 1 implementation and testing are complete. All 723 existing tests pass without regressions, and 14 new tests have been added to rigorously enforce Phase 1 requirements, bringing the total passing test suite to **737 passed tests**.

---

## 1. Summary of Files Changed & Attack Mitigations

Every security control added includes a one-line comment identifying the specific attack it blocks:

1. **`vault/views.py`**
   - *Attack Blocked:* Direct URL unauthenticated folder access / information leakage (`VULN-01`).
   - *Change:* When an anonymous user accesses `library(request, folder_id)` with a `folder_id`, the view redirects to `/accounts/login/?next=<path>` via `redirect_to_login(request.get_full_path(), login_url="login")`. Safe return navigation is handled by `safe_portal_destination`.
2. **`accounts/services/account_tag.py`** *(New)*
   - *Attack Blocked:* Token leakage and account identifier disclosure in the DOM and API responses (`VULN-02`).
   - *Change:* Computes an irreversible 16-character HMAC digest for cross-tab sync:
     `account_tag = salted_hmac("ssdc.account-tag", f"{user.pk}:{auth_version}:{portal_session}").hexdigest()[:16]`
3. **`config/context_processors.py`**
   - *Attack Blocked:* DOM-based session hijacking and credential harvesting.
   - *Change:* Registered `account_tag(request)` context processor, safely passing only the irreversible `account_tag` to templates for authenticated users without exposing `user.pk`, `auth_version`, or `portal_session`.
4. **`config/settings.py`**
   - *Attack Blocked:* Man-in-the-middle credential theft, cookie-tossing, and session hijacking (`VULN-07`).
   - *Change:*
     - Added `config.context_processors.account_tag` to template context processors.
     - Enforced `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = "Lax"`, `SESSION_COOKIE_PATH = "/"`, `SESSION_COOKIE_DOMAIN = None`.
     - When secure cookies are enabled (default), the session cookie is renamed to `__Host-sessionid`.
     - Permitted disabling secure cookies only via `ALLOW_INSECURE_COOKIES=1`, strictly gated to require `DEBUG=1` and `ALLOWED_HOSTS` limited to localhost/127.0.0.1; any other combination raises `ImproperlyConfigured`.
5. **`templates/components/session_guard.html`**
   - *Attack Blocked:* XSS extraction of raw session tokens and user identifiers from DOM attributes (`VULN-02`).
   - *Change:* Cleared `content=""` on `<meta name="vault-session">` and set `data-account-tag="{{ account_tag }}"`.
6. **`static/js/session.mjs`**
   - *Attack Blocked:* Token theft from `localStorage` (`VULN-02`) and stale account screen data leakage across tabs.
   - *Change:* Completely removed `localStorage.setItem('ssdc-vault-session')` and storage listeners. Implemented `BroadcastChannel('ssdc-vault-session')` broadcasting only non-sensitive event names (`'session_changed'`). Tab focus, page show, and visibility checks query `/accounts/session/` and redirect immediately if `session.account_tag !== currentTag` or unauthenticated.
7. **`accounts/views.py`**
   - *Attack Blocked:* Session token exposure in JSON endpoints (`VULN-02`).
   - *Change:* Updated `session_status(request)` to return `{"authenticated": bool, "account_tag": str|null, "home_url": str}` instead of raw `marker`.
8. **`tests/test_portals.py`**
   - *Attack Blocked:* Regression in session status verification.
   - *Change:* Updated `test_session_status_is_private_and_obeys_revocation` to assert the 16-character irreversible `account_tag` instead of the legacy marker.
9. **`tests/test_ui.py`**
   - *Attack Blocked:* Cross-tab account-switching regressions.
   - *Change:* Updated `browser_session` to read `django_settings.SESSION_COOKIE_NAME` and added an autouse fixture configuring insecure session cookies specifically for the local HTTP `LiveServer` runner.
10. **`scripts/production_smoke.py`**
    - *Attack Blocked:* Production deployment smoke validation regressions.
    - *Change:* Updated cookie verification to check for `__Host-sessionid` and `SameSite=Lax`.
11. **`.env.example`**
    - *Attack Blocked:* Insecure configuration defaults in staging and production deployments.
    - *Change:* Added documentation and placeholder keys for `ALLOW_INSECURE_COOKIES=0`, independent `SECRET_KEY`, `MFA_ENCRYPTION_KEY`, and SMTP delivery.
12. **`tests/test_phase1_security.py`** *(New)*
    - *Attack Blocked:* Unauthorized route exposure, cookie misconfiguration, and cross-tab account leakage.
    - *Change:* Added 14 automated tests covering Items 1–4, including the full anonymous route sweep and multi-tab account switch tests.

---

## 2. Test Suite Results

- **Test count before Phase 1:** 723 passed
- **Test count after Phase 1:** 737 passed (0 failed, 0 errors in 3m 25s)
- **Schema migrations:** 0 (none required or applied)

```
======================= 737 passed in 205.74s (0:03:25) ========================
```

---

## 3. Mandatory Anonymous Route Sweep Table

The complete route table is cataloged in [`artifacts/route_table.md`](artifacts/route_table.md). Every URL pattern resolved by Django's root URLconf was crawled with an unauthenticated client (`test_anonymous_route_sweep_every_route_protected`). All protected routes correctly return `302 -> /accounts/login/` (or Django Admin login), `401`, `403`, or `404`. Only routes in the explicit, documented public allowlist return `200` or intended public responses.

---

## 4. `python manage.py check --deploy` Output & Justifications

### Command Output
```bash
$ APP_ENV=production DATABASE_URL='postgresql://vault:password@db.example.test:5432/vault?sslmode=verify-full' POSTGRES_SSLMODE=verify-full SECRET_KEY='...' MFA_ENCRYPTION_KEY='...' ALLOWED_HOSTS='vault.example.test' DOCUMENT_STORAGE_PROVIDER='filesystem' SCAN_MODE='clamav' .venv/bin/python manage.py check --deploy
System check identified some issues:

WARNINGS:
?: (security.W021) You have not set the SECURE_HSTS_PRELOAD setting to True. Without this, your site cannot be submitted to the browser preload list.

System check identified 1 issue (0 silenced).
```

### Justification of Findings & Settings Enforced
1. **`SECURE_PROXY_SSL_HEADER`:** Configured to `("HTTP_X_FORWARDED_PROTO", "https")` in `config/settings.py` (line 232).
2. **`SECURE_SSL_REDIRECT`:** Set to `PRODUCTION` (True in production, redirects all HTTP to HTTPS).
3. **`SECURE_HSTS_SECONDS`:** Set to `31536000` (1 year) in production.
4. **`SECURE_HSTS_INCLUDE_SUBDOMAINS`:** Set to `True` in production.
5. **`SECURE_HSTS_PRELOAD`:** Explicitly set to `False` (`SECURE_HSTS_PRELOAD = False`). This triggers warning `security.W021`. As instructed in Item 4 ("no preload"), preloading is intentionally disabled to prevent irreversible domain-wide lockouts on external or unmanaged organizational subdomains.
6. **`SESSION_COOKIE_SECURE` & `CSRF_COOKIE_SECURE`:** Both set to `True` by default; session cookie renamed to `__Host-sessionid`.
7. **`SESSION_COOKIE_HTTPONLY`:** `True`.
8. **`CSRF_COOKIE_HTTPONLY`:** `False` (standard Django requirement for client-side CSRF header extraction).
9. **`SECURE_CONTENT_TYPE_NOSNIFF`:** `True`.
10. **`X_FRAME_OPTIONS`:** `DENY`.
11. **`SECURE_REFERRER_POLICY`:** `same-origin`.
12. **`CSRF_TRUSTED_ORIGINS` & `ALLOWED_HOSTS`:** Dynamically enforced without wildcards (`*`); rejects broad domains.
13. **`DEBUG` & `SECRET_KEY`:** In production, `DEBUG` is strictly enforced to `False`, and non-production placeholder keys raise `ImproperlyConfigured`.

---

## 5. Investigation & Architectural Findings (Items 5a–5f)

### 5a. Client IP Derivation behind Nginx in Docker
- **In Django:** `client_ip()` in `accounts/views.py` inspects `request.META["HTTP_X_REAL_IP"]` when `settings.PRODUCTION` is True, falling back to `request.META["REMOTE_ADDR"]`. In non-production, it uses `REMOTE_ADDR`.
- **In Nginx (`deploy/nginx.prod.conf`):**
  ```nginx
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $remote_addr;
  proxy_set_header X-Forwarded-Proto https;
  ```
  Nginx explicitly **overwrites** (does not append to) `X-Real-IP` and `X-Forwarded-For` with `$remote_addr` (the direct TCP connection address). Client-supplied headers cannot spoof IP addresses upstream.
- **In Gunicorn:** Gunicorn does not pass `--forwarded-allow-ips`. Instead, Django bypasses `REMOTE_ADDR` translation and directly reads `HTTP_X_REAL_IP`, which Nginx has sanitized.
- **In Event Logging:** `safe_details()` in `audit/services.py` deliberately strips client IP and User-Agent; they are never persisted to the `Event` table.

### 5b. Cache Backend for `allow_rate`
- `allow_rate` in `audit/services.py` does **NOT** use `LocMemCache` or Django's cache framework.
- It is backed directly by the PostgreSQL relational table `RateBucket` (`audit.RateBucket`).
- Execution uses `@transaction.atomic` and `RateBucket.objects.select_for_update()`.
- **Persistence & Concurrency:** It is shared across all Gunicorn worker processes and threads with row-level database locking and completely survives worker reloads, container restarts, and host reboots.

### 5c. Login Account Lockout Denial-of-Service Behavior
- In `accounts/views.py:sign_in()`:
  ```python
  rate_identity = form.cleaned_data.get("username")
  if not allow_rate("login-account", rate_identity, settings.LOGIN_ACCOUNT_LIMIT):
      messages.error(request, tr("Too many failed attempts for this account..."))
  ```
- The `login-account` rate bucket is evaluated **before** checking the password.
- **Vulnerability confirmed:** An unauthenticated attacker knowing an administrator's username can spam 5 incorrect password attempts. This exhausts the account's rate bucket (5 attempts per 300 seconds), thereby locking out the legitimate administrator even when entering the valid password. Per instructions, this behavior was not modified in Phase 1 and will be addressed in a subsequent phase (e.g. combining IP + account buckets or progressive delays).

### 5d. PDF.js Build Version & CVE-2024-4367
- **Loaded Build:** `static/vendor/pdfjs/pdf.mjs` declares:
  - `pdfjsVersion = '6.4.299'`
  - `pdfjsBuild = 'd0991a0d5'`
- **Status:** Version `6.4.299` is well above the vulnerable `< 4.2.67` threshold (CVE-2024-4367 arbitrary code execution via font matrix evaluation).
- **Hardening:** `static/js/viewer.mjs` explicitly passes `isEvalSupported: false` to `pdfjsLib.getDocument({...})`, providing defense-in-depth against JIT/eval-based PDF exploits.

### 5e. Content-Security-Policy (CSP)
- **Full CSP String (`config/middleware.py`):**
  ```text
  default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'
  ```
  *(Note: `/storage/google/` routes add `frame-src 'self' https://accounts.google.com`)*
- **Security Analysis:**
  - `'unsafe-inline'`: **None**. Not present.
  - `'unsafe-eval'`: **None**. Not present.
  - Wildcards (`*`): **None**. Not present.
  - `http:` sources: **None**. All sources are `'self'`, `data:`, `blob:`, or strict HTTPS.

### 5f. Existing `Event` Audit Model
- **Fields:**
  - `id`: Auto-incrementing primary key.
  - `at`: Timestamp (`DateTimeField`, `auto_now_add=True`).
  - `actor`: Foreign key to `accounts.User` (`SET_NULL`, nullable).
  - `kind`: Char field (`login`, `logout`, `upload`, `download`, `delete`, etc.).
  - `target`: Char field (document title, folder name, or user identity).
  - `outcome`: Char field (`success`, `denied`, `error`).
  - `details`: Safe JSON field (metadata dictionaries).
- **IP & User-Agent:** Neither IP address nor User-Agent is recorded. `safe_details()` strips all network headers and secrets.
- **Immutability:** In `audit/admin.py`, `has_add_permission`, `has_change_permission`, and `has_delete_permission` all return `False`. All fields are marked `readonly_fields`. Application-level updates and deletions via the Admin UI are prohibited.

---

## 6. Verification of Secrets (VULN-06)

- `.env.local` in `.gitignore`: **Yes** (matched by `.env.*` on line 11).
- `git log --all --oneline -- .env.local`: Output is empty (**No**, `.env.local` has never been committed to git history).
- `.env.example`: Updated with placeholder configurations for `ALLOW_INSECURE_COOKIES=0`, `SECRET_KEY=`, `MFA_ENCRYPTION_KEY=`, and SMTP credentials. No real secrets are present.

---

## 7. Registration Tokens (VULN-03)

- Registration token generation, verification, and migration routines were left completely untouched in Phase 1 as directed.
