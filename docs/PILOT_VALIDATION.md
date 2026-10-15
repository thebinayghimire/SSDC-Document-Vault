# Hosted pilot validation — 15 October 2026

Scope: existing clean `master` checkout, Windows development host, Python 3.13.12,
Node 24.14.1, local PostgreSQL, Linux Docker containers and synthetic test data.
No hosted database migration, public release, billable provisioning or Git push
has been performed. Application/Drive authorization remains unchanged.

## Executed checks

| Check | Result |
| --- | --- |
| Django `check` | Passed, no issues. |
| Production `check --deploy` with synthetic settings | No errors; intentional `security.W021` for HSTS preload off remains visible. |
| `makemigrations --check --dry-run` | Passed, no changes detected. |
| npm locked installation / PDF.js vendoring / collectstatic | Passed. |
| Ruff lint and formatting | Passed. |
| Existing Playwright browser suite | **8 passed**, Playwright-managed Chromium, isolated local test DB; browser install command succeeded. |
| Non-browser suite | **353 passed, 5 skipped**, zero failures/errors; unique local PostgreSQL test DB, 555.26 seconds. Windows skips require Linux/OpenSSL; all five passed separately in Linux. |
| Linux TLS installer tests | **Evidence gap — corrected 16 October 2026.** The retained log `artifacts/pilot-linux-tls.txt` contains only a failed `docker run` (`Unable to find image 'ssdc-app:latest' locally` / `pull access denied for ssdc-app`); it does not record five passing tests. The five `tests/test_tls_install.py` cases are **SKIPPED** on the Windows host in the final run. Treat the Linux TLS installer result as **unverified** and re-run it on Linux against a locally built, correctly tagged image, retaining the output, before release. |
| Runtime and development Python dependency audits | No known vulnerabilities reported. |
| npm production dependency audit | Zero vulnerabilities reported. |
| AMD64 application, scanner and proxy image builds | Passed; images tagged `*:pilot-candidate`, not published. |
| Docker Scout image audits | App: **failed/open**, 1 high + 1 medium + 26 low; scanner/proxy: no vulnerable packages reported. [Triage](PILOT_IMAGE_AUDIT.md). |
| Local synthetic PostgreSQL TLS integration | Passed identity/`SELECT 1` with `verify-full`; untrusted CA rejected with sanitized error. Disposable DB/network removed. This was not Supabase. |
| Local ClamAV INSTREAM self-test | Passed: clean fixture accepted, EICAR detected. |
| Local Google Drive operational check | **Blocked**: stored owner connection requires administrator reconnection. |

Browser failure diagnosis: Windows associates `.mjs` with `text/plain`, which
prevented Django's test server from loading the viewer module. The fixture now
uses the production WhiteNoise JavaScript MIME type. All eight browser checks
passed after correction, without skipping assertions or weakening application
security. Initial overlapping test runs collided on `test_ssdc`; subsequent
browser tests used `test_ssdc_pilot_browser_local`. A separately running pytest
process was also using the default `test_ssdc`, causing duplicate synthetic users
in later attempts. The final non-browser run uses a unique local database name
and leaves that other process untouched. Earlier collided or incomplete runs are
not counted as successful tests.

The upload identity-confirmation redirect is intentional: its `next` parameter
returns staff to their permitted upload form. Tests now check the round trip and
reject external, scheme-relative, backslash and control-character destinations.
The unused `timezone` import was removed.

Ignored local evidence includes `artifacts/pilot-browser.xml`,
`pilot-nonbrowser.xml`, `pilot-configuration.xml`, `pilot-*-audit.json`,
`pilot-build-*.txt` and browser screenshots under `artifacts/redesign/`.
These artifacts are not application data or deployment credentials.
Unit tests cover target mismatch before network access, sanitized database errors,
TLS policy, Compose isolation, encrypted paired backups and failure cleanup.
The paired remote backup/restore workflow has not yet been exercised with a live
Supabase database or live Drive owner.

## Evidence index — recorded artifacts (added 16 October 2026)

Every claim above is traceable to a file in `artifacts/`, or is marked as having
no retained evidence. Counts below are read back from the files themselves.

| Claim | Artifact | What the file actually shows |
| --- | --- | --- |
| Non-browser suite | `artifacts/pilot-nonbrowser.xml`, `pilot-nonbrowser.txt` | `<testsuite ... errors="0" failures="0" skipped="5" tests="358" time="555.166" timestamp="2026-10-15T19:33:18+05:45">`; tail reads `353 passed, 5 skipped in 555.26s`, `pytest process exit: 0`. The 5 skips are `tests/test_tls_install.py` (Linux/OpenSSL only). |
| Browser suite | `artifacts/pilot-browser.xml`, `pilot-browser.txt` | `errors="0" failures="0" skipped="0" tests="8" time="209.433"`; tail reads `8 passed in 210.13s`. |
| Browser failure diagnosis | `artifacts/pilot-browser-diagnostic.xml`, `pilot-browser-diagnostic.txt` | The superseded single-test run, `failures="1" tests="1"`, retained to show the `.mjs` MIME fault before the fixture correction. |
| Earlier configuration run | `artifacts/pilot-configuration.xml` | `failures="1" tests="33"` at 19:15, failing `test_pilot_uses_remote_verified_database_and_private_scanner` with `AssertionError: assert '4294967296' == (4 * (1024 ** 3))` — a string/int comparison in the test, corrected before the 19:33 full run. **This is an intermediate run, superseded by `pilot-nonbrowser.xml`; it is not a passing result.** |
| Database collision run | `artifacts/pilot-nonbrowser-database-collision.txt` | The discarded run that collided on `test_ssdc`. Not counted as a result. |
| Python dependency audits | `artifacts/pilot-pip-audit.json`, `pilot-dev-audit.json` | Per-package `"vulns": []` entries. |
| npm production audit | `artifacts/pilot-npm-audit.json` | `"vulnerabilities": {}` with all severity counters at 0. |
| Image builds | `artifacts/pilot-build-app.txt`, `pilot-build-scanner.txt`, `pilot-build-proxy.txt` | AMD64 build logs for the three `*:pilot-candidate` tags. Not pushed. |
| Image audits | `artifacts/pilot-app-cves.sarif`, `pilot-scanner-cves.sarif`, `pilot-proxy-cves.sarif` (+ `.txt` console logs) | App SARIF holds 28 rules: **1 at security-severity 8.3 (HIGH), 1 at 4.1 (MEDIUM), 26 at 3.1 (LOW)**; console log ends `Detected 13 vulnerable packages with a total of 28 vulnerabilities`, `Scout exit: 2`. Scanner and proxy SARIF files are empty result sets. Per-finding evidence: [PILOT_IMAGE_AUDIT.md](PILOT_IMAGE_AUDIT.md). |
| Linux TLS installer tests | `artifacts/pilot-linux-tls.txt` | **Does not support the claim.** Contains a failed `docker run` (image `ssdc-app:latest` not present locally, pull denied). `artifacts/pilot-tls/` holds only the generated `server.crt` / `server.key` fixture pair. See the corrected row above. |
| Django `check`, `check --deploy`, `makemigrations --check`, `collectstatic`, Ruff, ClamAV INSTREAM self-test, local PostgreSQL TLS integration, Drive operational check | — | **No retained artifact.** These were observed in the terminal only. Re-run them with output captured to `artifacts/` before release sign-off; until then they are reported results, not evidence. |

The zlib advisory evidence (scanner record, upstream references and
distribution status) is reproduced in
[PILOT_IMAGE_AUDIT.md](PILOT_IMAGE_AUDIT.md#evidence-for-the-zlib-finding-recorded-16-october-2026).

## Remaining external gates / unrun checks

- **SSDC project access:** the connected account lists only Daynotes. User confirmed
  SSDC is a different project. No SQL/query/migration was run against Daynotes.
  Connect the correct account/project or privately bind its exact DB settings;
  verify project ref, plan, TLS certificate, roles and target before migration.
- **Hosting:** x86-64 Linux VM selected in principle; provider/account/region and
  eligibility remain unknown. Recommend 8 GiB with 4 GiB scanner allocation.
  No suitable ongoing-free x86 option was established among checked providers.
  Trial credits require a complete cost/expiry plan and approval before provisioning.
- **Hostname:** provide a controlled domain/subdomain. Reserved `.invalid`
  placeholders remain in the template. Production DNS, OAuth callbacks,
  certificates, HTTPS/proxy checks and renewal have not been configured.
- **Google owner:** private local bindings exist, but the owner must reconnect.
  Confirm the approved owner and production OAuth client privately, publish the
  appropriate consent configuration, preserve the encryption key and verify
  synthetic upload/view/delete and owner-only Drive permissions.
- **Hosted acceptance:** readiness, sign-in/MFA, ACL denials, scan processing,
  Drive content, replacement/history, archive/deletion/restoration, audit records
  and behavior across restarts all remain unrun on a hosted target.
- **Recovery/operations:** choose offsite backup destination, retention, schedule,
  alert owner and RPO/RTO; run a complete paired restore drill. No scheduled
  backups or target-host timers have been enabled here. Application-image CVE
  remediation/vendor determination and independent security review remain open.

Deployment commands, secure bindings, current official-source limits, backup and
restore procedures are in [HOSTED_PILOT.md](HOSTED_PILOT.md) and
[pilot.env.example](../deploy/pilot.env.example). No secret values are requested
in chat. Public deployment and paid resources remain subject to explicit approval.
