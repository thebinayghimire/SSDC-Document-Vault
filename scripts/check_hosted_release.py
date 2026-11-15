"""Read-only production checks: trusted HTTPS, readiness, headers and secure CSRF cookies."""

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import requests


def check_hosted_release(base_url, *, session=None, verify=True):
    origin = urlsplit(base_url)
    if (
        origin.scheme != "https"
        or not origin.hostname
        or origin.username
        or origin.password
        or origin.query
        or origin.fragment
        or origin.path not in {"", "/"}
    ):
        raise ValueError("Use the public HTTPS origin without credentials, path or query")
    base = base_url.rstrip("/")
    client = session or requests.Session()
    failures = []
    checks = {}
    for path in ("/live/", "/health/", "/accounts/login/", "/manage/"):
        try:
            response = client.get(
                base + path, timeout=(10, 30), allow_redirects=False, verify=verify
            )
            checks[path] = {"status": response.status_code}
            if path == "/manage/":
                destination = urlsplit(response.headers.get("Location", ""))
                if response.status_code != 302 or destination.path != "/accounts/login/":
                    failures.append("unauthenticated_management_access")
                continue
            if response.status_code != 200:
                failures.append(path.strip("/").replace("/", "_") + "_unavailable")
                continue
            if path in {"/live/", "/health/"}:
                if response.json().get("status") != ("alive" if path == "/live/" else "ok"):
                    failures.append("invalid_health_response")
                continue
            hsts = response.headers.get("Strict-Transport-Security", "")
            age = re.search(r"(?:^|;)\s*max-age=(\d+)", hsts, re.I)
            if not age or int(age[1]) <= 0:
                failures.append("hsts_missing")
            if response.headers.get("X-Frame-Options", "").upper() != "DENY":
                failures.append("frame_protection_missing")
            csp = response.headers.get("Content-Security-Policy", "")
            if not all(rule in csp for rule in ("object-src 'none'", "frame-ancestors 'none'")):
                failures.append("content_security_policy_missing")
            if "no-store" not in response.headers.get("Cache-Control", ""):
                failures.append("private_cache_policy_missing")
            cookies = [cookie for cookie in response.cookies if cookie.name == "csrftoken"]
            if not cookies or not all(cookie.secure for cookie in cookies):
                failures.append("csrf_cookie_not_secure")
        except (requests.RequestException, ValueError):
            checks[path] = {"status": "unreachable_or_invalid"}
            failures.append("endpoint_unreachable_or_invalid")
    return {
        "origin": base,
        "checked_utc": datetime.now(UTC).isoformat(),
        "passed": not failures,
        "failures": sorted(set(failures)),
        "checks": checks,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument(
        "--ca-file", type=Path, help="Optional trusted CA file for an isolated TLS fixture"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check_hosted_release(args.base_url, verify=str(args.ca_file) if args.ca_file else True)
    body = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body)
    print(body, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
