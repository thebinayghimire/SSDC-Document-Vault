import re
import subprocess
import sys
from urllib.parse import parse_qs, urlsplit

import pytest
from django.test import Client
from django.urls import URLPattern, URLResolver, get_resolver

from accounts.services.account_tag import compute_account_tag

from .conftest import authenticate_client

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Item 1: Folder / Unauthenticated Redirect Tests
# ---------------------------------------------------------------------------


def test_unauthenticated_folder_access_redirects_to_neutral_login(client, folder):
    # Mitigates unauthorized data discovery by forcing authentication before folder browsing
    folder_url = f"/folders/{folder.pk}/"
    response = client.get(folder_url)
    assert response.status_code == 302
    assert response.url.startswith("/accounts/login/?next=")
    parsed = urlsplit(response.url)
    query = parse_qs(parsed.query)
    assert query["next"][0] == folder_url


def test_unauthenticated_folder_with_query_params_preserves_next_destination(client, folder):
    # Mitigates loss of navigation state during unauthenticated redirection
    folder_url = f"/folders/{folder.pk}/?view=gallery&sort=name"
    response = client.get(folder_url)
    assert response.status_code == 302
    parsed = urlsplit(response.url)
    query = parse_qs(parsed.query)
    assert query["next"][0] == folder_url


def test_unauthenticated_root_shows_public_landing_page(client):
    # Preserves public landing portal entry without disclosing private vault documents
    response = client.get("/")
    assert response.status_code == 200
    assert b"SSDC Document Vault" in response.content


def test_admin_logging_in_from_folder_redirect_lands_at_folder(client, users, folder, settings):
    # Validates safe_portal_destination routing for administrators accessing folders
    settings.MFA_ENABLED = False
    folder_url = f"/folders/{folder.pk}/"
    response = client.post(
        "/accounts/login/?next=" + folder_url,
        {"staff_id": "admin", "password": "Strong-Admin-Password-42"},
    )
    assert response.url == folder_url
    assert client.get(folder_url).status_code == 200


def test_staff_logging_in_from_folder_redirect_lands_at_folder(client, users, folder, settings):
    # Validates safe_portal_destination routing for permitted staff accessing folders
    settings.MFA_ENABLED = False
    folder_url = f"/folders/{folder.pk}/"
    response = client.post(
        "/accounts/login/?next=" + folder_url,
        {"staff_id": "alice", "password": "Strong-Staff-Password-42"},
    )
    assert response.url == folder_url
    assert client.get(folder_url).status_code == 200


# ---------------------------------------------------------------------------
# Item 2: Anonymous Route Sweep Test
# ---------------------------------------------------------------------------

# Explicit allowlist of intentionally public endpoints
PUBLIC_ROUTE_ALLOWLIST = {
    # Public root landing portal
    "",
    # Authentication endpoints
    "accounts/login/",
    "accounts/admin/login/",
    "accounts/staff/login/",
    "accounts/session/",
    "accounts/mfa/",
    "accounts/mfa/enroll/",
    # Public self-registration workflows
    "accounts/register/",
    "accounts/register/verify/",
    "accounts/register/resend/",
    "accounts/register/resend-email/",
    "accounts/register/status/",
    "accounts/register/verify/<str:token>/",
    "accounts/register/resend/<str:token>/",
    "accounts/register/status/<str:token>/",
    # Operational health checks
    "health/",
    "live/",
    # Public legal documents
    "privacy/",
    "terms/",
    # Public localization assets
    "jsi18n/",
    "i18n/setlang/",
    # Django Admin login entry point and JS catalog
    "admin/login/",
    "admin/jsi18n/",
}


def _walk_url_patterns(patterns, prefix=""):
    for p in patterns:
        if isinstance(p, URLPattern):
            yield prefix + str(p.pattern), p.name, p.callback
        elif isinstance(p, URLResolver):
            yield from _walk_url_patterns(p.url_patterns, prefix + str(p.pattern))


def _sample_url_for_pattern(pattern_str):
    url = pattern_str.lstrip("^").rstrip("$")
    url = re.sub(r"<uuid:[^>]+>", "00000000-0000-0000-0000-000000000000", url)
    url = re.sub(r"<int:[^>]+>", "1", url)
    url = re.sub(r"<str:[^>]+>", "sample-token", url)
    url = re.sub(r"<path:content_type_id>", "1", url)
    url = re.sub(r"<path:object_id>", "1", url)
    url = re.sub(r"<id>", "1", url)
    url = re.sub(r"\(\?P<app_label>accounts\|audit\|vault\)", "accounts", url)
    url = re.sub(r"\(\?P<url>\.\*\)", "test", url)
    return "/" + url


def test_anonymous_route_sweep_every_route_protected():
    """
    Walks every registered URL pattern. Asserts that any route NOT on the explicit
    public allowlist returns 302 to a login URL, 401, 403, or 404.
    """
    client = Client()
    patterns = list(_walk_url_patterns(get_resolver().url_patterns))
    assert len(patterns) >= 50

    login_endpoints = (
        "/accounts/login/",
        "/accounts/staff/login/",
        "/accounts/admin/login/",
        "/admin/login/",
    )

    for pat, name, callback in patterns:
        sample_path = _sample_url_for_pattern(pat)
        response = client.get(sample_path)
        status = response.status_code

        if pat in PUBLIC_ROUTE_ALLOWLIST:
            # Allowlist routes may return 200, 302 (redirect to login/home), 404 (invalid token), or 405 (POST-only)
            assert status in {200, 302, 404, 405}, (
                f"Unexpected status {status} for public route {pat}"
            )
        else:
            # Any route NOT on the public allowlist MUST reject anonymous visitors
            assert status in {302, 401, 403, 404}, (
                f"Security breach: Route '{pat}' (path '{sample_path}') returned {status} to anonymous request"
            )
            if status == 302:
                location = response.headers.get("Location", "")
                if not any(lp in location for lp in login_endpoints):
                    # Check if the redirection chain leads to a login endpoint
                    chain = client.get(sample_path, follow=True).redirect_chain
                    final_dest = chain[-1][0] if chain else ""
                    assert any(lp in final_dest for lp in login_endpoints), (
                        f"Route '{pat}' redirect chain does not lead to login: {chain}"
                    )


# ---------------------------------------------------------------------------
# Item 3: Cross-Tab Sync and Account-Switch Detection Tests
# ---------------------------------------------------------------------------


def test_account_tag_is_salted_hmac_and_irreversible(users):
    user = users["alice"]
    session = {"portal_session": "secrettoken123456", "auth_version": user.auth_version}
    tag = compute_account_tag(user, session)
    assert tag is not None
    assert len(tag) == 16
    assert re.fullmatch(r"[a-f0-9]{16}", tag)
    # Never matches raw user ID, auth version, or portal session
    assert str(user.pk) != tag
    assert "secrettoken123456" not in tag


def test_session_status_returns_account_tag_without_secrets(client, users):
    # Unauthenticated
    resp = client.get("/accounts/session/")
    assert resp.json() == {
        "authenticated": False,
        "account_tag": None,
        "home_url": "/accounts/login/",
    }

    # Authenticated as Alice
    authenticate_client(client, users["alice"])
    client.session["portal_session"] = "aliceportalhexsecret123"
    client.session.save()

    resp = client.get("/accounts/session/")
    data = resp.json()
    assert data["authenticated"] is True
    assert data["account_tag"] is not None
    assert len(data["account_tag"]) == 16
    assert data["home_url"] == "/staff/"

    # Assert raw secrets are NOT in response JSON
    assert "portal_session" not in data
    assert "user_id" not in data
    assert "pk" not in data
    assert "auth_version" not in data
    assert "aliceportalhexsecret123" not in resp.content.decode()


def test_meta_tag_renders_account_tag_and_no_portal_session_or_pk(client, users):
    authenticate_client(client, users["alice"])
    client.session["portal_session"] = "aliceportalhexsecret123"
    client.session.save()

    response = client.get("/staff/")
    html = response.content.decode()

    # Meta tag must contain data-account-tag
    tag = compute_account_tag(users["alice"], client.session)
    assert f'data-account-tag="{tag}"' in html
    # Meta content attribute must be empty
    assert (
        '<meta name="vault-session"\n      content=""' in html
        or '<meta name="vault-session" content=""' in html
    )

    # Raw secrets must NEVER appear in HTML
    assert "aliceportalhexsecret123" not in html
    assert f"{users['alice'].pk}:" not in html


def test_cross_tab_account_switch_detected_on_focus(client, users):
    """
    Test requirement: tab 1 signs in as A; tab 2 signs out and signs in as B;
    tab 1, on focus, queries /accounts/session/, detects tag mismatch, and treats itself as signed out.
    """
    # Tab 1 signs in as Alice
    authenticate_client(client, users["alice"])
    client.session["portal_session"] = "alice-session-token"
    client.session.save()
    tab1_tag = compute_account_tag(users["alice"], client.session)

    # Tab 1 verifies session status initially
    status1 = client.get("/accounts/session/").json()
    assert status1["authenticated"] is True
    assert status1["account_tag"] == tab1_tag

    # Tab 2 signs out and signs in as Bob
    client.post("/accounts/logout/")
    authenticate_client(client, users["bob"])
    client.session["portal_session"] = "bob-session-token"
    client.session.save()
    tab2_tag = compute_account_tag(users["bob"], client.session)
    assert tab1_tag != tab2_tag

    # Tab 1 receives focus: runs checkSession() -> queries /accounts/session/
    status_on_focus = client.get("/accounts/session/").json()
    assert status_on_focus["authenticated"] is True
    # Tab 1's stored tag does not match the live session's tag
    assert status_on_focus["account_tag"] != tab1_tag
    assert status_on_focus["account_tag"] == tab2_tag


# ---------------------------------------------------------------------------
# Item 4: Cookies and Transport Security Tests
# ---------------------------------------------------------------------------


def test_cookie_security_defaults_via_subprocess():
    """
    Spawns Python to verify that default settings (without ALLOW_INSECURE_COOKIES)
    enforce __Host-sessionid, Secure=True, and CSRF_COOKIE_SECURE=True.
    """
    code = """
import os, sys
os.environ.pop("ALLOW_INSECURE_COOKIES", None)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django
django.setup()
from django.conf import settings
print(settings.SESSION_COOKIE_NAME)
print(settings.SESSION_COOKIE_SECURE)
print(settings.CSRF_COOKIE_SECURE)
print(settings.SESSION_COOKIE_PATH)
print(settings.SESSION_COOKIE_DOMAIN)
print(settings.SESSION_COOKIE_SAMESITE)
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    lines = [line.strip() for line in result.stdout.strip().splitlines()]
    assert lines[0] == "__Host-sessionid"
    assert lines[1] == "True"
    assert lines[2] == "True"
    assert lines[3] == "/"
    assert lines[4] == "None"
    assert lines[5] == "Lax"


def test_allow_insecure_cookies_rejected_when_debug_false():
    """
    ALLOW_INSECURE_COOKIES=1 when DEBUG is False must raise ImproperlyConfigured.
    """
    code = """
import os, sys
os.environ["ALLOW_INSECURE_COOKIES"] = "1"
os.environ["DEBUG"] = "0"
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django
django.setup()
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode != 0
    assert "ImproperlyConfigured" in result.stderr
    assert "ALLOW_INSECURE_COOKIES=1 is only permitted when DEBUG=1" in result.stderr


def test_allow_insecure_cookies_rejected_when_allowed_hosts_external():
    """
    ALLOW_INSECURE_COOKIES=1 when ALLOWED_HOSTS contains non-local domains must raise ImproperlyConfigured.
    """
    code = """
import os, sys
os.environ["ALLOW_INSECURE_COOKIES"] = "1"
os.environ["DEBUG"] = "1"
os.environ["ALLOWED_HOSTS"] = "localhost,vault.ssdc.org"
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django
django.setup()
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode != 0
    assert "ImproperlyConfigured" in result.stderr
    assert "ALLOW_INSECURE_COOKIES=1 is only permitted when DEBUG=1" in result.stderr


def test_allow_insecure_cookies_allowed_in_local_debug():
    """
    ALLOW_INSECURE_COOKIES=1 when DEBUG=1 and hosts are local must set sessionid and Secure=False.
    """
    code = """
import os, sys
os.environ["ALLOW_INSECURE_COOKIES"] = "1"
os.environ["DEBUG"] = "1"
os.environ["ALLOWED_HOSTS"] = "localhost,127.0.0.1"
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django
django.setup()
from django.conf import settings
print(settings.SESSION_COOKIE_NAME)
print(settings.SESSION_COOKIE_SECURE)
print(settings.CSRF_COOKIE_SECURE)
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    lines = [line.strip() for line in result.stdout.strip().splitlines()]
    assert lines[0] == "sessionid"
    assert lines[1] == "False"
    assert lines[2] == "False"
