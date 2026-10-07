"""Verify localhost TLS fixture; does not validate a public domain certificate."""

import json
import subprocess

from playwright.sync_api import expect, sync_playwright

compose = [
    "docker",
    "compose",
    "--env-file",
    ".env.production-smoke",
    "-f",
    "compose.prod.yaml",
    "-f",
    "deploy/compose.smoke.yaml",
]
code = (
    "import os,django,secrets,json; os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings'); django.setup(); "
    "from accounts.models import User; from vault.models import Folder,FolderGrant; "
    "password=secrets.token_urlsafe(24); user=User.objects.create_user('smoke.'+secrets.token_hex(4),password=password); "
    "folder=Folder.objects.create(name='Synthetic TLS smoke folder'); FolderGrant.objects.create(folder=folder,user=user); "
    "print(json.dumps({'username':user.username,'password':password,'user_id':user.pk,'folder_id':str(folder.pk)}))"
)
result = subprocess.run(
    compose + ["exec", "-T", "app", "python", "-c", code],
    check=True,
    capture_output=True,
    text=True,
)
data = json.loads(result.stdout)
try:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        response = page.goto("https://localhost:8443/health/")
        assert response.status == 200
        assert "max-age=31536000" in response.headers["strict-transport-security"]
        assert response.headers["x-frame-options"] == "DENY"
        assert "object-src 'none'" in response.headers["content-security-policy"]
        page.goto("https://localhost:8443/accounts/login/")
        page.get_by_label("Staff ID").fill(data["username"])
        page.get_by_label("Password:", exact=True).fill(data["password"])
        page.get_by_role("button", name="Sign in", exact=False).click()
        page.wait_for_url("https://localhost:8443/")
        expect(page.get_by_role("heading", name="Your documents")).to_be_visible()
        cookies = {cookie["name"]: cookie for cookie in context.cookies()}
        assert cookies["sessionid"]["secure"] and cookies["sessionid"]["httpOnly"]
        assert cookies["sessionid"]["sameSite"] == "Strict"
        assert cookies["csrftoken"]["secure"]
        page.get_by_role("button", name="Sign out", exact=True).click()
        expect(page.get_by_role("heading", name="Welcome back.")).to_be_visible()
        http = context.request.get("http://localhost:8081/health/", max_redirects=0)
        assert http.status == 301 and http.headers["location"].startswith("https://")
        browser.close()
finally:
    code = (
        "import os,django; os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings'); django.setup(); "
        "from accounts.models import User; from vault.models import Folder; "
        f"Folder.objects.filter(pk='{data['folder_id']}').delete(); User.objects.filter(pk={data['user_id']}).delete()"
    )
    subprocess.run(
        compose + ["exec", "-T", "app", "python", "-c", code], check=True, capture_output=True
    )
print(
    "Production TLS smoke passed: HTTPS health/login/logout, secure cookies, HSTS/CSP/framing headers, HTTP redirect. Disposable account removed."
)
