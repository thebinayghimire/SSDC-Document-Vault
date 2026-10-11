"""Verify localhost TLS fixture; does not validate a public domain certificate."""

import argparse
import io
import json
import os
import subprocess
import time
from pathlib import Path

import pyotp
from playwright.sync_api import expect, sync_playwright
from pypdf import PdfWriter
from smoke_safety import require_isolated_smoke

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--retain-fixture",
    type=Path,
    help="Private synthetic credentials for an isolated restore check",
)
args = parser.parse_args()

compose = [
    "docker",
    "compose",
    "--project-name",
    "ssdc-vault-smoke",
    "--env-file",
    ".env.production-smoke",
    "-f",
    "compose.prod.yaml",
    "-f",
    "deploy/compose.smoke.yaml",
]
config = json.loads(
    subprocess.run(
        compose + ["config", "--format", "json"], check=True, capture_output=True, text=True
    ).stdout
)
require_isolated_smoke(config)
code = (
    "import os,django,secrets,json; os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings'); django.setup(); "
    "from accounts.models import User; from vault.models import Folder,FolderGrant; "
    "from accounts.mfa import encrypt; import pyotp; "
    "password=secrets.token_urlsafe(24); seed=pyotp.random_base32(); user=User.objects.create_superuser('smoke.'+secrets.token_hex(4),password=password); "
    "user.mfa_secret=encrypt(seed); user.mfa_confirmed=True; user.save(update_fields=['mfa_secret','mfa_confirmed']); "
    "folder=Folder.objects.create(name='Synthetic TLS smoke folder'); FolderGrant.objects.create(folder=folder,user=user); "
    "print(json.dumps({'username':user.username,'password':password,'seed':seed,'user_id':user.pk,'folder_id':str(folder.pk)}))"
)
result = subprocess.run(
    compose + ["exec", "-T", "app", "python", "-c", code],
    check=True,
    capture_output=True,
    text=True,
)
data = json.loads(result.stdout)
succeeded = False
document_id = None
try:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        deadline = time.monotonic() + 120
        while True:
            response = page.goto("https://localhost:8443/health/")
            if response.status == 200 or time.monotonic() >= deadline:
                break
            time.sleep(1)
        assert response.status == 200
        assert "max-age=31536000" in response.headers["strict-transport-security"]
        assert response.headers["x-frame-options"] == "DENY"
        assert "object-src 'none'" in response.headers["content-security-policy"]
        page.goto("https://localhost:8443/accounts/login/")
        page.get_by_label("Staff ID").fill(data["username"])
        page.get_by_label("Password:", exact=True).fill(data["password"])
        page.get_by_role("button", name="Sign in", exact=False).click()
        page.wait_for_url("https://localhost:8443/accounts/mfa/")
        page.get_by_label("Authenticator or recovery code").fill(pyotp.TOTP(data["seed"]).now())
        page.get_by_role("button", name="Continue", exact=True).click()
        page.wait_for_url("https://localhost:8443/")
        expect(page.get_by_role("heading", name="Your documents", exact=True)).to_be_visible()
        cookies = {cookie["name"]: cookie for cookie in context.cookies()}
        assert cookies["sessionid"]["secure"] and cookies["sessionid"]["httpOnly"]
        assert cookies["sessionid"]["sameSite"] == "Lax"
        assert cookies["csrftoken"]["secure"]
        buffer = io.BytesIO()
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        writer.add_blank_page(width=612, height=792)
        writer.write(buffer)
        page.goto("https://localhost:8443/folders/" + data["folder_id"] + "/upload/")
        page.get_by_label("Title:", exact=True).fill("Synthetic production PDF")
        page.get_by_label("PDF or image").set_input_files(
            {"name": "synthetic.pdf", "mimeType": "application/pdf", "buffer": buffer.getvalue()}
        )
        page.get_by_role("button", name="Upload document", exact=True).click()
        page.wait_for_url("**/manage/", timeout=60000)
        expect(page.get_by_text("Ready", exact=True).first).to_be_visible(timeout=30000)
        document_id = page.url.split("/documents/")[1].split("/")[0]
        page.goto("https://localhost:8443/documents/" + document_id + "/")
        expect(page.locator('#pdf-canvas[data-rendered="true"]')).to_be_visible(timeout=30000)
        content_url = page.locator("#viewer").get_attribute("data-url")
        ranged = context.request.get(
            "https://localhost:8443" + content_url, headers={"Range": "bytes=0-9"}
        )
        assert ranged.status == 206 and len(ranged.body()) == 10
        page.get_by_role("button", name="Next page", exact=True).click()
        expect(page.locator("#pdf-canvas")).to_have_attribute("data-page", "2", timeout=30000)
        assert not errors, errors
        page.get_by_role("button", name="Sign out", exact=True).click()
        expect(page.get_by_role("heading", name="Welcome back.")).to_be_visible()
        http = context.request.get("http://localhost:8081/health/", max_redirects=0)
        assert http.status == 301 and http.headers["location"] == "https://localhost:8443/health/"
        assert context.request.get(http.headers["location"]).status == 200
        browser.close()
        succeeded = True
finally:
    code = (
        "import os,django; os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings'); django.setup(); "
        "from accounts.models import User; from vault.models import Folder,Document; from django.db import connection; "
        f"Document.objects.filter(folder_id='{data['folder_id']}').delete(); Folder.objects.filter(pk='{data['folder_id']}').delete(); "
        # Retain immutable audit references. Users cannot be erased through the runtime role.
        f"User.objects.filter(pk={data['user_id']}).update(is_active=False)"
    )
    if args.retain_fixture and succeeded:
        args.retain_fixture.parent.mkdir(parents=True, exist_ok=True)
        with os.fdopen(
            os.open(args.retain_fixture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
        ) as stream:
            json.dump({**data, "document_id": document_id}, stream)
    else:
        subprocess.run(
            compose + ["exec", "-T", "app", "python", "-c", code], check=True, capture_output=True
        )
print(
    "Production TLS smoke passed: privileged MFA, scanned upload, parser sandbox, PDF render/ranges, HTTPS headers/cookies and followed canonical redirect."
)
