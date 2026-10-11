"""Verify recovered MFA and document permissions on the isolated localhost restore."""

import argparse
import json
from pathlib import Path

import pyotp
from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.fixture.read_text())
    base = "https://localhost:8443"
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(base + "/accounts/login/")
        page.get_by_label("Staff ID").fill(data["username"])
        page.get_by_label("Password:", exact=True).fill(data["password"])
        page.get_by_role("button", name="Sign in", exact=False).click()
        page.wait_for_url("**/accounts/mfa/")
        page.get_by_label("Authenticator or recovery code").fill(pyotp.TOTP(data["seed"]).now())
        page.get_by_role("button", name="Continue", exact=True).click()
        page.wait_for_url(base + "/")
        assert page.goto(base + "/documents/" + data["document_id"] + "/").status == 200
        expect(page.locator('#pdf-canvas[data-rendered="true"]')).to_be_visible(timeout=30000)
        content = page.locator("#viewer").get_attribute("data-url")
        assert context.request.get(base + content, headers={"Range": "bytes=0-9"}).status == 206
        page.get_by_role("button", name="Sign out", exact=True).click()
        assert context.request.get(base + content, max_redirects=0).status == 302
        browser.close()
    print(
        "Isolated restored portal passed: original MFA key/login, original document/PDF/ranges and post-logout denial."
    )


if __name__ == "__main__":
    main()
