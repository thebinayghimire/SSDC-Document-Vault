"""Browser regression checks using development-only synthetic demo data."""

import argparse
import json
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--base-url", default="http://127.0.0.1:8080")
parser.add_argument("--credentials", type=Path, default=Path("artifacts/demo-credentials.json"))
args = parser.parse_args()
credentials = json.loads(args.credentials.read_text())
Path("artifacts").mkdir(exist_ok=True)
base = args.base_url.rstrip("/")


def login(page, username):
    page.goto(base + "/accounts/login/")
    page.get_by_label("Staff ID").fill(username)
    page.get_by_label("Password:", exact=True).fill(credentials[username])
    page.get_by_role("button", name="Sign in", exact=False).click()
    page.wait_for_url(base + "/")


with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(base + "/accounts/login/")
    page.screenshot(path="artifacts/login.png", full_page=True)
    login(page, "demo.staff")
    expect(page.get_by_role("heading", name="Your documents")).to_be_visible()
    expect(page.get_by_text("Programme overview - sample report", exact=True)).to_be_visible()
    expect(page.get_by_text("Finance & operations", exact=True)).to_have_count(0)
    page.screenshot(path="artifacts/library.png", full_page=True)
    page.get_by_label("Search documents").fill("overview")
    page.get_by_role("button", name="Search", exact=True).click()
    expect(page.get_by_text("Workspace illustration - sample image", exact=True)).to_have_count(0)
    page.goto(base + "/?view=gallery")
    expect(page.locator(".document-card")).to_have_count(2)
    page.screenshot(path="artifacts/gallery.png", full_page=True)
    page.goto(base + f"/documents/{credentials['pdf_id']}/")
    page.locator('canvas[data-rendered="true"]').wait_for(timeout=30000)
    expect(page.locator("#viewer-message")).to_be_hidden()
    expect(page.locator(".watermark")).to_have_count(0)
    expect(page.get_by_role("button", name="Download", exact=True)).to_have_count(0)
    expect(page.get_by_role("button", name="Print", exact=True)).to_have_count(0)
    page.get_by_label("Next page", exact=True).click()
    expect(page.get_by_label("Page number", exact=True)).to_have_value("2")
    page.get_by_label("Zoom in", exact=True).click()
    page.screenshot(path="artifacts/pdf-viewer.png", full_page=True)
    page.goto(base + f"/documents/{credentials['image_id']}/")
    expect(page.locator("#viewer-message")).to_be_hidden(timeout=15000)
    expect(page.locator("#image-preview")).to_be_visible()
    page.screenshot(path="artifacts/image-viewer.png", full_page=True)
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(base + "/")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (
        "Mobile layout overflows"
    )
    page.screenshot(path="artifacts/mobile-library.png", full_page=True)
    page.get_by_role("button", name="Sign out", exact=True).click()
    expect(page.get_by_role("heading", name="Welcome back.")).to_be_visible()
    login(page, "demo.other")
    response = page.goto(base + f"/documents/{credentials['pdf_id']}/content/")
    assert response.status == 404
    assert not errors, "Browser JavaScript errors: " + "; ".join(errors)
    browser.close()
print(
    "Browser checks passed: login, ACL-filtered library, search, gallery, PDF pages/zoom, image, no watermark, mobile, logout, cross-user denial."
)
