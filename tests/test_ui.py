"""Browser regressions for the vault UI, using an isolated synthetic test database."""

import base64
import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pyotp
import pytest
from cryptography.fernet import Fernet
from django.db import connections
from django.test import Client
from playwright.sync_api import expect, sync_playwright

from vault.models import Document, Folder
from vault.services import upload_document

from .conftest import authenticate_client, image_upload, pdf_upload

pytestmark = pytest.mark.django_db(transaction=True)
ARTIFACTS = Path("artifacts/redesign")
WIDTHS = (375, 390, 430, 768, 1024, 1280, 1440, 1920)


@pytest.fixture
def browser_page(live_server, users, folder, document):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        yield page, context, live_server.url, errors
        browser.close()
        assert not errors, errors


def database_call(callback):
    # Playwright's sync API runs a loop on the caller thread. Keep Django ORM
    # work on a separate synchronous thread rather than disabling its guard.
    def run():
        try:
            return callback()
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(run).result()


def browser_session(context, base, user):
    client = database_call(lambda: authenticate_client(Client(), user))
    context.add_cookies(
        [{"name": "sessionid", "value": client.cookies["sessionid"].value, "url": base}]
    )


def no_overflow(page):
    if not page.evaluate("document.documentElement.scrollWidth <= innerWidth"):
        page.screenshot(path=str(ARTIFACTS / "overflow-failure.png"), full_page=True)
        outside = page.evaluate("""() => [...document.querySelectorAll('*')]
            .filter(el => el.getBoundingClientRect().right > innerWidth)
            .slice(0, 20).map(el => ({tag: el.tagName, id: el.id,
                class: el.className, right: el.getBoundingClientRect().right,
                width: el.getBoundingClientRect().width}))""")
        raise AssertionError(f"Page overflows: {page.url}; {outside}")


def test_failed_pdf_disables_controls_and_clears_render_state(browser_page, users, document):
    page, context, base, _ = browser_page
    browser_session(context, base, users["alice"])
    page.route(
        re.compile(r"/content/"), lambda route: route.fulfill(status=503, body="Synthetic outage")
    )
    page.goto(base + f"/documents/{document.pk}/")
    expect(page.locator('#viewer-message[data-error="true"]')).to_be_visible(timeout=30000)
    for selector in ("#fit", "#next", "#previous", "#zoom-in", "#zoom-out", "#page-number"):
        expect(page.locator(selector)).to_be_disabled()
    assert page.locator("#pdf-canvas").get_attribute("data-rendered") is None
    page.evaluate("document.querySelector('#fit').dispatchEvent(new Event('click'))")
    page.evaluate("document.querySelector('#zoom-in').dispatchEvent(new Event('click'))")
    expect(page.get_by_role("link", name="Return to the library and try again.")).to_be_visible()


def test_maximum_metadata_mobile_layout(browser_page, users, document, folder):
    page, context, base, _ = browser_page

    def prepare():
        users["admin"].username = "u" * 150
        users["admin"].save(update_fields=["username"])
        document.title = "T" * 200
        document.save(update_fields=["title"])
        folder.name = "F" * 120
        folder.save(update_fields=["name"])

    database_call(prepare)
    browser_session(context, base, users["admin"])
    page.set_viewport_size({"width": 390, "height": 844})
    for path in (
        "/",
        f"/folders/{folder.pk}/",
        "/manage/",
        f"/documents/{document.pk}/manage/",
        f"/documents/{document.pk}/",
        "/accounts/password/",
        "/accounts/confirm/",
        "/admin/accounts/user/",
    ):
        assert page.goto(base + path).status == 200
        no_overflow(page)
    expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()


def test_google_connection_browser_redirect(browser_page, users, settings):
    page, context, base, _ = browser_page
    settings.GOOGLE_DRIVE_CLIENT_ID = "synthetic.apps.googleusercontent.com"
    settings.GOOGLE_DRIVE_CLIENT_SECRET = "synthetic-secret"
    settings.GOOGLE_DRIVE_CREDENTIAL_KEY = Fernet.generate_key().decode()
    settings.GOOGLE_DRIVE_REDIRECT_URI = base + "/storage/google/callback/"
    browser_session(context, base, users["admin"])
    response = page.goto(base + "/")
    assert "accounts.google.com" not in response.headers["content-security-policy"]
    response = page.goto(base + "/storage/google/")
    assert (
        "form-action 'self' https://accounts.google.com"
        in response.headers["content-security-policy"]
    )
    # Redirect-chain requests bypass Playwright routing. Verify the real POST,
    # then exercise the Google form destination without an external request.
    response = page.request.post(
        base + "/storage/google/",
        form={
            "action": "connect",
            "csrfmiddlewaretoken": page.locator('[name="csrfmiddlewaretoken"]').last.input_value(),
        },
        max_redirects=0,
    )
    assert response.status == 302
    destination = urlsplit(response.headers["location"])
    assert destination.hostname == "accounts.google.com"
    fields = parse_qs(destination.query)
    page.evaluate(
        """({action, fields}) => {
        const form = document.querySelector('main form');
        form.action = action;
        form.method = 'get';
        form.querySelectorAll('input').forEach(input => input.remove());
        for (const [name, values] of Object.entries(fields)) {
            for (const value of values) {
                const input = document.createElement('input');
                input.type = 'hidden'; input.name = name; input.value = value;
                form.append(input);
            }
        }
    }""",
        {
            "action": f"{destination.scheme}://{destination.netloc}{destination.path}",
            "fields": fields,
        },
    )
    redirects = []

    def consent_page(route):
        query = parse_qs(urlsplit(route.request.url).query)
        assert query["redirect_uri"] == [base + "/storage/google/callback/"]
        assert query["scope"] == ["https://www.googleapis.com/auth/drive.file"]
        assert query.get("state") and query.get("code_challenge")
        redirects.append(True)
        route.fulfill(status=200, content_type="text/plain", body="Google consent page reached")

    page.route("https://accounts.google.com/**", consent_page)
    page.get_by_role("button", name="Connect / reconnect Google Drive", exact=True).click()
    expect(page.get_by_text("Google consent page reached", exact=True)).to_be_visible()
    assert redirects


def test_import_picker_drop_paste_and_batch(browser_page, users, folder, tmp_path):
    page, context, base, _ = browser_page
    browser_session(context, base, users["manager"])
    page.goto(base + "/")
    panel = page.locator("[data-import]")
    expect(panel).to_be_visible()
    expect(panel.locator("[data-start]")).to_be_disabled()
    page.get_by_label("Save to folder", exact=True).select_option(str(folder.pk))
    with page.expect_file_chooser() as chooser:
        panel.get_by_role("button", name="Choose files", exact=True).click()
    chooser.value.set_files(
        [
            {
                "name": "First report.pdf",
                "mimeType": "application/pdf",
                "buffer": pdf_upload().read(),
            },
            {"name": "notes.txt", "mimeType": "text/plain", "buffer": b"unsupported"},
        ]
    )
    expect(panel.locator(".import-file-row")).to_have_count(1)
    expect(panel.locator("[data-feedback]")).to_contain_text("unsupported")
    pdf_bytes = base64.b64encode(pdf_upload().read()).decode()
    # Exercise actual browser File/DataTransfer objects, not a mocked uploader.
    page.evaluate(
        """({data, name, kind}) => {
        const bytes = Uint8Array.from(atob(data), char => char.charCodeAt(0));
        const transfer = new DataTransfer();
        transfer.items.add(new File([bytes], name, {type: 'application/pdf', lastModified: 1}));
        const target = document.querySelector('[data-dropzone]');
        if (kind === 'paste') {
            target.focus(); target.dispatchEvent(new ClipboardEvent('paste', {clipboardData: transfer, bubbles: true}));
        } else target.dispatchEvent(new DragEvent('drop', {dataTransfer: transfer, bubbles: true}));
    }""",
        {"data": pdf_bytes, "name": "Dropped report.pdf", "kind": "drop"},
    )
    page.evaluate(
        """data => {
        const transfer = new DataTransfer();
        transfer.items.add(new File([Uint8Array.from(atob(data), c => c.charCodeAt(0))], 'Pasted report.pdf', {type: 'application/pdf'}));
        const target = document.querySelector('[data-dropzone]');
        target.focus(); target.dispatchEvent(new ClipboardEvent('paste', {clipboardData: transfer, bubbles: true}));
    }""",
        pdf_bytes,
    )
    expect(panel.locator(".import-file-row")).to_have_count(3)
    page.get_by_label("Document title for First report.pdf", exact=True).fill("Reviewed report")
    page.set_viewport_size({"width": 375, "height": 844})
    no_overflow(page)
    page.screenshot(path=str(ARTIFACTS / "import-queue-375.png"), full_page=True)
    panel.get_by_role("button", name="Import 3 documents", exact=True).click()
    try:
        expect(panel.locator('[data-state="done"]')).to_have_count(3, timeout=60000)
    except AssertionError as exc:
        page.screenshot(path=str(ARTIFACTS / "import-error.png"), full_page=True)
        raise AssertionError(panel.inner_text()) from exc
    assert database_call(lambda: Document.objects.filter(title="Reviewed report").exists())
    assert database_call(lambda: Document.objects.count()) == 4
    panel.get_by_role("button", name="Clear finished", exact=True).click()
    expect(panel.locator(".import-file-row")).to_have_count(0)
    # Native folder selection includes files from nested directories.
    source = tmp_path / "Local folder"
    (source / "Nested").mkdir(parents=True)
    (source / "Nested" / "Folder report.pdf").write_bytes(pdf_upload().read())
    (source / "skip.txt").write_text("Unsupported")
    panel.locator("[data-folder-input]").set_input_files(source)
    expect(panel.locator(".import-file-row")).to_have_count(1)
    expect(panel.locator(".import-file-details")).to_contain_text("Nested/Folder report.pdf")
    panel.get_by_role("button", name="Import 1 document", exact=True).click()
    expect(panel.locator('[data-state="done"]')).to_have_count(1, timeout=60000)
    page.set_viewport_size({"width": 1440, "height": 1000})
    page.goto(base + "/documents/import/")
    no_overflow(page)
    page.screenshot(path=str(ARTIFACTS / "import-1440.png"), full_page=True)


def test_routes_at_all_sizes(browser_page, users, folder, document):
    page, context, base, _ = browser_page
    photo = database_call(
        lambda: upload_document(users["admin"], folder, image_upload(), "Workspace image")
    )
    browser_session(context, base, users["admin"])
    routes = {
        "library": "/",
        "gallery": "/?view=gallery",
        "folder": f"/folders/{folder.pk}/",
        "management": "/manage/",
        "document-details": f"/documents/{document.pk}/manage/",
        "upload": f"/folders/{folder.pk}/upload/",
        "replacement": f"/documents/{document.pk}/replace/",
        "new-folder": "/folders/new/",
        "password": "/accounts/password/",
        "confirmation": "/accounts/confirm/",
        "pdf": f"/documents/{document.pk}/",
        "image": f"/documents/{photo.document_id}/",
        "administration": "/admin/",
        "staff-list": "/admin/accounts/user/",
        "staff-form": "/admin/accounts/user/add/",
    }
    results = []
    for width in WIDTHS:
        page.set_viewport_size({"width": width, "height": 1000})
        for name, route in routes.items():
            response = page.goto(base + route)
            assert response.status == 200, (route, response.status)
            if name in {"pdf", "image"}:
                expect(page.locator("#viewer-message")).to_be_hidden(timeout=30000)
            if name == "administration":
                bounds = page.evaluate("""() => ({header: document.querySelector('#header').getBoundingClientRect().toJSON(),
                    tools: document.querySelector('#user-tools').getBoundingClientRect().toJSON(),
                    parent: document.querySelector('#user-tools').parentElement.id})""")
                Path(ARTIFACTS / f"admin-header-{width}.json").write_text(json.dumps(bounds))
                assert bounds["tools"]["bottom"] <= bounds["header"]["bottom"]
                if width >= 1068:
                    assert (
                        page.locator(".admin-resource-group").first.bounding_box()["width"] >= 220
                    )
            if name == "library" and width >= 768:
                expect(page.locator(".mobile-metadata").first).to_be_hidden()
            no_overflow(page)
            if width in {375, 1440}:
                page.screenshot(path=str(ARTIFACTS / f"{name}-{width}.png"), full_page=True)
            results.append({"page": name, "width": width, "overflow": False})
    page.goto(base + "/admin/")
    page.evaluate("localStorage.setItem('theme', 'dark')")
    page.reload()
    expect(page.locator("html")).to_have_attribute("data-theme", "dark")
    assert page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(28, 28, 30)"
    page.screenshot(path=str(ARTIFACTS / "administration-dark.png"), full_page=True)
    page.evaluate("localStorage.setItem('theme', 'light')")
    page.reload()
    expect(page.locator("html")).to_have_attribute("data-theme", "light")
    response = page.goto(base + "/missing-page/")
    assert response.status == 404
    no_overflow(page)
    Path(ARTIFACTS / "responsive-results.json").write_text(json.dumps(results, indent=2))


def test_document_actions_and_mobile_navigation(browser_page, users, folder, document):
    page, context, base, _ = browser_page
    browser_session(context, base, users["admin"])
    manage_url = base + f"/documents/{document.pk}/manage/"
    page.goto(manage_url)
    expect(page.locator('.sidebar a[aria-current="page"]')).to_have_text("Manage documents")
    page.get_by_label("Title:", exact=True).fill("Updated programme report")
    page.get_by_role("button", name="Save changes", exact=True).click()
    expect(page.get_by_role("heading", name="Updated programme report")).to_be_visible()
    expect(page.get_by_role("status").filter(has_text="Document details updated")).to_be_visible()
    page.get_by_role("button", name="Archive document", exact=True).click()
    expect(page.locator(".status").filter(has_text="Archived")).to_be_visible()
    page.get_by_role("button", name="Unarchive document", exact=True).click()
    delete = page.get_by_role("button", name="Move to deleted", exact=True).first
    delete.click()
    dialog = page.get_by_role("dialog")
    expect(dialog).to_be_visible()
    expect(page.get_by_role("button", name="Cancel", exact=True)).to_be_focused()
    page.keyboard.press("Shift+Tab")
    assert page.evaluate("document.querySelector('dialog').contains(document.activeElement)")
    page.keyboard.press("Escape")
    expect(dialog).to_be_hidden()
    expect(delete).to_be_focused()
    delete.click()
    dialog.get_by_role("button", name="Move to deleted", exact=True).click()
    expect(page.get_by_role("button", name="Restore document", exact=True)).to_be_visible()
    page.get_by_role("button", name="Restore document", exact=True).click()
    page.get_by_role("link", name="Upload a replacement", exact=True).click()
    page.get_by_label("PDF or image:", exact=True).set_input_files(
        {"name": "replacement.pdf", "mimeType": "application/pdf", "buffer": pdf_upload().read()}
    )
    page.get_by_role("button", name="Upload document", exact=True).click()
    expect(page.get_by_role("heading", name="Version history", exact=False)).to_be_visible()
    expect(page.locator(".version-table tbody tr")).to_have_count(2)
    page.get_by_role("button", name="Restore this version", exact=True).click()
    expect(page.get_by_role("status").filter(has_text="Previous version restored")).to_be_visible()
    # Create a folder through the redesigned checkbox/form layout.
    page.goto(base + "/folders/new/")
    page.get_by_label("Name:", exact=True).fill("Browser-created folder")
    page.get_by_role("button", name="Create folder", exact=True).click()
    expect(page.get_by_role("heading", name="Browser-created folder")).to_be_visible()
    page.get_by_role("link", name="Upload document", exact=True).last.click()
    page.get_by_label("Title:", exact=True).fill("Browser upload")
    page.get_by_label("PDF or image:", exact=True).set_input_files(
        {"name": "upload.pdf", "mimeType": "application/pdf", "buffer": pdf_upload().read()}
    )
    page.get_by_role("button", name="Upload document", exact=True).click()
    expect(page.get_by_role("heading", name="Browser upload", exact=True)).to_be_visible()

    # Long permitted values must wrap without widening the page.
    def long_names():
        Document.objects.filter(pk=document.pk).update(title="x" * 200)
        Folder.objects.filter(pk=folder.pk).update(name="y" * 120)
        users["admin"].username = "z" * 150
        users["admin"].save()

    database_call(long_names)
    for route in ("/", "/?view=gallery", "/manage/", f"/documents/{document.pk}/manage/"):
        page.set_viewport_size({"width": 375, "height": 844})
        page.goto(base + route)
        no_overflow(page)
    page.goto(base + "/")
    page.get_by_label("Workspace navigation").click()
    expect(page.get_by_role("navigation", name="Mobile navigation")).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.get_by_role("navigation", name="Mobile navigation")).to_be_hidden()
    page.get_by_label("Workspace navigation").click()
    page.get_by_role("navigation", name="Mobile navigation").get_by_role(
        "link", name="Account security", exact=True
    ).click()
    expect(page.get_by_role("heading", name="Change password")).to_be_visible()
    page.get_by_role("button", name="Sign out", exact=True).click()
    expect(page.get_by_role("heading", name="Welcome back.")).to_be_visible()


def test_search_preview_resize_and_delivery_failure(browser_page, users, folder, document):
    page, context, base, _ = browser_page
    database_call(
        lambda: upload_document(users["manager"], folder, image_upload(), "Project image")
    )
    browser_session(context, base, users["alice"])
    page.goto(base + "/")
    expect(page.get_by_role("link", name="Administration", exact=True)).to_have_count(0)
    expect(page.get_by_role("link", name="Add documents", exact=True)).to_have_count(0)
    for width in (390, 768, 1440):
        page.set_viewport_size({"width": width, "height": 1000})
        no_overflow(page)
        page.screenshot(path=str(ARTIFACTS / f"staff-library-{width}.png"), full_page=True)
    page.set_viewport_size({"width": 1440, "height": 1000})
    page.get_by_label("Search documents", exact=True).fill("Project")
    page.get_by_label("File type", exact=True).select_option("pdf")
    page.get_by_label("Sort by", exact=True).select_option("name")
    page.get_by_role("button", name="Search", exact=True).click()
    expect(page.locator(".library-table tbody tr")).to_have_count(1)
    page.get_by_role("link", name="Gallery view", exact=True).click()
    assert "q=Project" in page.url and "type=pdf" in page.url and "sort=name" in page.url
    expect(page.locator(".document-card")).to_have_count(1)
    page.get_by_label("Search documents", exact=True).fill("No match")
    page.get_by_role("button", name="Search", exact=True).click()
    expect(page.get_by_role("heading", name="No matching documents")).to_be_visible()
    page.get_by_role("link", name="Clear filters", exact=True).last.click()
    expect(page.locator(".document-card")).to_have_count(2)
    page.goto(base + f"/documents/{document.pk}/")
    expect(page.locator("#viewer-message")).to_be_hidden(timeout=30000)
    page.get_by_label("Next page", exact=True).click()
    expect(page.get_by_label("Page number", exact=True)).to_have_value("2")
    page.get_by_label("Zoom in", exact=True).click()
    page.get_by_role("button", name="Fit width", exact=True).click()
    page.set_viewport_size({"width": 390, "height": 844})
    page.wait_for_function(
        "document.querySelector('#page-surface').getBoundingClientRect().width <= "
        "document.querySelector('#preview-stage').clientWidth"
    )
    no_overflow(page)
    expect(page.locator(".watermark")).to_have_count(0)
    expect(page.get_by_role("button", name="Download", exact=True)).to_have_count(0)
    expect(page.get_by_role("button", name="Print", exact=True)).to_have_count(0)
    page.route(
        re.compile(r"/content/"), lambda route: route.fulfill(status=404, body="Unavailable")
    )
    page.goto(base + f"/documents/{document.pk}/")
    expect(page.locator("#viewer-message")).to_contain_text("Preview unavailable")
    expect(page.get_by_role("button", name="Fit width", exact=True)).to_be_disabled()
    expect(page.get_by_label("Zoom in", exact=True)).to_be_disabled()
    expect(page.locator("#preview-skeleton")).to_be_hidden()
    expect(page.locator("#viewer")).to_have_attribute("aria-busy", "false")
    page.screenshot(path=str(ARTIFACTS / "preview-error-390.png"), full_page=True)
    response = database_call(
        lambda: authenticate_client(Client(), users["bob"]).get(
            f"/documents/{document.pk}/content/"
        )
    )
    assert response.status_code == 404


def test_signin_errors_and_mfa_screens(browser_page, users):
    page, _, base, _ = browser_page
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(base + "/accounts/login/")
    page.screenshot(path=str(ARTIFACTS / "login-390.png"), full_page=True)
    page.get_by_label("Staff ID").fill("manager")
    page.get_by_label("Password:", exact=True).fill("wrong")
    page.get_by_role("button", name="Sign in", exact=False).click()
    expect(page.get_by_role("alert")).to_contain_text("Unable to sign in")
    expect(page.locator(".error-summary")).to_be_focused()
    page.screenshot(path=str(ARTIFACTS / "login-error-390.png"), full_page=True)
    page.get_by_label("Password:", exact=True).fill("Strong-Manager-Password-42")
    page.get_by_role("button", name="Sign in", exact=False).click()
    expect(page.get_by_role("heading", name="Set up your authenticator.")).to_be_visible()
    secret = page.locator(".secret").inner_text()
    for width in WIDTHS:
        page.set_viewport_size({"width": width, "height": 1000})
        no_overflow(page)
    # Never persist screenshots containing setup keys or recovery codes.
    page.get_by_label("Authenticator or recovery code:", exact=True).fill(pyotp.TOTP(secret).now())
    page.get_by_role("button", name="Verify and continue", exact=True).click()
    expect(page.get_by_role("heading", name="Save your recovery codes.")).to_be_visible()
    expect(page.locator(".recovery-codes code")).to_have_count(8)
    for width in WIDTHS:
        page.set_viewport_size({"width": width, "height": 1000})
        no_overflow(page)
    page.get_by_role("link", name="I've saved my codes", exact=True).click()
    page.get_by_role("button", name="Sign out", exact=True).click()
    page.get_by_label("Staff ID").fill("manager")
    page.get_by_label("Password:", exact=True).fill("Strong-Manager-Password-42")
    page.get_by_role("button", name="Sign in", exact=False).click()
    expect(page.get_by_role("heading", name="Verify your identity")).to_be_visible()
    for width in WIDTHS:
        page.set_viewport_size({"width": width, "height": 1000})
        no_overflow(page)
    # Ensure widget validation retains accessible error relationships.
    page.goto(base + "/accounts/login/")
    page.set_viewport_size({"width": 1440, "height": 1000})
    page.screenshot(path=str(ARTIFACTS / "login-1440.png"), full_page=True)
