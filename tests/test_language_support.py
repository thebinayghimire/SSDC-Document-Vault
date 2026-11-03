from pathlib import Path

import pytest
from django.conf import settings
from django.template.loader import get_template
from django.urls import reverse
from django.utils import translation

from accounts.forms import LoginForm
from vault.forms import UploadForm


@pytest.fixture
def language_client(client, settings):
    settings.STORAGES = {
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
    with translation.override("en"):
        yield client


def test_nepali_sign_in_and_accessible_language_choice(language_client):
    response = language_client.get(reverse("staff_login"), HTTP_ACCEPT_LANGUAGE="ne")
    assert response.status_code == 200
    text = response.content.decode()
    assert '<html lang="ne">' in text
    assert "कर्मचारी साइन इन" in text
    assert "कर्मचारी परिचय" in text
    assert 'lang="ne"' in text
    assert 'action="/i18n/setlang/"' in text
    assert 'name="csrfmiddlewaretoken"' in text


def test_language_preference_survives_navigation_and_switches_back(language_client):
    url = reverse("staff_login") + "?next=%2Flibrary%2F"
    response = language_client.post(reverse("set_language"), {"language": "ne", "next": url})
    assert response.status_code == 302
    assert response.cookies[settings.LANGUAGE_COOKIE_NAME].value == "ne"
    assert response.url == url
    assert "कर्मचारी साइन इन" in language_client.get(url).content.decode()
    assert "गोपनीयता नीति" in language_client.get(reverse("privacy")).content.decode()
    language_client.post(reverse("set_language"), {"language": "en", "next": url})
    assert "Staff sign in" in language_client.get(url).content.decode()


def test_language_redirect_rejects_external_destinations(language_client):
    response = language_client.post(
        reverse("set_language"), {"language": "ne", "next": "https://example.org/"}
    )
    assert response.url == "/"


def test_language_change_requires_csrf(settings):
    from django.test import Client

    assert (
        Client(enforce_csrf_checks=True)
        .post(reverse("set_language"), {"language": "ne"})
        .status_code
        == 403
    )


def test_lazy_form_labels_follow_language():
    with translation.override("ne"):
        assert str(LoginForm().fields["staff_id"].label) == "कर्मचारी परिचय"
        assert str(LoginForm().fields["password"].label) == "पासवर्ड"
        assert str(UploadForm().fields["title"].label) == "शीर्षक"
    with translation.override("en"):
        assert str(LoginForm().fields["staff_id"].label) == "Staff ID"


def test_browser_catalogue_includes_upload_and_preview_messages(language_client):
    response = language_client.get(reverse("javascript-catalog"), HTTP_ACCEPT_LANGUAGE="ne")
    assert response.status_code == 200
    # The JS response escapes Unicode, so decode the catalogue through its source values.
    assert "Importing documents" in response.content.decode()
    assert response.headers["Content-Language"] == "ne"
    assert "Accept-Language" in response.headers["Vary"]


def test_all_templates_compile():
    for path in Path(settings.BASE_DIR, "templates").rglob("*.html"):
        get_template(str(path.relative_to(Path(settings.BASE_DIR, "templates"))))


def test_nepali_staff_library_renders_navigation_and_empty_state(settings):
    from django.template.loader import render_to_string
    from django.test import RequestFactory
    from django.urls import resolve

    from accounts.models import User

    settings.STORAGES = {
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
    request = RequestFactory().get("/staff/")
    request.user = User(username="staffmember", role=User.Role.STAFF)
    request.session = {}
    request.resolver_match = resolve("/staff/")
    with translation.override("ne"):
        text = render_to_string(
            "vault/library.html",
            {"total": 0, "page": [], "folders": [], "mode": "list"},
            request=request,
        )
    assert "कागजात पुस्तकालय" in text
    assert "अहिलेसम्म कागजात छैनन्" in text
    assert "कर्मचारी" in text
    assert "खाताको सुरक्षा" in text
