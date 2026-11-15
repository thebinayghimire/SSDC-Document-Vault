"""Independent registration/email flags, safe defaults, and absent Phase 1 routes."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import get_connection
from django.urls import Resolver404, resolve
from django.utils import timezone

from accounts.models import StaffRegistrationRequest, User
from config.settings import env_flag

ROOT = Path(__file__).resolve().parents[1]
FLAGS = (
    "STAFF_SELF_REGISTRATION_ENABLED",
    "EMAIL_LOGIN_ENABLED",
    "SELF_REGISTERED_EMAIL_CHANGE_ENABLED",
)


def read_settings(overrides=None, unset_flags=True):
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("GOOGLE_", "DRIVE_", "RENDER", "POSTGRES_", "DATABASE_URL"))
        and key not in {"SECRET_KEY", "MFA_ENCRYPTION_KEY"}
    }
    environment["APP_ENV"] = "test"
    if unset_flags:
        for flag in FLAGS:
            environment.pop(flag, None)
    environment.update(overrides or {})
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json; from config import settings; "
                "print(json.dumps({"
                + ", ".join(f"{name!r}: getattr(settings, {name!r})" for name in FLAGS)
                + ", 'EMAIL_BACKEND': settings.EMAIL_BACKEND}))"
            ),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_all_phase_1_flags_default_to_false():
    values = read_settings()
    assert {flag: values[flag] for flag in FLAGS} == {flag: False for flag in FLAGS}


@pytest.mark.parametrize("enabled", FLAGS)
def test_each_flag_is_independent(enabled):
    values = read_settings({enabled: "1"})
    assert values[enabled] is True
    for flag in FLAGS:
        if flag != enabled:
            assert values[flag] is False


@pytest.mark.parametrize("value", ["true", "yes", "2", "on", " 1", ""])
def test_flag_parser_rejects_ambiguous_boolean_values(monkeypatch, value):
    monkeypatch.setenv("SYNTHETIC_PHASE_1_FLAG", value)
    with pytest.raises(ImproperlyConfigured, match="must be 0 or 1"):
        env_flag("SYNTHETIC_PHASE_1_FLAG", False)


def test_flag_parser_defaults_without_environment_value(monkeypatch):
    monkeypatch.delenv("SYNTHETIC_PHASE_1_FLAG", raising=False)
    assert env_flag("SYNTHETIC_PHASE_1_FLAG", False) is False
    assert env_flag("SYNTHETIC_PHASE_1_FLAG", True) is True
    monkeypatch.setenv("SYNTHETIC_PHASE_1_FLAG", "1")
    assert env_flag("SYNTHETIC_PHASE_1_FLAG", False) is True
    monkeypatch.setenv("SYNTHETIC_PHASE_1_FLAG", "0")
    assert env_flag("SYNTHETIC_PHASE_1_FLAG", True) is False


def test_email_delivery_is_locmem_only_in_phase_1():
    values = read_settings()
    assert values["EMAIL_BACKEND"] == "django.core.mail.backends.locmem.EmailBackend"
    assert django_settings.EMAIL_BACKEND == "django.core.mail.backends.locmem.EmailBackend"
    assert get_connection().__class__.__name__ == "EmailBackend"
    assert get_connection().__class__.__module__.endswith("locmem")


@pytest.mark.parametrize(
    "path",
    [
        "/accounts/register/",
        "/accounts/signup/",
        "/accounts/register/verify/",
        "/accounts/email-login/",
        "/accounts/email/change/",
    ],
)
def test_no_public_registration_or_email_routes_exist(path, settings, client):
    settings.STAFF_SELF_REGISTRATION_ENABLED = True
    settings.EMAIL_LOGIN_ENABLED = True
    settings.SELF_REGISTERED_EMAIL_CHANGE_ENABLED = True
    with pytest.raises(Resolver404):
        resolve(path)
    assert client.get(path).status_code == 404


@pytest.mark.django_db
def test_disabling_flags_does_not_remove_in_progress_registration_state(settings):
    applicant = User.objects.create_user("synthetic-applicant", password="Synthetic-Password-42")
    request = StaffRegistrationRequest.objects.create(
        user=applicant,
        status=StaffRegistrationRequest.Status.PENDING_REVIEW,
        email_verified_at=timezone.now(),
    )
    settings.STAFF_SELF_REGISTRATION_ENABLED = False
    settings.EMAIL_LOGIN_ENABLED = False
    settings.SELF_REGISTERED_EMAIL_CHANGE_ENABLED = False
    request.refresh_from_db()
    assert request.status == StaffRegistrationRequest.Status.PENDING_REVIEW
    assert StaffRegistrationRequest.objects.filter(pk=request.pk).exists()
