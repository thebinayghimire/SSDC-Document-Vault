"""Integration tests for the administrator staff-registration review interface."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.db import connections
from django.test import Client
from django.urls import reverse

from accounts.models import EmailNotification, StaffRegistrationRequest, User
from accounts.services.otp import decrypt_otp
from accounts.services.registration import (
    DecisionConflict,
    approve_registration,
    decline_registration,
    expire_registration,
    register_applicant,
    verify_registration_otp,
)
from audit.models import Event

from .conftest import authenticate_client

pytestmark = pytest.mark.django_db

PASSWORD = "Strong-Applicant-Password-42"
REVIEW_URL_NAME = "admin:accounts_staffregistrationrequest_changelist"


@pytest.fixture
def registration_enabled(settings):
    settings.STAFF_SELF_REGISTRATION_ENABLED = True
    settings.EMAIL_DELIVERY_ENABLED = False
    return settings


def _latest_otp(registration):
    notification = (
        EmailNotification.objects.filter(
            registration_request=registration,
            kind="registration_otp",
            status=EmailNotification.Status.PENDING,
        )
        .order_by("-created_at", "-pk")
        .first()
    )
    assert notification is not None
    return decrypt_otp(notification.context["otp_ciphertext"])


def _pending_request(email="pending.review@example.test", password=PASSWORD):
    registration = register_applicant(email=email, password=password).request
    assert registration is not None
    assert verify_registration_otp(registration, _latest_otp(registration)).status == "verified"
    registration.refresh_from_db()
    return registration


def _approved_request(email, admin):
    registration = _pending_request(email)
    approve_registration(registration.pk, admin)
    registration.refresh_from_db()
    return registration


def _declined_request(email, admin, *, allow_reapplication=False):
    registration = _pending_request(email)
    decline_registration(
        registration.pk,
        admin,
        note="Synthetic review note",
        allow_reapplication=allow_reapplication,
    )
    registration.refresh_from_db()
    return registration


def _expired_request(email):
    registration = _pending_request(email)
    assert expire_registration(registration.pk) is True
    registration.refresh_from_db()
    return registration


def _change_url(registration):
    return reverse(
        "admin:accounts_staffregistrationrequest_change",
        args=[registration.pk],
    )


def _approve_url(registration):
    return reverse(
        "admin:accounts_staffregistrationrequest_approve",
        args=[registration.pk],
    )


def _decline_url(registration):
    return reverse(
        "admin:accounts_staffregistrationrequest_decline",
        args=[registration.pk],
    )


def _allow_reapplication_url(registration):
    return reverse(
        "admin:accounts_staffregistrationrequest_allow_reapplication",
        args=[registration.pk],
    )


def test_portal_admin_can_open_the_review_queue(client, users, registration_enabled):
    authenticate_client(client, users["admin"])
    response = client.get(reverse(REVIEW_URL_NAME))
    assert response.status_code == 200
    content = response.content.decode()
    assert "Staff registration requests" in content
    assert "Review pending applications" in content


@pytest.mark.parametrize("actor", ["alice", "manager"])
def test_non_admins_cannot_view_the_queue_or_review_endpoints(
    client, users, registration_enabled, actor
):
    registration = _pending_request()
    authenticate_client(client, users[actor])
    for url in (
        reverse(REVIEW_URL_NAME),
        _change_url(registration),
        _approve_url(registration),
        _decline_url(registration),
        _allow_reapplication_url(registration),
    ):
        response = client.get(url)
        assert response.status_code in {302, 403, 404}
        assert response.status_code != 200
    registration.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.PENDING_REVIEW


def test_anonymous_user_is_redirected_to_the_admin_login(client, registration_enabled):
    registration = _pending_request()
    response = client.get(_change_url(registration))
    assert response.status_code == 302
    assert "/admin/login/" in response.url


def test_registration_requests_cannot_be_added_or_deleted(client, users, registration_enabled):
    authenticate_client(client, users["admin"])
    add_response = client.get(reverse("admin:accounts_staffregistrationrequest_add"))
    assert add_response.status_code == 403

    registration = _pending_request()
    delete_response = client.post(
        reverse("admin:accounts_staffregistrationrequest_delete", args=[registration.pk]),
        {"post": "yes"},
    )
    assert delete_response.status_code == 403
    assert StaffRegistrationRequest.objects.filter(pk=registration.pk).exists()


def test_queue_lists_requests_and_filters_by_each_status(client, users, registration_enabled):
    authenticate_client(client, users["admin"])
    pending = _pending_request("pending.queue@example.test")
    approved = _approved_request("approved.queue@example.test", users["admin"])
    declined = _declined_request("declined.queue@example.test", users["admin"])
    unverified = register_applicant(
        email="unverified.queue@example.test", password=PASSWORD
    ).request
    expired = _expired_request("expired.queue@example.test")

    url = reverse(REVIEW_URL_NAME)
    response = client.get(url)
    assert response.status_code == 200
    content = response.content.decode()
    for registration in (pending, approved, declined, unverified, expired):
        assert registration.applicant_email in content

    expectations = {
        "pending_review": pending,
        "approved": approved,
        "declined": declined,
        "email_pending": unverified,
        "expired": expired,
    }
    for status, expected in expectations.items():
        response = client.get(url, {"status": status})
        assert response.status_code == 200
        assert list(response.context["cl"].queryset) == [expected]


def test_queue_surfaces_the_pending_review_count(client, users, registration_enabled):
    authenticate_client(client, users["admin"])
    _pending_request("one.pending@example.test")
    _pending_request("two.pending@example.test")
    _approved_request("already.approved@example.test", users["admin"])

    response = client.get(reverse(REVIEW_URL_NAME))
    assert response.status_code == 200
    content = response.content.decode()
    assert "2 verified applications are waiting for a decision." in content
    assert "Review pending applications" in content


def test_admin_search_finds_requests_by_applicant_and_user_fields(
    client, users, registration_enabled
):
    authenticate_client(client, users["admin"])
    registration = _pending_request("search.target@example.test")

    response = client.get(reverse(REVIEW_URL_NAME), {"q": "search.target@example.test"})
    assert response.status_code == 200
    assert list(response.context["cl"].queryset) == [registration]

    response = client.get(reverse(REVIEW_URL_NAME), {"q": registration.user.username})
    assert response.status_code == 200
    assert list(response.context["cl"].queryset) == [registration]


def test_admin_approval_activates_only_the_staff_role(client, users, registration_enabled):
    registration = _pending_request()
    user = registration.user
    user.role = User.Role.MANAGER
    user.is_staff = True
    user.save(update_fields=["role", "is_staff"])
    authenticate_client(client, users["admin"])

    response = client.post(_approve_url(registration), follow=True)
    assert response.status_code == 200
    assert "was approved" in response.content.decode()

    registration.refresh_from_db()
    user.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.APPROVED
    assert registration.reviewed_by == users["admin"]
    assert registration.reviewed_at is not None
    assert registration.review_note == ""
    assert registration.pending_password_hash == ""
    assert user.is_active is True
    assert user.role == User.Role.STAFF
    assert user.is_staff is False
    assert user.is_superuser is False
    assert user.check_password(PASSWORD) is True

    event = Event.objects.get(kind="staff_registration_approved")
    assert event.actor == users["admin"]
    assert event.target == str(user.pk)

    notification = EmailNotification.objects.get(
        registration_request=registration,
        kind="registration_approved",
    )
    assert notification.recipient_email == registration.applicant_email
    assert notification.status == EmailNotification.Status.PENDING


def test_approval_and_decline_endpoints_reject_get_requests(client, users, registration_enabled):
    registration = _pending_request()
    authenticate_client(client, users["admin"])

    assert client.get(_approve_url(registration)).status_code == 405
    assert client.get(_decline_url(registration)).status_code == 405
    assert client.get(_allow_reapplication_url(registration)).status_code == 405

    registration.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.PENDING_REVIEW
    assert registration.user.is_active is False


def test_admin_decline_keeps_the_account_inactive_and_records_the_note(
    client, users, registration_enabled
):
    registration = _pending_request()
    authenticate_client(client, users["admin"])

    response = client.post(
        _decline_url(registration),
        {"note": "Incomplete supporting documentation", "allow_reapplication": "on"},
        follow=True,
    )
    assert response.status_code == 200
    assert "was declined" in response.content.decode()

    registration.refresh_from_db()
    registration.user.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.DECLINED
    assert registration.reviewed_by == users["admin"]
    assert registration.reviewed_at is not None
    assert registration.review_note == "Incomplete supporting documentation"
    assert registration.reapplication_allowed is True
    assert registration.pending_password_hash == ""
    assert registration.user.is_active is False

    event = Event.objects.get(kind="staff_registration_declined")
    assert event.actor == users["admin"]
    assert event.target == str(registration.user_id)

    notification = EmailNotification.objects.get(
        registration_request=registration,
        kind="registration_declined",
    )
    assert notification.recipient_email == registration.applicant_email
    assert notification.status == EmailNotification.Status.PENDING


def test_admin_decline_defaults_to_disallowing_reapplication(client, users, registration_enabled):
    registration = _pending_request()
    authenticate_client(client, users["admin"])

    response = client.post(_decline_url(registration), {"note": ""}, follow=True)
    assert response.status_code == 200
    registration.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.DECLINED
    assert registration.reapplication_allowed is False
    assert registration.review_note == ""


def test_admin_can_allow_reapplication_on_a_declined_request(client, users, registration_enabled):
    registration = _declined_request("reapplication.candidate@example.test", users["admin"])
    assert registration.reapplication_allowed is False
    authenticate_client(client, users["admin"])

    response = client.post(_allow_reapplication_url(registration), follow=True)
    assert response.status_code == 200
    assert "Reapplication has been allowed" in response.content.decode()

    registration.refresh_from_db()
    assert registration.reapplication_allowed is True
    assert Event.objects.filter(
        kind="staff_registration_reapplication_allowed",
        actor=users["admin"],
    ).exists()
    assert EmailNotification.objects.filter(
        registration_request=registration,
        kind="registration_reapplication_allowed",
    ).exists()


def test_non_admin_cannot_allow_reapplication(client, users, registration_enabled):
    registration = _declined_request("blocked.reapplication@example.test", users["admin"])
    authenticate_client(client, users["alice"])

    response = client.post(_allow_reapplication_url(registration))
    assert response.status_code in {302, 403, 404}
    registration.refresh_from_db()
    assert registration.reapplication_allowed is False


def test_double_approval_is_idempotent_and_reports_the_existing_decision(
    client, users, registration_enabled
):
    registration = _pending_request()
    authenticate_client(client, users["admin"])

    assert client.post(_approve_url(registration)).status_code == 302
    events = Event.objects.filter(kind="staff_registration_approved").count()
    notifications = EmailNotification.objects.filter(
        registration_request=registration,
        kind="registration_approved",
    ).count()

    response = client.post(_approve_url(registration), follow=True)
    assert response.status_code == 200
    assert "already approved" in response.content.decode()

    assert Event.objects.filter(kind="staff_registration_approved").count() == events
    assert (
        EmailNotification.objects.filter(
            registration_request=registration,
            kind="registration_approved",
        ).count()
        == notifications
    )
    registration.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.APPROVED


def test_approval_after_a_decline_is_rejected_with_a_friendly_message(
    client, users, registration_enabled
):
    registration = _pending_request()
    decline_registration(registration.pk, users["admin"], note="Declined first")
    authenticate_client(client, users["admin"])

    response = client.post(_approve_url(registration), follow=True)
    assert response.status_code == 200
    assert "cannot be approved because its status has changed" in response.content.decode()

    registration.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.DECLINED
    assert registration.user.is_active is False
    assert not Event.objects.filter(kind="staff_registration_approved").exists()


def test_decline_after_an_approval_is_rejected_with_a_friendly_message(
    client, users, registration_enabled
):
    registration = _approved_request("already.approved@example.test", users["admin"])
    authenticate_client(client, users["admin"])

    response = client.post(_decline_url(registration), {"note": "Stale page"}, follow=True)
    assert response.status_code == 200
    assert "cannot be declined because its status has changed" in response.content.decode()

    registration.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.APPROVED
    assert registration.user.is_active is True
    assert not Event.objects.filter(kind="staff_registration_declined").exists()


def test_unverified_and_expired_requests_are_not_actionable(client, users, registration_enabled):
    unverified = register_applicant(email="not.verified@example.test", password=PASSWORD).request
    expired = _expired_request("has.expired@example.test")
    authenticate_client(client, users["admin"])

    for registration, expected_status in (
        (unverified, StaffRegistrationRequest.Status.EMAIL_PENDING),
        (expired, StaffRegistrationRequest.Status.EXPIRED),
    ):
        response = client.get(_change_url(registration))
        assert response.status_code == 200
        content = response.content.decode()
        assert "Approve staff registration" not in content
        assert "Decline staff registration" not in content

        response = client.post(_approve_url(registration), follow=True)
        assert response.status_code == 200
        assert "cannot be approved because its status has changed" in response.content.decode()
        registration.refresh_from_db()
        assert registration.status == expected_status


def test_change_form_renders_post_only_csrf_protected_decision_forms(
    client, users, registration_enabled
):
    registration = _pending_request()
    authenticate_client(client, users["admin"])

    response = client.get(_change_url(registration))
    assert response.status_code == 200
    content = response.content.decode()
    assert f'action="{_approve_url(registration)}"' in content
    assert f'action="{_decline_url(registration)}"' in content
    assert "csrfmiddlewaretoken" in content
    assert "Approve staff registration" in content
    assert "Decline staff registration" in content
    assert 'name="note"' in content
    assert 'name="allow_reapplication"' in content


def test_declined_change_form_offers_reapplication_controls(client, users, registration_enabled):
    registration = _declined_request("declined.detail@example.test", users["admin"])
    authenticate_client(client, users["admin"])

    response = client.get(_change_url(registration))
    assert response.status_code == 200
    content = response.content.decode()
    assert "Allow reapplication" in content
    assert f'action="{_allow_reapplication_url(registration)}"' in content

    allow_reapplication_registration = _declined_request(
        "already.allowed@example.test", users["admin"], allow_reapplication=True
    )
    response = client.get(_change_url(allow_reapplication_registration))
    assert response.status_code == 200
    assert "Allow reapplication" not in response.content.decode()


def test_change_form_never_exposes_password_hashes_or_otp_digests(
    client, users, registration_enabled
):
    registration = register_applicant(
        email="secrets.detail@example.test", password=PASSWORD
    ).request
    otp = _latest_otp(registration)
    authenticate_client(client, users["admin"])

    response = client.get(_change_url(registration))
    assert response.status_code == 200
    content = response.content.decode()
    assert registration.pending_password_hash not in content
    assert registration.otp_digest not in content
    assert otp not in content
    assert "password" not in content.lower() or "Password staged" in content


def test_review_endpoints_require_a_valid_csrf_token(users, registration_enabled):
    registration = _pending_request()
    csrf_client = Client(enforce_csrf_checks=True)
    authenticate_client(csrf_client, users["admin"])

    for url in (
        _approve_url(registration),
        _decline_url(registration),
        _allow_reapplication_url(registration),
    ):
        assert csrf_client.post(url).status_code == 403

    registration.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.PENDING_REVIEW


def test_delivery_failure_does_not_roll_back_a_successful_approval(
    client,
    users,
    registration_enabled,
    settings,
    monkeypatch,
    django_capture_on_commit_callbacks,
):
    registration = _pending_request()
    authenticate_client(client, users["admin"])
    settings.EMAIL_DELIVERY_ENABLED = True

    def explode(*args, **kwargs):
        raise RuntimeError("synthetic SMTP outage")

    monkeypatch.setattr("accounts.services.notifications.EmailMultiAlternatives", explode)

    with django_capture_on_commit_callbacks(execute=True):
        response = client.post(_approve_url(registration))
    assert response.status_code == 302

    registration.refresh_from_db()
    registration.user.refresh_from_db()
    assert registration.status == StaffRegistrationRequest.Status.APPROVED
    assert registration.user.is_active is True
    notification = EmailNotification.objects.get(
        registration_request=registration,
        kind="registration_approved",
    )
    assert notification.status == EmailNotification.Status.FAILED


@pytest.mark.django_db(transaction=True)
def test_simultaneous_approval_and_decline_leave_exactly_one_decision(users, registration_enabled):
    registration = _pending_request("race.decision@example.test")
    barrier = threading.Barrier(2)

    def decide(action):
        try:
            barrier.wait(timeout=20)
            if action == "approve":
                approve_registration(registration.pk, users["admin"])
            else:
                decline_registration(registration.pk, users["admin"])
            return "decided"
        except DecisionConflict:
            return "conflict"
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = sorted(
            future.result(timeout=30)
            for future in (
                executor.submit(decide, "approve"),
                executor.submit(decide, "decline"),
            )
        )

    assert results == ["conflict", "decided"]
    registration.refresh_from_db()
    registration.user.refresh_from_db()
    assert registration.status in {
        StaffRegistrationRequest.Status.APPROVED,
        StaffRegistrationRequest.Status.DECLINED,
    }
    assert (registration.status == StaffRegistrationRequest.Status.APPROVED) == (
        registration.user.is_active
    )
    assert (
        EmailNotification.objects.filter(
            registration_request=registration,
            kind__in=["registration_approved", "registration_declined"],
        ).count()
        == 1
    )
    assert (
        Event.objects.filter(
            kind__in=["staff_registration_approved", "staff_registration_declined"],
            details__object_id=registration.pk,
        ).count()
        == 1
    )
