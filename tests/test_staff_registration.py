"""Staff registration state model and database invariants."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.db import IntegrityError, connections, transaction
from django.utils import timezone

from accounts.models import StaffRegistrationRequest, User


def email_pending(user, digest="a" * 64, **fields):
    now = timezone.now()
    return StaffRegistrationRequest.objects.create(
        user=user,
        status=StaffRegistrationRequest.Status.EMAIL_PENDING,
        otp_digest=digest,
        otp_expires_at=now + timezone.timedelta(minutes=10),
        otp_sent_at=now,
        **fields,
    )


def test_registration_request_keeps_applicant_identity_on_a_foreign_key():
    field = StaffRegistrationRequest._meta.get_field("user")
    assert field.get_internal_type() == "ForeignKey"
    assert field.remote_field.related_name == "staff_registration_requests"
    assert field.remote_field.on_delete.__name__ == "CASCADE"


def test_reviewer_is_a_set_null_foreign_key_with_an_index():
    field = StaffRegistrationRequest._meta.get_field("reviewed_by")
    assert field.null
    assert field.remote_field.on_delete.__name__ == "SET_NULL"
    assert "staff_reg_reviewer_idx" in {
        index.name for index in StaffRegistrationRequest._meta.indexes
    }


def test_registration_lifecycle_statuses_are_explicit_and_complete():
    assert list(StaffRegistrationRequest.Status.values) == [
        "email_pending",
        "pending_review",
        "approved",
        "declined",
        "expired",
    ]
    assert StaffRegistrationRequest._meta.get_field("status").default == "email_pending"
    assert StaffRegistrationRequest._meta.get_field("reviewed_at").null
    assert StaffRegistrationRequest._meta.get_field("email_verified_at").null
    assert StaffRegistrationRequest._meta.get_field("otp_digest").max_length == 64
    assert StaffRegistrationRequest._meta.get_field("otp_attempts").default == 0
    assert StaffRegistrationRequest._meta.get_field("otp_expires_at").null
    assert StaffRegistrationRequest._meta.get_field("otp_sent_at").null


@pytest.mark.django_db
def test_valid_email_pending_request_requires_and_accepts_otp_metadata(users):
    request = email_pending(users["alice"])
    assert request.status == StaffRegistrationRequest.Status.EMAIL_PENDING
    assert request.otp_digest == "a" * 64
    assert request.otp_attempts == 0
    assert request.otp_sent_at is not None
    assert request.otp_expires_at > request.otp_sent_at


@pytest.mark.django_db
def test_email_pending_without_complete_otp_metadata_is_rejected(users):
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            StaffRegistrationRequest.objects.create(
                user=users["alice"],
                status=StaffRegistrationRequest.Status.EMAIL_PENDING,
            )
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            StaffRegistrationRequest.objects.create(
                user=users["alice"],
                status=StaffRegistrationRequest.Status.EMAIL_PENDING,
                otp_digest="",
                otp_expires_at=timezone.now(),
                otp_sent_at=timezone.now(),
            )


@pytest.mark.django_db
def test_unknown_status_and_negative_attempts_are_rejected_by_the_database(users):
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            StaffRegistrationRequest.objects.create(user=users["alice"], status="unknown")
    request = StaffRegistrationRequest.objects.create(
        user=users["alice"],
        status=StaffRegistrationRequest.Status.PENDING_REVIEW,
        email_verified_at=timezone.now(),
    )
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            StaffRegistrationRequest.objects.filter(pk=request.pk).update(otp_attempts=-1)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "status",
    [
        StaffRegistrationRequest.Status.PENDING_REVIEW,
        StaffRegistrationRequest.Status.APPROVED,
        StaffRegistrationRequest.Status.DECLINED,
        StaffRegistrationRequest.Status.EXPIRED,
    ],
)
def test_closed_or_reviewable_statuses_do_not_require_active_otp_metadata(users, status):
    request = StaffRegistrationRequest.objects.create(
        user=users["alice"],
        status=status,
        email_verified_at=timezone.now()
        if status != StaffRegistrationRequest.Status.EXPIRED
        else None,
    )
    assert request.status == status


@pytest.mark.django_db
def test_only_one_active_registration_is_allowed_per_user(users):
    first = email_pending(users["alice"])
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            StaffRegistrationRequest.objects.create(
                user=users["alice"],
                status=StaffRegistrationRequest.Status.PENDING_REVIEW,
                email_verified_at=timezone.now(),
            )
    StaffRegistrationRequest.objects.filter(pk=first.pk).update(
        status=StaffRegistrationRequest.Status.APPROVED,
        reviewed_by=users["admin"],
        reviewed_at=timezone.now(),
    )
    second = StaffRegistrationRequest.objects.create(
        user=users["alice"],
        status=StaffRegistrationRequest.Status.PENDING_REVIEW,
        email_verified_at=timezone.now(),
    )
    assert second.status == StaffRegistrationRequest.Status.PENDING_REVIEW


@pytest.mark.django_db
def test_multiple_finished_requests_are_retained_for_audit(users):
    for status in (
        StaffRegistrationRequest.Status.APPROVED,
        StaffRegistrationRequest.Status.DECLINED,
        StaffRegistrationRequest.Status.EXPIRED,
    ):
        StaffRegistrationRequest.objects.create(user=users["alice"], status=status)
    assert StaffRegistrationRequest.objects.filter(user=users["alice"]).count() == 3


@pytest.mark.django_db
def test_reviewer_identity_survives_but_is_nulled_when_the_reviewer_is_removed(users):
    reviewer = users["admin"]
    request = StaffRegistrationRequest.objects.create(
        user=users["alice"],
        status=StaffRegistrationRequest.Status.APPROVED,
        reviewed_by=reviewer,
        reviewed_at=timezone.now(),
    )
    reviewer.delete()
    request.refresh_from_db()
    assert request.reviewed_by is None
    assert request.reviewed_at is not None
    assert User.objects.filter(pk=users["alice"].pk).exists()


@pytest.mark.django_db(transaction=True)
def test_concurrent_active_registration_requests_are_serialized_by_the_unique_constraint(users):
    user_pk = users["alice"].pk
    barrier = threading.Barrier(2)

    def create_request(index):
        try:
            barrier.wait(timeout=20)
            StaffRegistrationRequest.objects.create(
                user_id=user_pk,
                status=StaffRegistrationRequest.Status.PENDING_REVIEW,
                email_verified_at=timezone.now(),
                otp_attempts=index,
            )
            return "created"
        except IntegrityError:
            return "conflict"
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = sorted(
            future.result(timeout=30)
            for future in [executor.submit(create_request, 1), executor.submit(create_request, 2)]
        )
    assert results == ["conflict", "created"]
    assert (
        StaffRegistrationRequest.objects.filter(
            user_id=user_pk,
            status__in=[
                StaffRegistrationRequest.Status.EMAIL_PENDING,
                StaffRegistrationRequest.Status.PENDING_REVIEW,
            ],
        ).count()
        == 1
    )
