from copy import deepcopy

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models, router, transaction
from django.db.models import F
from django.db.models.functions import Lower
from django.utils import timezone


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = "admin", "Administrator"
        MANAGER = "manager", "Document manager"
        STAFF = "staff", "Staff"
        RESTRICTED = "restricted", "Restricted staff"

    role = models.CharField(max_length=16, choices=Role.choices, default=Role.STAFF)
    auth_version = models.PositiveIntegerField(default=1)
    mfa_secret = models.TextField(blank=True)
    mfa_confirmed = models.BooleanField(default=False)
    mfa_last_step = models.BigIntegerField(default=-1)
    recovery_hashes = models.JSONField(default=list, blank=True)

    @property
    def is_portal_admin(self):
        return self.is_active and (self.is_superuser or self.role == self.Role.ADMIN)

    @property
    def can_manage(self):
        return self.is_active and (self.is_portal_admin or self.role == self.Role.MANAGER)

    @property
    def requires_mfa(self):
        return self.can_manage or self.is_staff or settings.MFA_ALL_STAFF

    @property
    def requires_authenticator(self):
        return settings.MFA_ENABLED and (self.requires_mfa or self.mfa_confirmed)

    def has_perm(self, perm, obj=None):
        return self.is_portal_admin or super().has_perm(perm, obj)

    def has_module_perms(self, app_label):
        return self.is_portal_admin or super().has_module_perms(app_label)

    def _remember_saved_values(self, fields=None):
        if fields is None:
            self._saved_values = {}
        for field in self._meta.concrete_fields:
            if (fields is None or field.name in fields) and field.attname in self.__dict__:
                # Recovery hashes are mutable: keep an independent comparison value.
                self._saved_values[field.attname] = deepcopy(self.__dict__[field.attname])

    @classmethod
    def from_db(cls, db, field_names, values):
        instance = super().from_db(db, field_names, values)
        instance._remember_saved_values()
        return instance

    def refresh_from_db(self, using=None, fields=None, from_queryset=None):
        if fields is not None:
            fields = set(fields)
        super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        self._remember_saved_values(fields)

    def save(self, *args, force_insert=False, force_update=False, using=None, update_fields=None):
        if args:
            force_insert, force_update, using, update_fields = self._parse_save_params(
                *args,
                method_name="save",
                force_insert=force_insert,
                force_update=force_update,
                using=using,
                update_fields=update_fields,
            )
        using = using or router.db_for_write(type(self), instance=self)
        if update_fields is not None:
            update_fields = set(update_fields)
            if not update_fields:
                return
        if self._state.adding or force_insert:
            email = (self.email or "").strip()
            if email:
                # A new account with an email must become claimable atomically with
                # its creation. The advisory lock is taken before the user row is
                # inserted, matching the canonical email-authority lock order.
                from .services.email_claims import (
                    acquire_email_lock,
                    claim_for_new_user,
                    normalize_email,
                )

                self.email = normalize_email(email)
                with transaction.atomic(using=using):
                    acquire_email_lock(using=using)
                    super().save(
                        force_insert=force_insert,
                        force_update=force_update,
                        using=using,
                        update_fields=update_fields,
                    )
                    self._remember_saved_values()
                    claim_for_new_user(self, using=using)
                return
            if self.email:
                self.email = ""
            super().save(
                force_insert=force_insert,
                force_update=force_update,
                using=using,
                update_fields=update_fields,
            )
            self._remember_saved_values()
            return

        if update_fields is None:
            # A full save of a loaded account means save its actual edits, not its
            # stale copy of fields changed by another request. Deferred fields
            # remain untouched unless explicitly assigned.
            update_fields = {
                field.name
                for field in self._meta.concrete_fields
                if not field.primary_key
                and field.attname in self.__dict__
                and (
                    field.attname not in self._saved_values
                    or self.__dict__[field.attname] != self._saved_values[field.attname]
                )
            }
        update_fields.discard("auth_version")
        if "email" in update_fields:
            saved_email = getattr(self, "_saved_values", {}).get("email", "")
            if (self.email or "") != (saved_email or ""):
                from .services.email_claims import EmailWriteBypass

                raise EmailWriteBypass(
                    "Email changes must be made through accounts.services.email_claims.set_email()."
                )
        security_fields = {
            "role",
            "is_active",
            "is_staff",
            "is_superuser",
            "password",
            "mfa_confirmed",
            "mfa_secret",
        }
        with transaction.atomic(using=using):
            current = type(self).objects.using(using).select_for_update().get(pk=self.pk)
            security_changed = any(
                getattr(current, field) != getattr(self, field)
                for field in security_fields & update_fields
            )
            # The row lock serializes this increment with password/role changes,
            # MFA verification, and the admin actions' atomic F() increments.
            self.auth_version = current.auth_version + int(security_changed)
            if security_changed:
                update_fields.add("auth_version")
            if update_fields:
                super().save(using=using, force_update=force_update, update_fields=update_fields)
            self._remember_saved_values(update_fields | {"auth_version"})


class EmailClaim(models.Model):
    """The authoritative, case-insensitive owner of an email address."""

    normalized_email = models.CharField(max_length=254, unique=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="email_claim",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(normalized_email=""),
                name="email_claim_normalized_nonempty",
            ),
            models.CheckConstraint(
                condition=models.Q(normalized_email=Lower("normalized_email")),
                name="email_claim_normalized_lowercase",
            ),
        ]

    def __str__(self):
        return self.normalized_email


class StaffRegistrationRequest(models.Model):
    class Status(models.TextChoices):
        EMAIL_PENDING = "email_pending", "Email pending"
        PENDING_REVIEW = "pending_review", "Pending review"
        APPROVED = "approved", "Approved"
        DECLINED = "declined", "Declined"
        EXPIRED = "expired", "Expired"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="staff_registration_requests",
    )
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.EMAIL_PENDING,
    )
    applicant_email = models.CharField(max_length=254, blank=True)
    language = models.CharField(max_length=8, default="en")
    pending_password_hash = models.CharField(max_length=256, blank=True)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    otp_digest = models.CharField(max_length=64, blank=True)
    otp_expires_at = models.DateTimeField(null=True, blank=True)
    otp_attempts = models.PositiveSmallIntegerField(default=0)
    otp_sent_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reviewed_staff_registration_requests",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_note = models.TextField(blank=True)
    reapplication_allowed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(
                    status__in=[
                        "email_pending",
                        "pending_review",
                        "approved",
                        "declined",
                        "expired",
                    ]
                ),
                name="staff_registration_valid_status",
            ),
            models.CheckConstraint(
                condition=models.Q(otp_attempts__gte=0),
                name="staff_registration_nonnegative_otp_attempts",
            ),
            models.UniqueConstraint(
                fields=["user"],
                condition=models.Q(status__in=["email_pending", "pending_review"]),
                name="staff_registration_one_active_per_user",
            ),
            models.CheckConstraint(
                condition=(
                    ~models.Q(status="email_pending")
                    | (
                        ~models.Q(otp_digest="")
                        & models.Q(otp_expires_at__isnull=False)
                        & models.Q(otp_sent_at__isnull=False)
                    )
                ),
                name="staff_registration_email_pending_has_otp",
            ),
        ]
        indexes = [
            models.Index(
                fields=["status", "created_at"],
                name="staff_reg_status_created_idx",
            ),
            models.Index(
                fields=["reviewed_by"],
                name="staff_reg_reviewer_idx",
            ),
        ]

    def __str__(self):
        return f"{self.user_id}:{self.status}"


class StaffRegistrationToken(models.Model):
    """Database-backed, single-use, 24-hour verification token for staff registration.

    Mitigates token replay attacks and URL token persistence (VULN-03).
    Only the SHA-256 hash of the random secret is stored.
    """

    registration = models.ForeignKey(
        StaffRegistrationRequest,
        on_delete=models.CASCADE,
        related_name="tokens",
    )
    # Mitigates plaintext credential exposure in database dumps and logs by storing only SHA-256 hash
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # Mitigates indefinite window of opportunity by enforcing 24-hour expiry
    expires_at = models.DateTimeField(db_index=True)
    # Mitigates token replay attacks by tracking consumption timestamp
    used_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["token_hash"], name="staff_reg_tok_hash_idx"),
            models.Index(fields=["expires_at", "used_at"], name="staff_reg_tok_exp_used_idx"),
        ]

    def __str__(self):
        return f"Token({self.registration_id}, used={bool(self.used_at)})"


class EmailChangeRequest(models.Model):
    """A verified, reserved replacement of the address owned by an account."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending verification"
        APPLIED = "applied", "Applied"
        CANCELLED = "cancelled", "Cancelled"
        EXPIRED = "expired", "Expired"
        SUPERSEDED = "superseded", "Superseded"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="email_change_requests",
    )
    old_email = models.CharField(max_length=254, blank=True)
    new_email = models.CharField(max_length=254)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    language = models.CharField(max_length=8, default="en")
    otp_digest = models.CharField(max_length=64, blank=True)
    otp_expires_at = models.DateTimeField(null=True, blank=True)
    otp_attempts = models.PositiveSmallIntegerField(default=0)
    otp_sent_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(
                    status__in=["pending", "applied", "cancelled", "expired", "superseded"]
                ),
                name="email_change_valid_status",
            ),
            models.CheckConstraint(
                condition=models.Q(otp_attempts__gte=0),
                name="email_change_nonnegative_otp_attempts",
            ),
            models.CheckConstraint(
                condition=(
                    ~models.Q(status="pending")
                    | (
                        ~models.Q(otp_digest="")
                        & models.Q(otp_expires_at__isnull=False)
                        & models.Q(otp_sent_at__isnull=False)
                    )
                ),
                name="email_change_pending_has_otp",
            ),
            models.UniqueConstraint(
                fields=["new_email"],
                condition=models.Q(status="pending"),
                name="email_change_pending_address_unique",
            ),
            models.UniqueConstraint(
                fields=["user"],
                condition=models.Q(status="pending"),
                name="email_change_one_pending_per_user",
            ),
        ]
        indexes = [
            models.Index(
                fields=["status", "created_at"],
                name="email_change_status_idx",
            ),
            models.Index(
                fields=["user", "status"],
                name="email_change_user_status_idx",
            ),
        ]

    def __str__(self):
        return f"{self.user_id}:{self.new_email}:{self.status}"


class EmailNotification(models.Model):
    """Durable outbox for transactional email delivery and safe retries."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SENDING = "sending", "Sending"
        SENT = "sent", "Sent"
        FAILED = "failed", "Failed"
        DEAD_LETTER = "dead_letter", "Dead letter"
        SUPERSEDED = "superseded", "Superseded"

    kind = models.CharField(max_length=64, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="email_notifications",
    )
    registration_request = models.ForeignKey(
        StaffRegistrationRequest,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="email_notifications",
    )
    email_change_request = models.ForeignKey(
        EmailChangeRequest,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="email_notifications",
    )
    recipient_email = models.CharField(max_length=254)
    subject = models.CharField(max_length=255)
    template_name = models.CharField(max_length=128)
    context = models.JSONField(default=dict, blank=True)
    dedupe_key = models.CharField(max_length=128, unique=True, null=True, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    attempts = models.PositiveSmallIntegerField(default=0)
    max_attempts = models.PositiveSmallIntegerField(default=5)
    next_attempt_at = models.DateTimeField(default=timezone.now, db_index=True)
    locked_at = models.DateTimeField(null=True, blank=True)
    locked_by = models.CharField(max_length=64, blank=True)
    last_error = models.TextField(blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    superseded_by = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="superseded_notifications",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(
                    status__in=[
                        "pending",
                        "sending",
                        "sent",
                        "failed",
                        "dead_letter",
                        "superseded",
                    ]
                ),
                name="email_notification_valid_status",
            ),
            models.CheckConstraint(
                condition=models.Q(attempts__gte=0),
                name="email_notification_nonnegative_attempts",
            ),
            models.CheckConstraint(
                condition=models.Q(max_attempts__gte=1),
                name="email_notification_positive_max_attempts",
            ),
            models.CheckConstraint(
                condition=models.Q(attempts__lte=F("max_attempts")),
                name="email_notification_attempts_within_limit",
            ),
        ]
        indexes = [
            models.Index(
                fields=["status", "next_attempt_at"],
                name="notif_status_next_idx",
            ),
            models.Index(
                fields=["kind", "created_at"],
                name="notif_kind_created_idx",
            ),
        ]

    def __str__(self):
        return f"{self.kind}:{self.recipient_email}:{self.status}"
