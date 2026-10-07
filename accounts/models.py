from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


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

    def has_perm(self, perm, obj=None):
        return self.is_portal_admin or super().has_perm(perm, obj)

    def has_module_perms(self, app_label):
        return self.is_portal_admin or super().has_module_perms(app_label)

    def save(self, *args, **kwargs):
        if self.pk:
            old = type(self).objects.filter(pk=self.pk).first()
            fields = ("role", "is_active", "is_staff", "is_superuser", "password", "mfa_confirmed")
            if old and any(getattr(old, field) != getattr(self, field) for field in fields):
                self.auth_version = old.auth_version + 1
                if kwargs.get("update_fields"):
                    kwargs["update_fields"] = set(kwargs["update_fields"]) | {"auth_version"}
        super().save(*args, **kwargs)
