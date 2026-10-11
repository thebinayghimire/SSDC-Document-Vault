from copy import deepcopy

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models, router, transaction


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
