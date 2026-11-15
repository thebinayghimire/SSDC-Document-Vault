from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import AdminUserCreationForm, UserChangeForm
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import F, Q
from django.shortcuts import redirect

from audit.services import record
from config.admin import site

from .models import User
from .services.email_claims import (
    EmailConflict,
    acquire_email_lock,
    check_availability,
    normalize_email,
    set_email,
)


class CreationForm(AdminUserCreationForm):
    class Meta(AdminUserCreationForm.Meta):
        model = User
        fields = ("username", "role")
        labels = {"username": "Staff ID"}


class ChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = User
        labels = {"username": "Staff ID"}

    def clean_email(self):
        email = self.cleaned_data.get("email", "")
        if not email:
            return ""
        normalized = normalize_email(email)
        try:
            check_availability(normalized, exclude_user_pk=self.instance.pk)
        except EmailConflict as exc:
            raise ValidationError(str(exc)) from exc
        return normalized

    def clean(self):
        data = super().clean()
        old = User.objects.filter(pk=self.instance.pk).first()
        if old and old.is_portal_admin:
            remains_admin = data.get("is_active", True) and (
                old.is_superuser or data.get("role") == User.Role.ADMIN
            )
            other_admin = (
                User.objects.filter(is_active=True)
                .exclude(pk=old.pk)
                .filter(Q(is_superuser=True) | Q(role=User.Role.ADMIN))
                .exists()
            )
            if not remains_admin and not other_admin:
                raise ValidationError(
                    "The last active administrator cannot be disabled or demoted."
                )
        return data


@admin.register(User, site=site)
class PortalUserAdmin(UserAdmin):
    add_form = CreationForm
    form = ChangeForm
    list_display = ("username", "role", "is_active", "mfa_confirmed")
    list_filter = ("role", "is_active", "mfa_confirmed")
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Staff details", {"fields": ("first_name", "last_name", "email", "role", "is_active")}),
        ("Security", {"fields": ("mfa_confirmed", "auth_version", "last_login", "date_joined")}),
    )
    readonly_fields = ("mfa_confirmed", "auth_version", "last_login", "date_joined")
    add_fieldsets = ((None, {"fields": ("username", "role", "password1", "password2")}),)
    filter_horizontal = ()
    actions = ["revoke_sessions", "reset_mfa"]

    def has_delete_permission(self, request, obj=None):
        return False

    def changeform_view(self, request, object_id=None, form_url="", extra_context=None):
        try:
            return super().changeform_view(request, object_id, form_url, extra_context)
        except EmailConflict as exc:
            messages.error(request, str(exc))
            return redirect(request.path)

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            acquire_email_lock()
            old = User.objects.select_for_update().get(pk=obj.pk) if change else None
            was_admin = old and old.is_portal_admin
            fields = set(form.changed_data) & {
                "username",
                "first_name",
                "last_name",
                "email",
                "role",
                "is_active",
            }
            email_changed = "email" in fields
            fields.discard("email")
            if old:
                for field in fields:
                    setattr(old, field, getattr(obj, field))
            if was_admin and not old.is_portal_admin:
                others = (
                    User.objects.filter(is_active=True)
                    .exclude(pk=obj.pk)
                    .filter(Q(is_superuser=True) | Q(role=User.Role.ADMIN))
                )
                if not others.exists():
                    raise ValidationError(
                        "The last active administrator cannot be disabled or demoted."
                    )
            if old:
                old.save(update_fields=fields)
            else:
                super().save_model(request, obj, form, change)
            if email_changed:
                set_email(
                    old or obj,
                    form.cleaned_data.get("email", ""),
                    actor=request.user,
                    source="admin",
                )
                obj.refresh_from_db()
            record(request.user, "account_changed" if change else "account_created", obj.pk)

    def user_change_password(self, request, id, form_url=""):
        with transaction.atomic():
            request._vault_password_change = True
            try:
                return super().user_change_password(request, id, form_url)
            finally:
                del request._vault_password_change

    def log_change(self, request, obj, message):
        result = super().log_change(request, obj, message)
        # Django calls this after a valid password form actually saves. A redirect
        # from a cancelled/conflicting submission must not create a success event.
        if getattr(request, "_vault_password_change", False):
            record(request.user, "admin_password_reset", obj.pk)
        return result

    @admin.action(description="Revoke selected users' sessions")
    def revoke_sessions(self, request, queryset):
        with transaction.atomic():
            for user in queryset.order_by("pk").select_for_update(no_key=True):
                User.objects.filter(pk=user.pk).update(auth_version=F("auth_version") + 1)
                record(request.user, "sessions_revoked", user.pk)

    @admin.action(description="Reset MFA after verified identity recovery (revokes sessions)")
    def reset_mfa(self, request, queryset):
        with transaction.atomic():
            for user in queryset.order_by("pk").select_for_update(no_key=True):
                User.objects.filter(pk=user.pk).update(
                    mfa_secret="",
                    mfa_confirmed=False,
                    mfa_last_step=-1,
                    recovery_hashes=[],
                    auth_version=F("auth_version") + 1,
                )
                record(request.user, "mfa_reset", user.pk)
