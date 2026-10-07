from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import AdminUserCreationForm, UserChangeForm
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.db.models import F, Q

from audit.services import record
from config.admin import site

from .models import User


class CreationForm(AdminUserCreationForm):
    class Meta(AdminUserCreationForm.Meta):
        model = User
        fields = ("username", "role")


class ChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = User

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

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(731011)")
            old = User.objects.filter(pk=obj.pk).first() if change else None
            if old and old.is_portal_admin and not obj.is_portal_admin:
                others = (
                    User.objects.filter(is_active=True)
                    .exclude(pk=obj.pk)
                    .filter(Q(is_superuser=True) | Q(role=User.Role.ADMIN))
                )
                if not others.exists():
                    raise ValidationError(
                        "The last active administrator cannot be disabled or demoted."
                    )
            super().save_model(request, obj, form, change)
            record(request.user, "account_changed" if change else "account_created", obj.pk)

    def user_change_password(self, request, id, form_url=""):
        response = super().user_change_password(request, id, form_url)
        if request.method == "POST" and response.status_code == 302:
            record(request.user, "admin_password_reset", id)
        return response

    @admin.action(description="Revoke selected users' sessions")
    def revoke_sessions(self, request, queryset):
        for user in queryset:
            User.objects.filter(pk=user.pk).update(auth_version=F("auth_version") + 1)
            record(request.user, "sessions_revoked", user.pk)

    @admin.action(description="Reset MFA after verified identity recovery (revokes sessions)")
    def reset_mfa(self, request, queryset):
        for user in queryset:
            User.objects.filter(pk=user.pk).update(
                mfa_secret="",
                mfa_confirmed=False,
                mfa_last_step=-1,
                recovery_hashes=[],
                auth_version=F("auth_version") + 1,
            )
            record(request.user, "mfa_reset", user.pk)
