from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import AdminUserCreationForm, UserChangeForm
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Count, F, Q
from django.http import Http404
from django.shortcuts import redirect
from django.urls import path, reverse
from django.utils.decorators import method_decorator
from django.utils.formats import date_format
from django.utils.html import format_html
from django.utils.timezone import localtime
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_POST

from audit.services import record
from config.admin import site

from .forms import RegistrationDecisionForm
from .models import StaffRegistrationRequest, User
from .services.email_claims import (
    EmailConflict,
    acquire_email_lock,
    check_availability,
    normalize_email,
    set_email,
)
from .services.registration import (
    DecisionConflict,
    RegistrationStateError,
    allow_reapplication,
    approve_registration,
    decline_registration,
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


class RegistrationStatusFilter(admin.SimpleListFilter):
    title = _("registration status")
    parameter_name = "status"

    def lookups(self, request, model_admin):
        counts = dict(
            model_admin.get_queryset(request)
            .order_by()
            .values_list("status")
            .annotate(total=Count("pk"))
        )
        return [
            (value, f"{label} ({counts.get(value, 0)})")
            for value, label in StaffRegistrationRequest.Status.choices
        ]

    def queryset(self, request, queryset):
        value = self.value()
        if value in StaffRegistrationRequest.Status.values:
            return queryset.filter(status=value)
        return queryset


@admin.register(StaffRegistrationRequest, site=site)
class StaffRegistrationRequestAdmin(admin.ModelAdmin):
    list_display = (
        "applicant",
        "status_badge",
        "email_verification",
        "created_at",
        "reviewed_at",
        "reviewed_by_display",
    )
    list_display_links = ("applicant",)
    list_filter = (RegistrationStatusFilter, ("created_at", admin.DateFieldListFilter))
    search_fields = ("applicant_email", "user__username", "user__email")
    ordering = ("-created_at",)
    list_per_page = 50
    actions = None
    fieldsets = (
        (
            None,
            {
                "fields": (
                    "applicant_email",
                    "status_badge",
                    "email_verified_at",
                    "created_at",
                )
            },
        ),
        (
            _("Applicant account"),
            {"fields": ("user_link", "account_state", "password_staged")},
        ),
        (
            _("Review"),
            {"fields": ("reviewed_by", "reviewed_at", "review_note", "reapplication_allowed")},
        ),
    )
    readonly_fields = (
        "applicant_email",
        "status_badge",
        "email_verified_at",
        "created_at",
        "user_link",
        "account_state",
        "password_staged",
        "reviewed_by",
        "reviewed_at",
        "review_note",
        "reapplication_allowed",
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user", "reviewed_by")

    def has_module_permission(self, request):
        return bool(getattr(request.user, "is_portal_admin", False))

    def has_view_permission(self, request, obj=None):
        return bool(getattr(request.user, "is_portal_admin", False))

    def has_change_permission(self, request, obj=None):
        return bool(getattr(request.user, "is_portal_admin", False))

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description=_("Applicant email"), ordering="applicant_email")
    def applicant(self, obj):
        return obj.applicant_email or obj.user.email or obj.user.username

    @admin.display(description=_("Status"), ordering="status")
    def status_badge(self, obj):
        return format_html(
            '<span class="vault-status-badge vault-status-badge--{status}">{label}</span>',
            status=obj.status,
            label=obj.get_status_display(),
        )

    @admin.display(description=_("Email verification"), ordering="email_verified_at")
    def email_verification(self, obj):
        if obj.email_verified_at is None:
            return format_html(
                '<span class="vault-status-badge vault-status-badge--unverified">{}</span>',
                _("Not verified"),
            )
        return format_html(
            '<span class="vault-status-badge vault-status-badge--verified">{}</span>'
            '<br><span class="vault-muted">{}</span>',
            _("Verified"),
            date_format(localtime(obj.email_verified_at), "SHORT_DATETIME_FORMAT"),
        )

    @admin.display(description=_("Applicant account"))
    def user_link(self, obj):
        if obj.user_id is None:
            return _("No account")
        url = reverse(f"{self.admin_site.name}:accounts_user_change", args=[obj.user_id])
        return format_html('<a href="{}">{}</a>', url, obj.user.username)

    @admin.display(description=_("Account status"))
    def account_state(self, obj):
        if obj.user_id is not None and obj.user.is_active:
            return format_html(
                '<span class="vault-status-badge vault-status-badge--verified">{}</span>',
                _("Active"),
            )
        return format_html(
            '<span class="vault-status-badge vault-status-badge--unverified">{}</span>',
            _("Inactive"),
        )

    @admin.display(description=_("Password staged"))
    def password_staged(self, obj):
        return _("Yes") if obj.pending_password_hash else _("No")

    @admin.display(description=_("Reviewer"), ordering="reviewed_by__username")
    def reviewed_by_display(self, obj):
        return obj.reviewed_by.username if obj.reviewed_by_id else _("—")

    def get_urls(self):
        model_name = f"{self.opts.app_label}_{self.opts.model_name}"
        urls = [
            path(
                "<path:object_id>/approve/",
                self.admin_site.admin_view(self.approve_view),
                name=f"{model_name}_approve",
            ),
            path(
                "<path:object_id>/decline/",
                self.admin_site.admin_view(self.decline_view),
                name=f"{model_name}_decline",
            ),
            path(
                "<path:object_id>/allow-reapplication/",
                self.admin_site.admin_view(self.allow_reapplication_view),
                name=f"{model_name}_allow_reapplication",
            ),
        ]
        return urls + super().get_urls()

    def changelist_view(self, request, extra_context=None):
        pending_count = (
            self.get_queryset(request)
            .filter(status=StaffRegistrationRequest.Status.PENDING_REVIEW)
            .count()
        )
        extra_context = {
            **(extra_context or {}),
            "pending_count": pending_count,
            "title": _("Staff registration requests"),
        }
        return super().changelist_view(request, extra_context)

    def changeform_view(self, request, object_id=None, form_url="", extra_context=None):
        extra_context = {
            **(extra_context or {}),
            "decline_form": RegistrationDecisionForm(),
            "show_save": False,
            "show_save_and_continue": False,
            "show_save_and_add_another": False,
            "show_delete": False,
        }
        return super().changeform_view(request, object_id, form_url, extra_context)

    def _review_object(self, request, object_id):
        obj = self.get_object(request, object_id)
        if obj is None:
            raise Http404("Staff registration request not found.")
        if not self.has_change_permission(request, obj):
            raise PermissionDenied
        return obj

    def _change_url(self, obj):
        return reverse(
            f"{self.admin_site.name}:{self.opts.app_label}_{self.opts.model_name}_change",
            args=[obj.pk],
        )

    @method_decorator(require_POST)
    def approve_view(self, request, object_id):
        obj = self._review_object(request, object_id)
        try:
            result = approve_registration(
                request_id=obj.pk,
                actor=request.user,
                base_url=request.build_absolute_uri("/"),
            )
        except DecisionConflict:
            messages.error(
                request,
                _("This application cannot be approved because its status has changed."),
            )
        except RegistrationStateError:
            messages.error(request, _("That registration request no longer exists."))
        else:
            if result.changed:
                messages.success(
                    request,
                    _("Staff registration for %(email)s was approved.")
                    % {"email": obj.applicant_email},
                )
            else:
                messages.info(
                    request,
                    _("Staff registration for %(email)s was already approved.")
                    % {"email": obj.applicant_email},
                )
        return redirect(self._change_url(obj))

    @method_decorator(require_POST)
    def decline_view(self, request, object_id):
        obj = self._review_object(request, object_id)
        form = RegistrationDecisionForm(request.POST)
        if not form.is_valid():
            messages.error(
                request,
                _("Provide a valid review note of no more than 2000 characters."),
            )
            return redirect(self._change_url(obj))
        try:
            result = decline_registration(
                request_id=obj.pk,
                actor=request.user,
                note=form.cleaned_data["note"],
                allow_reapplication=form.cleaned_data["allow_reapplication"],
                base_url=request.build_absolute_uri("/"),
            )
        except DecisionConflict:
            messages.error(
                request,
                _("This application cannot be declined because its status has changed."),
            )
        except RegistrationStateError:
            messages.error(request, _("That registration request no longer exists."))
        else:
            if result.changed:
                messages.warning(
                    request,
                    _("Staff registration for %(email)s was declined.")
                    % {"email": obj.applicant_email},
                )
            else:
                messages.info(
                    request,
                    _("Staff registration for %(email)s was already declined.")
                    % {"email": obj.applicant_email},
                )
        return redirect(self._change_url(obj))

    @method_decorator(require_POST)
    def allow_reapplication_view(self, request, object_id):
        obj = self._review_object(request, object_id)
        try:
            result = allow_reapplication(
                request_id=obj.pk,
                actor=request.user,
                base_url=request.build_absolute_uri("/"),
            )
        except DecisionConflict:
            messages.error(
                request,
                _("Reapplication can only be allowed for a declined application."),
            )
        except RegistrationStateError:
            messages.error(request, _("That registration request no longer exists."))
        else:
            if result.changed:
                messages.success(
                    request,
                    _("Reapplication has been allowed for %(email)s.")
                    % {"email": obj.applicant_email},
                )
            else:
                messages.info(
                    request,
                    _("Reapplication is already allowed for %(email)s.")
                    % {"email": obj.applicant_email},
                )
        return redirect(self._change_url(obj))
