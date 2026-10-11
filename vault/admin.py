from django.contrib import admin
from django.contrib.admin.actions import delete_selected as django_delete_selected
from django.db import transaction

from audit.services import record
from config.admin import site

from .models import Document, DocumentGrant, Folder, FolderGrant, Version
from .mutations import mutation_access
from .services import save_document_fields


class AuditedAdmin(admin.ModelAdmin):
    actions = ["delete_selected"]

    def audit_details(self, obj, before=None, deleting=False):
        if not isinstance(obj, (FolderGrant, DocumentGrant)):
            return {"object_type": obj._meta.label_lower, "object_id": str(obj.pk)}

        def state(item):
            if item is None:
                return None
            return {
                name: str(getattr(item, name)) if name.endswith("_id") else getattr(item, name)
                for name in (
                    "user_id",
                    "manage",
                    "folder_id" if isinstance(item, FolderGrant) else "document_id",
                )
            }

        return {
            "object_type": obj._meta.label_lower,
            "object_id": str(obj.pk),
            "subject_id": obj.user_id,
            "before": state(before),
            "after": None if deleting else state(obj),
        }

    @admin.action(description="Delete selected %(verbose_name_plural)s", permissions=["delete"])
    def delete_selected(self, request, queryset):
        # Include Django's deletion history, which its default action writes
        # before calling delete_queryset(), in the same all-or-nothing batch.
        with mutation_access(request.user, administrator=True):
            return django_delete_selected(self, request, queryset)

    def save_model(self, request, obj, form, change):
        with mutation_access(request.user, administrator=True) as actor:
            before = (
                type(obj).objects.select_for_update().filter(pk=obj.pk).first() if change else None
            )
            super().save_model(request, obj, form, change)
            kind = (
                "permission_changed"
                if isinstance(obj, (FolderGrant, DocumentGrant))
                else "admin_changed"
            )
            record(actor, kind, obj.pk, details=self.audit_details(obj, before))

    def delete_model(self, request, obj):
        with mutation_access(request.user, administrator=True) as actor:
            target = obj.pk
            details = self.audit_details(obj, before=obj, deleting=True)
            super().delete_model(request, obj)
            record(actor, "admin_deleted", target, details=details)

    def delete_queryset(self, request, queryset):
        with mutation_access(request.user, administrator=True):
            for obj in queryset:
                self.delete_model(request, obj)


@admin.register(Folder, site=site)
class FolderAdmin(AuditedAdmin):
    list_display = ("name", "parent", "restricted")
    search_fields = ("name",)

    def _changeform_view(self, request, object_id, form_url, extra_context):
        # Retain the write guard from form validation through saving.
        with mutation_access(request.user, administrator=True):
            return super()._changeform_view(request, object_id, form_url, extra_context)

    def save_model(self, request, obj, form, change):
        with mutation_access(request.user, administrator=True):
            obj.full_clean()
            super().save_model(request, obj, form, change)


@admin.register(FolderGrant, site=site)
class FolderGrantAdmin(AuditedAdmin):
    list_display = ("folder", "user", "manage")
    list_filter = ("manage",)
    search_fields = ("folder__name", "user__username")


@admin.register(DocumentGrant, site=site)
class DocumentGrantAdmin(AuditedAdmin):
    list_display = ("document", "user", "manage")
    search_fields = ("document__title", "user__username")


@admin.register(Document, site=site)
class DocumentAdmin(AuditedAdmin):
    list_display = ("title", "folder", "restricted", "archived", "deleted_at")
    list_filter = ("restricted", "archived")
    search_fields = ("title",)
    fields = (
        "title",
        "folder",
        "restricted",
        "archived",
        "deleted_at",
        "created_by",
        "active_version",
    )
    readonly_fields = ("deleted_at", "created_by", "active_version")

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            save_document_fields(obj, form.changed_data, actor=request.user)
            obj.refresh_from_db()
            record(request.user, "admin_changed", obj.pk)

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Version, site=site)
class VersionAdmin(admin.ModelAdmin):
    list_display = ("document", "original_name", "status", "scan_result", "uploaded_at")
    list_filter = ("status", "scan_result")
    readonly_fields = tuple(field.name for field in Version._meta.fields)
    exclude = ("storage_key", "thumbnail_key")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
