from django.contrib import admin
from django.db import connection, transaction

from audit.services import record
from config.admin import site

from .models import Document, DocumentGrant, Folder, FolderGrant, Version


class AuditedAdmin(admin.ModelAdmin):
    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        kind = (
            "permission_changed"
            if isinstance(obj, (FolderGrant, DocumentGrant))
            else "admin_changed"
        )
        record(request.user, kind, obj.pk)

    def delete_model(self, request, obj):
        target = obj.pk
        super().delete_model(request, obj)
        record(request.user, "admin_deleted", target)

    def delete_queryset(self, request, queryset):
        for obj in queryset:
            self.delete_model(request, obj)


@admin.register(Folder, site=site)
class FolderAdmin(AuditedAdmin):
    list_display = ("name", "parent", "restricted")
    search_fields = ("name",)

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(731010)")
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
