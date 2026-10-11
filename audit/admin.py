from django.contrib import admin

from config.admin import site

from .models import Event


@admin.register(Event, site=site)
class EventAdmin(admin.ModelAdmin):
    list_display = ("at", "actor", "kind", "target", "outcome")
    list_filter = ("kind", "outcome", "at")
    search_fields = ("actor__username", "target", "kind")
    readonly_fields = ("at", "actor", "kind", "target", "outcome", "details")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
