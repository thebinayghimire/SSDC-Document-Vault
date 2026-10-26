import time

from django.contrib.admin import AdminSite
from django.shortcuts import redirect

from accounts.navigation import reauthentication_url, safe_admin_destination


class VaultAdminSite(AdminSite):
    site_header = "SSDC Vault Administration"
    site_title = "SSDC Administration"
    index_title = "Accounts, permissions, and audit"

    def has_permission(self, request):
        return (
            request.user.is_authenticated
            and request.user.is_portal_admin
            and (
                not request.user.requires_authenticator
                or request.session.get("mfa_verified", False)
            )
            and time.time() - request.session.get("reauth_at", 0) <= 600
        )

    def login(self, request, extra_context=None):
        if not request.user.is_authenticated:
            return redirect("login")
        if not request.user.is_portal_admin:
            return redirect("library")
        destination = safe_admin_destination(request, request.GET.get("next"))
        return redirect(reauthentication_url(destination))


site = VaultAdminSite(name="admin")
