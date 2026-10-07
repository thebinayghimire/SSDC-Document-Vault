import time

from django.contrib.admin import AdminSite
from django.shortcuts import redirect


class VaultAdminSite(AdminSite):
    site_header = "SSDC Vault Administration"
    site_title = "SSDC Administration"
    index_title = "Accounts, permissions, and audit"

    def has_permission(self, request):
        return (
            request.user.is_authenticated
            and request.user.is_portal_admin
            and request.session.get("mfa_verified", False)
            and time.time() - request.session.get("reauth_at", 0) <= 600
        )

    def login(self, request, extra_context=None):
        return redirect("reauthenticate" if request.user.is_authenticated else "login")


site = VaultAdminSite(name="admin")
