import time
from urllib.parse import urlencode

from django.contrib.admin import AdminSite
from django.shortcuts import redirect
from django.urls import reverse

from accounts.navigation import portal_home, reauthentication_url, safe_admin_destination


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
        destination = safe_admin_destination(request, request.GET.get("next"))
        if not request.user.is_authenticated:
            return redirect(reverse("admin_login") + "?" + urlencode({"next": destination}))
        if not request.user.is_portal_admin:
            return redirect(portal_home(request.user))
        return redirect(reauthentication_url(destination))

    def logout(self, request, extra_context=None):
        from accounts.views import sign_out

        return sign_out(request)


site = VaultAdminSite(name="admin")
