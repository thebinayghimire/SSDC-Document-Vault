import re
import secrets
import time

from django.conf import settings
from django.contrib.auth import logout

from .logging import request_reference


class RequestReferenceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        supplied = request.META.get("HTTP_X_REQUEST_ID", "")
        request.request_id = (
            supplied if re.fullmatch(r"[a-f0-9]{32}", supplied) else secrets.token_hex(16)
        )
        token = request_reference.set(request.request_id)
        try:
            response = self.get_response(request)
            response["X-Request-ID"] = request.request_id
            return response
        finally:
            request_reference.reset(token)


class SessionPolicyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            now = time.time()
            session = request.session
            invalid = (
                not request.user.is_active
                or session.get("auth_version") != request.user.auth_version
                or now - session.get("auth_started", 0) > settings.SESSION_COOKIE_AGE
                or now - session.get("last_seen", 0) > settings.SESSION_IDLE_SECONDS
                or (request.user.requires_authenticator and not session.get("mfa_verified"))
            )
            if invalid:
                logout(request)
            else:
                session["last_seen"] = now
        return self.get_response(request)


class MaintenanceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path == "/live/":
            from .views import live

            return live(request)
        from django.http import HttpResponse

        from vault.maintenance import MaintenanceBusy, maintenance_lock

        try:
            with maintenance_lock():
                return self.get_response(request)
        except (MaintenanceBusy, OSError):
            response = HttpResponse("Maintenance in progress. Please retry shortly.", status=503)
            response["Retry-After"] = "60"
            return response


class PrivateHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Cache-Control"] = "no-store, private, max-age=0"
        response["Pragma"] = "no-cache"
        if request.path == "/storage/google/callback/":
            response["Referrer-Policy"] = "no-referrer"
        response["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Browsers enforce form-action on the POST's OAuth redirect as well.
        form_action = (
            "'self' https://accounts.google.com" if request.path == "/storage/google/" else "'self'"
        )
        response["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; "
            "worker-src 'self' blob:; object-src 'none'; base-uri 'none'; "
            f"frame-ancestors 'none'; form-action {form_action}"
        )
        return response
