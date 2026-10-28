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


class UploadLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    @staticmethod
    def rejected(request):
        from django.http import HttpResponse, JsonResponse

        message = "Upload one file per request within the configured upload limit."
        response = (
            JsonResponse({"error": message}, status=413)
            if "application/json" in request.headers.get("Accept", "")
            else HttpResponse(message, status=413, content_type="text/plain")
        )
        response["Cache-Control"] = "no-store, private, max-age=0"
        return response

    def __call__(self, request):
        from django.http import HttpResponseBadRequest

        try:
            length = int(request.META.get("CONTENT_LENGTH") or 0)
            if length < 0:
                raise ValueError
        except (ValueError, TypeError):
            return HttpResponseBadRequest("Invalid request length.")
        if length > settings.DATA_UPLOAD_MAX_MEMORY_SIZE:
            return self.rejected(request)
        if request.method == "POST" and request.content_type == "multipart/form-data":
            # Parse through the bounded handlers before any view can accept a
            # completed first file from a subsequently rejected multipart body.
            _ = request.POST
            if getattr(request, "upload_limit_exceeded", False):
                return self.rejected(request)
        response = self.get_response(request)
        if getattr(request, "upload_limit_exceeded", False):
            return self.rejected(request)
        return response


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
