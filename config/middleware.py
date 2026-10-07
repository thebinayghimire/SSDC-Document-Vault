import time

from django.conf import settings
from django.contrib.auth import logout


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
                or (
                    (request.user.requires_mfa or request.user.mfa_confirmed)
                    and not session.get("mfa_verified")
                )
            )
            if invalid:
                logout(request)
            else:
                session["last_seen"] = now
        return self.get_response(request)


class PrivateHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Cache-Control"] = "no-store, private, max-age=0"
        response["Pragma"] = "no-cache"
        response["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; "
            "worker-src 'self' blob:; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        return response
