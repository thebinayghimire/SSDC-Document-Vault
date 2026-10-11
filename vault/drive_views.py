from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.debug import sensitive_variables
from django.views.decorators.http import require_http_methods

from audit.services import record

from .drive_auth import StorageError, begin_oauth, finish_oauth
from .drive_storage import ensure_folder
from .models import DriveConnection
from .views import recent_identity, request_limit


def administrator(request):
    # Session middleware refreshes account status/version and enforces privileged MFA.
    if not request.user.is_active or not request.user.is_portal_admin:
        raise PermissionDenied
    if not recent_identity(request):
        raise PermissionDenied


@login_required
@require_http_methods(["GET", "POST"])
@sensitive_variables()
def connection(request):
    if request.user.is_portal_admin and not recent_identity(request):
        return redirect(reverse("reauthenticate") + "?next=" + reverse("drive_connection"))
    administrator(request)
    if request.method == "POST":
        throttled = request_limit(request, "drive-connect", 5)
        if throttled:
            return throttled
        try:
            if request.POST.get("action") == "folder":
                ensure_folder()
                record(request.user, "drive_folder_ready")
                messages.success(request, "Private SSDC storage folder is ready.")
            else:
                return redirect(begin_oauth(request))
        except StorageError as exc:
            messages.error(request, str(exc))
        return redirect("drive_connection")
    state = DriveConnection.objects.filter(pk=1).first()
    return render(
        request,
        "vault/drive_connection.html",
        {
            "connected": bool(
                state and state.encrypted_credentials and not state.reconnect_required
            ),
            "folder_ready": bool(state and state.folder_id),
        },
    )


@login_required
@require_http_methods(["GET"])
@sensitive_variables()
def callback(request):
    administrator(request)
    try:
        finish_oauth(request)
        record(request.user, "drive_connected")
        messages.success(request, "Storage owner connected. Prepare the private SSDC folder next.")
    except StorageError as exc:
        messages.error(request, str(exc))
    except PermissionDenied:
        # Fixed body, no query parameters reflected; one-time state stays consumed.
        return HttpResponse("Invalid or expired storage authorization. Start again.", status=403)
    response = redirect("drive_connection")
    response["Referrer-Policy"] = "no-referrer"
    return response
