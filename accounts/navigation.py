import posixpath
import re
from urllib.parse import urlencode, urlsplit

from django.urls import Resolver404, resolve, reverse
from django.utils.http import url_has_allowed_host_and_scheme


def safe_return_destination(request, destination, fallback):
    """Return a local, same-origin destination or a known-safe fallback."""
    if (
        destination
        and destination.startswith("/")
        and not destination.startswith("//")
        and "\\" not in destination
        and not any(ord(character) < 32 or ord(character) == 127 for character in destination)
        and url_has_allowed_host_and_scheme(
            destination,
            allowed_hosts={request.get_host()},
            require_https=request.is_secure(),
        )
    ):
        return destination
    return fallback


def safe_admin_destination(request, destination, fallback=None):
    """Validate a canonical destination within the admin subtree, excluding login routes."""
    admin_index = reverse("admin:index")
    fallback = fallback or admin_index
    candidate = safe_return_destination(request, destination, fallback)
    parsed = urlsplit(candidate)
    path = parsed.path
    if re.search(r"(?i)%(?:2e|2f|5c)", path):
        return fallback
    normalized_path = posixpath.normpath(path)
    if path.endswith("/") and not normalized_path.endswith("/"):
        normalized_path += "/"
    if normalized_path != path:
        return fallback
    admin_login = reverse("admin:login")
    if (
        not normalized_path.startswith(admin_index)
        or normalized_path.rstrip("/") == admin_login.rstrip("/")
        or normalized_path.startswith(admin_login.rstrip("/") + "/")
    ):
        return fallback
    return candidate


def portal_home(user):
    return reverse("admin:index" if user.is_portal_admin else "staff_portal")


def safe_portal_destination(request, destination):
    """Keep sign-in returns within the account's portal and permitted tools."""
    fallback = portal_home(request.user)
    candidate = safe_return_destination(request, destination, fallback)
    path = urlsplit(candidate).path
    if re.search(r"(?i)%(?:2e|2f|5c)", path):
        return fallback
    if posixpath.normpath(path).rstrip("/") != path.rstrip("/"):
        return fallback
    try:
        route = resolve(path)
    except Resolver404:
        return fallback
    if "admin" in route.namespaces:
        return (
            safe_admin_destination(request, candidate) if request.user.is_portal_admin else fallback
        )
    allowed = {"library", "folder", "preview", "content", "thumbnail", "password_change"}
    if not request.user.is_portal_admin:
        allowed.add("staff_portal")
    if request.user.can_manage:
        allowed.update(
            {
                "management",
                "import_documents",
                "manage_document",
                "upload",
                "replace",
                "create_folder",
                "create_root_folder",
            }
        )
    if request.user.is_portal_admin:
        allowed.add("drive_connection")
    return candidate if route.url_name in allowed else fallback


def reauthentication_url(destination):
    return reverse("reauthenticate") + "?" + urlencode({"next": destination})
