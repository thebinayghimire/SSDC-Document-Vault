import re
import time
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.http import Http404, HttpResponse, JsonResponse, StreamingHttpResponse
from django.middleware.csrf import get_token
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods, require_POST

from audit.services import allow_rate, record

from .forms import FolderForm, ImportForm, MetadataForm, UploadForm
from .models import Document, Folder, Version
from .policy import can_manage_document, folder_permissions, permitted_documents
from .services import (
    change_document_lifecycle,
    restore_document_version,
    upload_document,
)
from .services import (
    create_folder as save_folder,
)
from .storage import StorageError, provider
from .validation import InvalidUpload


def recent_identity(request):
    return time.time() - request.session.get("reauth_at", 0) <= 600


def request_limit(request, scope="content", limit=240):
    if not allow_rate(scope, str(request.user.pk), limit, 60):
        record(request.user, scope, outcome="throttled")
        response = HttpResponse("Too many requests. Try again shortly.", status=429)
        response["Retry-After"] = "60"
        return response
    return None


def authorized_document(request, identifier, manage=False):
    document = (
        permitted_documents(request.user, manage=manage)
        .select_related("active_version", "folder")
        .filter(pk=identifier)
        .first()
    )
    if document is None:
        record(request.user, "document_access", identifier, "denied")
        raise Http404
    return document


def breadcrumbs(folder, visible):
    result, seen = [], set()
    while folder and folder.pk not in seen:
        seen.add(folder.pk)
        if folder.pk in visible:
            result.append(folder)
        folder = folder.parent
    return list(reversed(result))


@require_http_methods(["GET", "HEAD"])
def library(request, folder_id=None):
    if not request.user.is_authenticated:
        return render(request, "home.html")
    throttled = request_limit(request, "library", 120)
    if throttled:
        return throttled
    viewable, manageable = folder_permissions(request.user)
    folder = (
        get_object_or_404(Folder.objects.filter(pk__in=viewable), pk=folder_id)
        if folder_id
        else None
    )
    search = request.GET.get("q", "")[:200].strip()
    mode = "gallery" if request.GET.get("view") == "gallery" else "list"
    sort = request.GET.get("sort", "newest")
    orders = {"newest": "-modified_at", "oldest": "modified_at", "name": "title"}
    query = (
        permitted_documents(request.user)
        .filter(
            active_version__status=Version.Status.READY, archived=False, deleted_at__isnull=True
        )
        .select_related("active_version", "folder")
    )
    if folder:
        query = query.filter(folder=folder)
    if search:
        query = query.filter(title__icontains=search)
    file_type = request.GET.get("type", "")
    if file_type == "pdf":
        query = query.filter(active_version__mime_type="application/pdf")
    elif file_type == "image":
        query = query.filter(active_version__mime_type__startswith="image/")
    folders = Folder.objects.filter(pk__in=viewable, parent=folder)
    # A separately granted child under a hidden ancestor remains discoverable at root.
    if folder is None:
        folders = Folder.objects.filter(pk__in=viewable).exclude(parent_id__in=viewable)
    page = Paginator(query.order_by(orders.get(sort, "-modified_at"), "id"), 24).get_page(
        request.GET.get("page")
    )
    return render(
        request,
        "vault/library.html",
        {
            "folder": folder,
            "folders": folders,
            "page": page,
            "search": search,
            "mode": mode,
            "sort": sort,
            "file_type": file_type,
            "can_upload": folder and folder.pk in manageable,
            "import_folders": Folder.objects.filter(pk__in=manageable)
            .select_related("parent")
            .order_by("name", "id"),
            "import_folder_ids": manageable,
            "max_upload_bytes": settings.MAX_UPLOAD_BYTES,
            "breadcrumbs": breadcrumbs(folder, viewable),
            "total": query.count(),
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def import_documents(request):
    if request.method == "POST" and not request.user.can_manage:
        raise Http404
    _, manageable = folder_permissions(request.user)
    folders = (
        Folder.objects.filter(pk__in=manageable).select_related("parent").order_by("name", "id")
    )
    form = ImportForm(request.POST or None, request.FILES or None, allowed_folders=folders)
    wants_json = request.headers.get("Accept") == "application/json"
    if request.method == "GET" and wants_json:
        return JsonResponse({"csrf_token": get_token(request)})
    if request.method == "POST":
        if not recent_identity(request):
            if wants_json:
                return JsonResponse(
                    {
                        "error": "Verify your identity, then continue your upload.",
                        "reauth_url": reverse("reauthenticate"),
                    },
                    status=401,
                )
            return redirect("reauthenticate")
        if not form.is_valid():
            if wants_json:
                return JsonResponse({"errors": form.errors.get_json_data()}, status=400)
        else:
            throttled = request_limit(request, "upload", 60)
            if throttled:
                return throttled
            try:
                version = upload_document(
                    request.user,
                    form.cleaned_data["folder"],
                    form.cleaned_data["file"],
                    form.cleaned_data["title"],
                )
            except InvalidUpload as exc:
                form.add_error("file", str(exc))
            except StorageError as exc:
                form.add_error("file", str(exc))
            except (PermissionDenied, Document.DoesNotExist) as exc:
                if wants_json:
                    return JsonResponse(
                        {"error": "You no longer have permission to upload to this folder."},
                        status=403,
                    )
                raise Http404 from exc
            else:
                if wants_json:
                    return JsonResponse(
                        {
                            "status": version.status,
                            "note": version.processing_note,
                            "manage_url": reverse("manage_document", args=[version.document_id]),
                        },
                        status=201,
                    )
                return redirect("manage_document", document_id=version.document_id)
            if wants_json:
                return JsonResponse({"errors": form.errors.get_json_data()}, status=400)
    return render(
        request,
        "vault/import.html",
        {
            "form": form,
            "import_folders": folders,
            "import_folder_ids": manageable,
            "max_upload_bytes": settings.MAX_UPLOAD_BYTES,
        },
    )


@login_required
@require_http_methods(["GET", "HEAD"])
def preview(request, document_id):
    throttled = request_limit(request)
    if throttled:
        return throttled
    document = authorized_document(request, document_id)
    if (
        document.deleted_at
        or document.archived
        or not document.active_version
        or document.active_version.status != Version.Status.READY
    ):
        raise Http404
    record(request.user, "document_view", document.pk)
    return render(
        request,
        "vault/viewer.html",
        {
            "document": document,
            "version": document.active_version,
            "can_manage": can_manage_document(request.user, document),
            "can_view_folder": document.folder_id in folder_permissions(request.user)[0],
        },
    )


@login_required
@require_http_methods(["GET", "HEAD"])
def content(request, document_id, thumbnail=False):
    throttled = request_limit(request)
    if throttled:
        return throttled
    document = authorized_document(request, document_id)
    version = document.active_version
    if (
        document.deleted_at
        or document.archived
        or not version
        or version.status != Version.Status.READY
    ):
        raise Http404
    key = version.thumbnail_key if thumbnail else version.storage_key
    selected = request.GET.get("version")
    if selected and selected != str(version.pk):
        return HttpResponse(
            "The selected version changed. Refresh the preview.",
            status=409,
            content_type="text/plain",
        )
    if not key:
        raise Http404
    mime = "image/jpeg" if thumbnail else version.mime_type
    if mime not in {"application/pdf", "image/jpeg", "image/png", "image/webp"}:
        raise Http404
    storage = provider(version.storage_provider)
    try:
        total = storage.size(key)
        expected_size = version.thumbnail_size if thumbnail else version.size
        if total != expected_size:
            raise StorageError("integrity")
    except StorageError as exc:
        return storage_failure(request, document, exc)
    range_header = request.headers.get("Range")
    # No validators are emitted: an If-Range condition cannot match this response.
    if request.headers.get("If-Range"):
        range_header = None
    start, end = 0, None
    if range_header and request.method != "HEAD":
        match = re.fullmatch(r"bytes=(\d*)-(\d*)", range_header)
        try:
            if not match or not any(match.groups()):
                raise ValueError
            first, last = match.groups()
            if first:
                start = int(first)
                end = min(int(last), total - 1) if last else total - 1
            else:
                suffix = int(last)
                if suffix <= 0:
                    raise ValueError
                start, end = max(0, total - suffix), total - 1
            if start > end or start >= total:
                raise ValueError
        except (ValueError, OverflowError):
            response = HttpResponse(status=416)
            response["Content-Range"] = f"bytes */{total}"
            return response
    try:
        if request.method == "HEAD":
            response = HttpResponse(content_type=mime)
        else:
            response = StreamingHttpResponse(
                storage.open(key, start, end),
                content_type=mime,
                status=206 if end is not None else 200,
            )
    except StorageError as exc:
        return storage_failure(request, document, exc)
    if end is not None:
        response["Content-Range"] = f"bytes {start}-{end}/{total}"
    response["Content-Length"] = str(total if end is None else end - start + 1)
    response["Content-Disposition"] = 'inline; filename="preview"'
    response["Accept-Ranges"] = "bytes"
    response["X-Content-Type-Options"] = "nosniff"
    response["ETag"] = f'"{version.pk}{"-thumbnail" if thumbnail else ""}"'
    record(request.user, "thumbnail" if thumbnail else "document_bytes", document.pk)
    return response


def storage_failure(request, document, error):
    record(request.user, "storage_error", document.pk, error.code)
    if error.code == "missing":
        raise Http404
    response = HttpResponse(str(error), status=503, content_type="text/plain")
    response["Retry-After"] = "60"
    return response


@login_required
@require_http_methods(["GET", "POST"])
def upload(request, folder_id=None, document_id=None):
    if document_id:
        document = authorized_document(request, document_id, manage=True)
        folder = document.folder
        if document.deleted_at:
            raise Http404
    else:
        document = None
        _, manageable = folder_permissions(request.user)
        folder = get_object_or_404(Folder.objects.filter(pk__in=manageable), pk=folder_id)
    if not recent_identity(request):
        return redirect(
            reverse("reauthenticate") + "?" + urlencode({"next": request.get_full_path()})
        )
    from .forms import ReplacementForm

    form = (ReplacementForm if document else UploadForm)(
        request.POST or None,
        request.FILES or None,
        initial={"title": document.title if document else ""},
    )
    if request.method == "POST" and form.is_valid():
        throttled = request_limit(request, "upload", 10)
        if throttled:
            return throttled
        try:
            version = upload_document(
                request.user,
                folder,
                form.cleaned_data["file"],
                form.cleaned_data["title"],
                document,
            )
        except InvalidUpload as exc:
            form.add_error("file", str(exc))
        except (PermissionDenied, Document.DoesNotExist) as exc:
            raise Http404 from exc
        else:
            messages.success(
                request,
                f"Upload {version.get_status_display().lower()}: {version.processing_note}.",
            )
            return redirect("manage_document", document_id=version.document_id)
    return render(
        request,
        "vault/form.html",
        {
            "form": form,
            "title": "Replace document" if document else "Upload document",
            "multipart": True,
            "max_upload_bytes": settings.MAX_UPLOAD_BYTES,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def manage_document(request, document_id):
    document = authorized_document(request, document_id, manage=True)
    if not recent_identity(request):
        return redirect("reauthenticate")
    _, manageable = folder_permissions(request.user)
    form = MetadataForm(
        request.POST or None,
        instance=document,
        allowed_folders=Folder.objects.filter(Q(pk__in=manageable) | Q(pk=document.folder_id)),
        actor=request.user,
    )
    if request.method == "POST" and form.is_valid():
        try:
            with transaction.atomic():
                document = form.save()
                record(request.user, "metadata_changed", document.pk)
        except PermissionDenied as exc:
            raise Http404 from exc
        except Document.DoesNotExist as exc:
            raise Http404 from exc
        except ValidationError as exc:
            form.add_error(None, exc)
        else:
            messages.success(request, "Document details updated.")
            return redirect("manage_document", document_id=document.pk)
    return render(
        request,
        "vault/manage.html",
        {
            "document": document,
            "form": form,
            "versions": document.versions.order_by("-uploaded_at"),
        },
    )


@login_required
@require_POST
def lifecycle(request, document_id, action):
    document = authorized_document(request, document_id, manage=True)
    if not recent_identity(request):
        return redirect("reauthenticate")
    actions = {"archive", "unarchive", "delete", "restore"}
    if action not in actions:
        raise Http404
    try:
        document = change_document_lifecycle(request.user, document, action)
    except (PermissionDenied, Document.DoesNotExist) as exc:
        raise Http404 from exc
    except StorageError as exc:
        return storage_failure(request, document, exc)
    return redirect("manage_document", document_id=document.pk)


@login_required
@require_http_methods(["GET", "POST"])
def create_folder(request, folder_id=None):
    _, manageable = folder_permissions(request.user)
    parent = (
        get_object_or_404(Folder.objects.filter(pk__in=manageable), pk=folder_id)
        if folder_id
        else None
    )
    if not parent and not request.user.is_portal_admin:
        raise Http404
    if not recent_identity(request):
        return redirect("reauthenticate")
    # Managers may create inherited children; restricted policies are administrator-owned.
    form = FolderForm(request.POST or None, initial={"restricted": False})
    if not request.user.is_portal_admin:
        form.fields.pop("restricted")
    if request.method == "POST" and form.is_valid():
        folder = form.save(commit=False)
        folder.parent = parent
        if not request.user.is_portal_admin:
            folder.restricted = False
        throttled = request_limit(request, "folder-create", 10)
        if throttled:
            return throttled
        try:
            folder = save_folder(request.user, folder)
        except PermissionDenied as exc:
            raise Http404 from exc
        except ValidationError as exc:
            form.add_error(None, exc)
        else:
            return redirect("folder", folder_id=folder.pk)
    return render(request, "vault/form.html", {"form": form, "title": "Create folder"})


@login_required
@require_http_methods(["GET", "HEAD"])
def management(request):
    if not request.user.can_manage:
        raise Http404
    docs = permitted_documents(request.user, manage=True).select_related("folder", "active_version")
    return render(
        request,
        "vault/management.html",
        {"page": Paginator(docs, 24).get_page(request.GET.get("page"))},
    )


@login_required
@require_POST
def restore_version(request, document_id, version_id):
    document = authorized_document(request, document_id, manage=True)
    if not recent_identity(request):
        return redirect("reauthenticate")
    try:
        document = restore_document_version(request.user, document, version_id)
    except (PermissionDenied, Document.DoesNotExist) as exc:
        raise Http404 from exc
    except StorageError as exc:
        return storage_failure(request, document, exc)
    messages.success(request, "Previous version restored as the current document.")
    return redirect("manage_document", document_id=document.pk)
