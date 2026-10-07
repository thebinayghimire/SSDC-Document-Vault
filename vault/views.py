import re
import time

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import connection, transaction
from django.db.models import Q
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST

from audit.services import allow_rate, record

from .forms import FolderForm, MetadataForm, UploadForm
from .models import Document, Folder, Version
from .policy import can_manage_document, folder_permissions, permitted_documents
from .services import upload_document
from .storage import path_for
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


@login_required
@require_http_methods(["GET", "HEAD"])
def library(request, folder_id=None):
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
            "breadcrumbs": breadcrumbs(folder, viewable),
            "total": query.count(),
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
            "watermark": f"SSDC · {request.user.username} · {timezone.localtime():%Y-%m-%d %H:%M}",
            "can_manage": can_manage_document(request.user, document),
        },
    )


def bounded_stream(path, start, length):
    with path.open("rb") as stream:
        stream.seek(start)
        while length > 0:
            chunk = stream.read(min(65536, length))
            if not chunk:
                break
            length -= len(chunk)
            yield chunk


@login_required
@require_http_methods(["GET", "HEAD"])
def content(request, document_id, thumbnail=False):
    from django.http import StreamingHttpResponse

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
    if not key:
        raise Http404
    path = path_for(key)
    if not path.is_file():
        record(request.user, "storage_error", document.pk, "missing")
        raise Http404
    total = path.stat().st_size
    mime = "image/jpeg" if thumbnail else version.mime_type
    range_header = request.headers.get("Range")
    if range_header and not thumbnail:
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
        response = (
            HttpResponse(content_type=mime, status=206)
            if request.method == "HEAD"
            else StreamingHttpResponse(
                bounded_stream(path, start, end - start + 1), content_type=mime, status=206
            )
        )
        response["Content-Range"] = f"bytes {start}-{end}/{total}"
        response["Content-Length"] = str(end - start + 1)
    else:
        response = (
            HttpResponse(content_type=mime)
            if request.method == "HEAD"
            else FileResponse(path.open("rb"), content_type=mime)
        )
        response["Content-Length"] = str(total)
    response["Content-Disposition"] = 'inline; filename="preview"'
    response["Accept-Ranges"] = "bytes"
    response["X-Content-Type-Options"] = "nosniff"
    record(request.user, "thumbnail" if thumbnail else "document_bytes", document.pk)
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
        return redirect("reauthenticate")
    form = UploadForm(
        request.POST or None,
        request.FILES or None,
        initial={"title": document.title if document else ""},
    )
    if request.method == "POST" and form.is_valid():
        throttled = request_limit(request, "upload", 10)
        if throttled:
            return throttled
        try:
            # Recheck policy under a transaction; subsequent reads always recheck it too.
            version = upload_document(
                request.user,
                folder,
                form.cleaned_data["file"],
                form.cleaned_data["title"],
                document,
            )
        except InvalidUpload as exc:
            form.add_error("file", str(exc))
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
    )
    if request.method == "POST" and form.is_valid():
        form.save()
        record(request.user, "metadata_changed", document.pk)
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
    with transaction.atomic():
        document = Document.objects.select_for_update().get(pk=document.pk)
        if action in {"archive", "unarchive"}:
            document.archived = action == "archive"
        else:
            document.deleted_at = timezone.now() if action == "delete" else None
        document.save()
        record(request.user, f"document_{action}", document.pk)
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
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(731010)")
            try:
                folder.full_clean()
            except ValidationError as exc:
                form.add_error(None, exc)
            else:
                folder.save()
                record(request.user, "folder_created", folder.pk)
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
    with transaction.atomic():
        document = Document.objects.select_for_update().get(pk=document.pk)
        if document.deleted_at:
            raise Http404
        version = get_object_or_404(
            Version, pk=version_id, document=document, status=Version.Status.READY
        )
        if not path_for(version.storage_key).is_file():
            raise Http404
        document.active_version = version
        document.save()
        record(request.user, "version_restored", version.pk)
    messages.success(request, "Previous version restored as the current document.")
    return redirect("manage_document", document_id=document.pk)
