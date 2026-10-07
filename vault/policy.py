from django.db.models import Q

from .models import Document, Folder


def folder_permissions(user):
    if not user.is_authenticated or not user.is_active:
        return set(), set()
    folders = list(Folder.objects.all().prefetch_related("grants"))
    if user.is_portal_admin:
        ids = {folder.pk for folder in folders}
        return ids, ids
    by_id = {folder.pk: folder for folder in folders}
    viewable, manageable = set(), set()
    for folder in folders:
        current, seen = folder, set()
        while current and current.pk not in seen:
            seen.add(current.pk)
            if current.restricted:
                grant = next((g for g in current.grants.all() if g.user_id == user.pk), None)
                if grant:
                    viewable.add(folder.pk)
                    if grant.manage and user.can_manage:
                        manageable.add(folder.pk)
                break
            current = by_id.get(current.parent_id)
    return viewable, manageable


def permitted_documents(user, manage=False):
    if not user.is_authenticated or not user.is_active:
        return Document.objects.none()
    if user.is_portal_admin:
        return Document.objects.all()
    if manage and not user.can_manage:
        return Document.objects.none()
    viewable, manageable = folder_permissions(user)
    folders = manageable if manage else viewable
    explicit = Q(restricted=True, grants__user=user)
    if manage:
        explicit &= Q(grants__manage=True)
    query = Document.objects.filter(Q(restricted=False, folder_id__in=folders) | explicit)
    if not manage:
        query = query.filter(archived=False, deleted_at__isnull=True)
    return query.distinct()


def can_manage_document(user, document):
    return permitted_documents(user, manage=True).filter(pk=document.pk).exists()
