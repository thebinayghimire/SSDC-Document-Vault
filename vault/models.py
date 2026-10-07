import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class Folder(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.PROTECT, related_name="children"
    )
    restricted = models.BooleanField(
        default=True,
        help_text="Replace ancestor grants (empty grants deny everyone except admins).",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name", "id"]

    def __str__(self):
        return self.name

    def clean(self):
        if self._state.adding and type(self).objects.count() >= settings.MAX_FOLDERS:
            raise ValidationError("The folder limit has been reached.")
        parent, seen = self.parent, {self.pk}
        depth = 0
        while parent:
            if parent.pk in seen:
                raise ValidationError("Folder cycles are not allowed.")
            seen.add(parent.pk)
            depth += 1
            if depth > 20:
                raise ValidationError("Folders may be nested at most 20 levels.")
            parent = parent.parent


class FolderGrant(models.Model):
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name="grants")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    manage = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["folder", "user"], name="unique_folder_grant")
        ]


class Document(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    folder = models.ForeignKey(Folder, on_delete=models.PROTECT, related_name="documents")
    restricted = models.BooleanField(
        default=False, help_text="Use document grants instead of folder grants."
    )
    archived = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True, db_index=True)
    active_version = models.ForeignKey(
        "Version", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        ordering = ["-modified_at", "id"]

    def __str__(self):
        return self.title

    def clean(self):
        if self.active_version and self.active_version.document_id != self.pk:
            raise ValidationError("Active version must belong to this document.")


class DocumentGrant(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name="grants")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    manage = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["document", "user"], name="unique_document_grant")
        ]


class Version(models.Model):
    class Status(models.TextChoices):
        QUARANTINED = "quarantined", "Quarantined"
        READY = "ready", "Ready"
        REJECTED = "rejected", "Rejected"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name="versions")
    original_name = models.CharField(max_length=255)
    storage_key = models.CharField(max_length=100, unique=True)
    thumbnail_key = models.CharField(max_length=100, blank=True)
    thumbnail_size = models.PositiveIntegerField(
        default=0, help_text="Reserved preview bytes until processing completes."
    )
    mime_type = models.CharField(max_length=80)
    size = models.PositiveBigIntegerField()
    sha256 = models.CharField(max_length=64)
    page_count = models.PositiveIntegerField(default=1)
    uploader = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.QUARANTINED, db_index=True
    )
    processing_note = models.CharField(max_length=120, blank=True)
    scan_result = models.CharField(max_length=32, blank=True)
