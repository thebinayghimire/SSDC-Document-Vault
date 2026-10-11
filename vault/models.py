import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import connection, models, transaction


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
        parents = dict(type(self).objects.values_list("pk", "parent_id"))
        if self.pk not in parents and len(parents) >= settings.MAX_FOLDERS:
            raise ValidationError("The folder limit has been reached.")
        parents[self.pk] = self.parent_id
        for identifier in parents:
            seen, node, depth = set(), identifier, 0
            while node is not None:
                if node in seen:
                    raise ValidationError({"parent": "Folder cycles are not allowed."})
                seen.add(node)
                if depth > 20:
                    raise ValidationError(
                        {
                            "parent": "Folders may be nested at most 20 levels, including descendants."
                        }
                    )
                node = parents.get(node)
                depth += 1

    def save(self, *args, **kwargs):
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(731012)")
            fields = kwargs.get("update_fields")
            if fields is not None and "parent" not in fields and "parent_id" not in fields:
                current = (
                    type(self)
                    .objects.filter(pk=self.pk)
                    .values_list("parent_id", flat=True)
                    .first()
                )
                self.parent_id = current
            self.clean()
            return super().save(*args, **kwargs)


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
    selection_revision = models.PositiveBigIntegerField(default=0, editable=False)

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
    storage_provider = models.CharField(max_length=16, default="filesystem")
    thumbnail_key = models.CharField(max_length=100, blank=True)
    thumbnail_size = models.PositiveIntegerField(
        default=0, help_text="Reserved preview bytes until processing completes."
    )
    thumbnail_sha256 = models.CharField(max_length=64, blank=True, editable=False)
    selection_revision = models.PositiveBigIntegerField(default=0, editable=False)
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


class DriveConnection(models.Model):
    """Singleton owner credentials; never register this model with Django admin."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    installation_id = models.UUIDField(default=uuid.uuid4, editable=False)
    encrypted_credentials = models.TextField(blank=True)
    owner_id = models.CharField(max_length=128, blank=True)
    folder_id = models.CharField(max_length=128, blank=True)
    reconnect_required = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "SSDC Drive connection"


class DriveObject(models.Model):
    """Durable upload intent survives publication rollback and document purge."""

    key = models.CharField(max_length=100, unique=True)
    file_id = models.CharField(max_length=128, unique=True)
    folder_id = models.CharField(max_length=128)
    installation_id = models.UUIDField()
    size = models.PositiveBigIntegerField()
    sha256 = models.CharField(max_length=64)
    md5 = models.CharField(max_length=32)
    mime_type = models.CharField(max_length=80)
    complete = models.BooleanField(default=False)
    encrypted_session = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class DriveOAuthAttempt(models.Model):
    state_hash = models.CharField(max_length=64, primary_key=True)
    session_hash = models.CharField(max_length=64)
    encrypted_verifier = models.TextField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    auth_version = models.PositiveIntegerField()
    expires_at = models.DateTimeField()
