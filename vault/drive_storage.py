"""Private Drive blobs. Pre-generated IDs make uncertain creates safe to retry."""

import hashlib
import random
import re
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from urllib.parse import quote, urlsplit

import requests
from cryptography.fernet import InvalidToken
from django.db import transaction

from .drive_auth import StorageError, access_token, cipher
from .models import DriveConnection, DriveObject

API = "https://www.googleapis.com/drive/v3"
UPLOAD = "https://www.googleapis.com/upload/drive/v3/files"
FIELDS = (
    "id,size,mimeType,md5Checksum,appProperties,parents,ownedByMe,trashed,permissions(type,role)"
)
CHUNK = 1024 * 1024  # Multiple of Drive's 256 KiB resumable chunk size.
DEADLINE = ContextVar("drive_deadline", default=None)
# PDF.js issues many byte-range requests for one preview. Cache only Drive
# metadata (never document bytes) briefly so each range needs one media call.
METADATA_CACHE_SECONDS = 30
METADATA_CACHE_LIMIT = 512
_METADATA_CACHE = OrderedDict()
_METADATA_CACHE_LOCK = threading.Lock()


@contextmanager
def network_budget(seconds=60):
    outer = DEADLINE.get()
    token = DEADLINE.set(
        min(outer, time.monotonic() + seconds) if outer else time.monotonic() + seconds
    )
    try:
        yield
    finally:
        DEADLINE.reset(token)


def bounded_operation(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with network_budget():
            return function(*args, **kwargs)

    return wrapped


def backoff(attempt):
    delay = min(8, 2**attempt) + random.uniform(0, 1)
    if DEADLINE.get() and time.monotonic() + delay >= DEADLINE.get():
        raise StorageError()
    time.sleep(delay)


@bounded_operation
def request(method, url, *, accepted=(200,), attempts=4, **kwargs):
    token = access_token()
    headers = {"Accept-Encoding": "identity", **kwargs.pop("headers", {})}
    attempt, refreshed = 0, False
    while attempt < attempts:
        remaining = DEADLINE.get() - time.monotonic()
        if remaining <= 0:
            raise StorageError()
        try:
            response = requests.request(
                method,
                url,
                headers={**headers, "Authorization": f"Bearer {token}"},
                timeout=(min(5, remaining), min(10, remaining)),
                allow_redirects=False,
                **kwargs,
            )
        except requests.RequestException:
            if attempt + 1 == attempts:
                raise StorageError() from None
            backoff(attempt)
            attempt += 1
            continue
        if response.status_code in accepted:
            return response
        try:
            reasons = {e.get("reason") for e in response.json().get("error", {}).get("errors", [])}
        except (ValueError, AttributeError, TypeError):
            reasons = set()
        status = response.status_code
        response.close()
        if status == 401 and not refreshed:
            token = access_token(force=True)
            refreshed = True
            continue
        if "storageQuotaExceeded" in reasons:
            raise StorageError("quota")
        if status == 404:
            raise StorageError("missing")
        if status == 401:
            DriveConnection.objects.filter(pk=1).update(reconnect_required=True)
            raise StorageError("reconnect")
        transient = (
            status == 429
            or 500 <= status < 600
            or bool(reasons & {"rateLimitExceeded", "userRateLimitExceeded", "backendError"})
        )
        if not transient or attempt + 1 == attempts:
            raise StorageError()
        backoff(attempt)
        attempt += 1
    raise StorageError()


def forget_metadata(identifier=None):
    """Drop cached metadata after a mutation or when tests replace the Drive backend."""
    with _METADATA_CACHE_LOCK:
        if identifier is None:
            _METADATA_CACHE.clear()
        else:
            _METADATA_CACHE.pop(identifier, None)


def metadata(identifier, *, cache_seconds=0):
    now = time.monotonic()
    if cache_seconds > 0:
        with _METADATA_CACHE_LOCK:
            cached = _METADATA_CACHE.get(identifier)
            if cached is not None:
                expires_at, data = cached
                if expires_at > now:
                    _METADATA_CACHE.move_to_end(identifier)
                    return data
                _METADATA_CACHE.pop(identifier, None)
    data = request(
        "GET", f"{API}/files/{quote(identifier, safe='')}", params={"fields": FIELDS}
    ).json()
    if cache_seconds > 0:
        with _METADATA_CACHE_LOCK:
            _METADATA_CACHE[identifier] = (now + cache_seconds, data)
            _METADATA_CACHE.move_to_end(identifier)
            while len(_METADATA_CACHE) > METADATA_CACHE_LIMIT:
                _METADATA_CACHE.popitem(last=False)
    return data


def private_owned(data, installation, key, folder=None):
    return (
        data.get("ownedByMe") is True
        and not data.get("trashed")
        and data.get("appProperties") == {"ssdc_installation": str(installation), "ssdc_key": key}
        and (folder is None or data.get("parents") == [folder])
        and bool(data.get("permissions"))
        and all(
            p.get("type") == "user" and p.get("role") == "owner"
            for p in data.get("permissions", [])
        )
    )


@bounded_operation
def ensure_folder(cache_seconds=0):
    DriveConnection.objects.get_or_create(pk=1)
    with transaction.atomic():
        connection = DriveConnection.objects.select_for_update().get(pk=1)
        if not connection.folder_id:
            connection.folder_id = request(
                "GET",
                f"{API}/files/generateIds",
                params={
                    "count": 1,
                    "space": "drive",
                    "type": "files",
                },
            ).json()["ids"][0]
            connection.save(update_fields=["folder_id", "updated_at"])
        identifier, installation = connection.folder_id, connection.installation_id
    try:
        data = metadata(identifier, cache_seconds=cache_seconds)
    except StorageError as exc:
        if exc.code != "missing":
            raise
        response = request(
            "POST",
            f"{API}/files",
            accepted=(200, 201, 409),
            params={"fields": FIELDS},
            json={
                "id": identifier,
                "name": "SSDC Private Documents",
                "mimeType": "application/vnd.google-apps.folder",
                "appProperties": {"ssdc_installation": str(installation), "ssdc_key": "root"},
            },
        )
        response.close()
        forget_metadata(identifier)
        data = metadata(identifier, cache_seconds=cache_seconds)
    if (
        not private_owned(data, installation, "root")
        or data.get("mimeType") != "application/vnd.google-apps.folder"
    ):
        raise StorageError("integrity")
    return connection


class RemoteStream:
    def __init__(self, response, length):
        self.response, self.length = response, length
        self.deadline = time.monotonic() + 60

    def __iter__(self):
        remaining = self.length
        try:
            for block in self.response.iter_content(65536):
                if time.monotonic() > self.deadline:
                    raise StorageError()
                if len(block) > remaining:
                    raise StorageError("integrity")
                remaining -= len(block)
                yield block
            if remaining:
                raise StorageError()
        except requests.RequestException:
            raise StorageError() from None
        finally:
            self.close()

    def close(self):
        self.response.close()


class GoogleDriveStorage:
    def object(self, key):
        obj = DriveObject.objects.filter(key=key).first()
        if not obj:
            raise StorageError("missing")
        return obj

    def verified(self, obj, *, cache_seconds=0):
        data = metadata(obj.file_id, cache_seconds=cache_seconds)
        if not (
            private_owned(data, obj.installation_id, obj.key, obj.folder_id)
            and int(data.get("size", -1)) == obj.size
            and data.get("mimeType") == obj.mime_type
            and data.get("md5Checksum") == obj.md5
        ):
            raise StorageError("integrity")
        return data

    @bounded_operation
    def put(self, key, path, mime, name):
        connection = ensure_folder()
        with path.open("rb") as stream:
            sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        with path.open("rb") as stream:
            md5 = hashlib.file_digest(stream, "md5").hexdigest()
        obj = DriveObject.objects.filter(key=key).first()
        if obj is None:
            identifier = request("GET", f"{API}/files/generateIds", params={"count": 1}).json()[
                "ids"
            ][0]
            obj = DriveObject.objects.create(
                key=key,
                file_id=identifier,
                folder_id=connection.folder_id,
                installation_id=connection.installation_id,
                size=path.stat().st_size,
                sha256=sha256,
                md5=md5,
                mime_type=mime,
            )  # Committed intent BEFORE any file upload.
        if (obj.sha256, obj.size, obj.mime_type) != (sha256, path.stat().st_size, mime):
            raise StorageError("integrity")
        try:
            self.verified(obj)
        except StorageError as exc:
            if exc.code == "integrity" and obj.encrypted_session and not obj.complete:
                partial = metadata(obj.file_id)
                if not (
                    private_owned(partial, obj.installation_id, obj.key, obj.folder_id)
                    and partial.get("size") in {None, "0", 0}
                    and not partial.get("md5Checksum")
                ):
                    raise
            elif exc.code != "missing":
                raise
            self.upload(obj, path, name)
            forget_metadata(obj.file_id)
            self.verified(obj)
        DriveObject.objects.filter(pk=obj.pk).update(complete=True, encrypted_session="")

    def upload(self, obj, path, name):
        deadline = time.monotonic() + 75
        offset = 0
        if obj.encrypted_session:
            try:
                session = cipher().decrypt(obj.encrypted_session.encode()).decode()
            except (InvalidToken, ValueError):
                raise StorageError("configuration") from None
            response = request(
                "PUT",
                session,
                accepted=(200, 201, 308, 404),
                data=b"",
                headers={"Content-Range": f"bytes */{obj.size}"},
            )
            status, received = response.status_code, response.headers.get("Range", "")
            response.close()
            if status in {200, 201}:
                return
            if status == 308:
                match = re.fullmatch(r"bytes=0-(\d+)", received)
                if received and not match:
                    raise StorageError("integrity")
                offset = int(match[1]) + 1 if match else 0
                if offset >= obj.size:
                    raise StorageError("integrity")
            else:
                # Expired resumable sessions restart with the SAME reserved file ID.
                DriveObject.objects.filter(pk=obj.pk).update(encrypted_session="")
                session = ""
        else:
            session = ""
        if not session:
            session = self.start_upload(obj, name)
            if session is None:
                return
            encrypted = cipher().encrypt(session.encode()).decode()
            DriveObject.objects.filter(pk=obj.pk).update(encrypted_session=encrypted)
        self.send_chunks(obj, path, session, offset, deadline)

    def start_upload(self, obj, name):
        response = request(
            "POST",
            UPLOAD,
            accepted=(200, 201, 409),
            params={
                "uploadType": "resumable",
                "fields": "id",
            },
            headers={
                "X-Upload-Content-Type": obj.mime_type,
                "X-Upload-Content-Length": str(obj.size),
            },
            json={
                "id": obj.file_id,
                "name": name,
                "mimeType": obj.mime_type,
                "parents": [obj.folder_id],
                "appProperties": {
                    "ssdc_installation": str(obj.installation_id),
                    "ssdc_key": obj.key,
                },
            },
        )
        if response.status_code == 409:
            response.close()
            return None  # Caller verifies ownership and digest; never blindly accepts a conflict.
        session = response.headers.get("Location", "")
        response.close()
        uri = urlsplit(session)
        if (
            uri.scheme != "https"
            or uri.netloc != "www.googleapis.com"
            or not uri.path.startswith("/upload/drive/v3/files")
        ):
            raise StorageError("integrity")
        return session

    def send_chunks(self, obj, path, session, offset, deadline):
        recoveries = 0
        with path.open("rb") as stream:
            while offset < obj.size:
                if time.monotonic() > deadline:
                    raise StorageError()
                stream.seek(offset)
                block = stream.read(min(CHUNK, obj.size - offset))
                try:
                    response = request(
                        "PUT",
                        session,
                        attempts=1,
                        accepted=(200, 201, 308, 409),
                        data=block,
                        headers={
                            "Content-Type": obj.mime_type,
                            "Content-Range": f"bytes {offset}-{offset + len(block) - 1}/{obj.size}",
                        },
                    )
                except StorageError as exc:
                    if exc.code != "unavailable" or recoveries >= 3:
                        raise
                    backoff(recoveries)
                    recoveries += 1
                    # Probe the server offset after an uncertain chunk; never invent progress.
                    response = request(
                        "PUT",
                        session,
                        accepted=(200, 201, 308),
                        data=b"",
                        headers={"Content-Range": f"bytes */{obj.size}"},
                    )
                if response.status_code in {200, 201, 409}:
                    response.close()
                    return
                received = response.headers.get("Range", "")
                response.close()
                match = re.fullmatch(r"bytes=0-(\d+)", received)
                next_offset = int(match[1]) + 1 if match else 0
                if received and not match or next_offset > obj.size or next_offset < offset:
                    raise StorageError("integrity")
                if next_offset == offset:
                    recoveries += 1
                    if recoveries > 3:
                        raise StorageError()
                    backoff(recoveries - 1)
                offset = next_offset
        raise StorageError()

    @bounded_operation
    def size(self, key):
        obj = self.object(key)
        if not obj.complete:
            raise StorageError()
        # Fail closed if the owner changed folder sharing outside SSDC. A short
        # metadata-only cache avoids two extra Drive calls for every PDF.js range.
        ensure_folder(cache_seconds=METADATA_CACHE_SECONDS)
        self.verified(obj, cache_seconds=METADATA_CACHE_SECONDS)
        return obj.size

    def exists(self, key):
        try:
            self.size(key)
            return True
        except StorageError as exc:
            if exc.code == "missing":
                return False
            raise

    def open(self, key, start=0, end=None):
        obj = self.object(key)
        headers = {} if end is None else {"Range": f"bytes={start}-{end}"}
        response = request(
            "GET",
            f"{API}/files/{quote(obj.file_id, safe='')}",
            accepted=(200, 206),
            params={"alt": "media"},
            headers=headers,
            stream=True,
        )
        expected = obj.size if end is None else end - start + 1
        valid = response.status_code == (200 if end is None else 206)
        if end is not None:
            valid = (
                valid and response.headers.get("Content-Range") == f"bytes {start}-{end}/{obj.size}"
            )
        valid = valid and response.headers.get("Content-Length") == str(expected)
        if not valid:
            response.close()
            raise StorageError("integrity")
        return RemoteStream(response, expected)

    def delete_orphan(self, key, *, allow_incomplete=False):
        from .storage import key_is_referenced

        if key_is_referenced(key):
            raise StorageError("integrity")
        obj = self.object(key)
        try:
            if allow_incomplete and not obj.complete:
                # An interrupted resumable upload cannot have the final digest.
                # Ownership, key, parent and a bounded partial size still prove
                # this is the private object reserved for this unreferenced key.
                data = metadata(obj.file_id)
                size = data.get("size")
                if size is None or size in {"0", 0}:
                    valid = True
                else:
                    try:
                        valid = 0 <= int(size) <= obj.size
                    except (TypeError, ValueError):
                        valid = False
                if not (
                    valid
                    and private_owned(data, obj.installation_id, obj.key, obj.folder_id)
                    and data.get("mimeType") in {None, obj.mime_type}
                ):
                    raise StorageError("integrity")
            else:
                self.verified(obj)  # Both app ownership and digest must match before removal.
            response = request(
                "DELETE", f"{API}/files/{quote(obj.file_id, safe='')}", accepted=(204, 404)
            )
            response.close()
        except StorageError as exc:
            if exc.code != "missing":
                raise
        forget_metadata(obj.file_id)
        obj.delete()
