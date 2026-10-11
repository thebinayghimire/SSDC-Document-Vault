"""Confidential web-server OAuth for one storage owner, independent of staff login."""

import hashlib
import json
import secrets
from datetime import timedelta
from urllib.parse import urlsplit

import requests
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone
from google.auth.exceptions import RefreshError, TransportError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow

from .models import DriveConnection, DriveOAuthAttempt
from .mutations import mutation_access

SCOPE = "https://www.googleapis.com/auth/drive.file"


class StorageError(Exception):
    """Only fixed, safe messages cross the storage boundary."""

    def __init__(self, code="unavailable"):
        self.code = code
        super().__init__(
            {
                "reconnect": "Document storage needs administrator reconnection.",
                "missing": "Document content is unavailable.",
                "quota": "Google Drive storage is full. Contact an administrator.",
                "integrity": "Document storage integrity check failed.",
                "configuration": "Document storage setup is incomplete.",
            }.get(code, "Document storage is temporarily unavailable. Retry later.")
        )


def cipher():
    try:
        return Fernet(settings.GOOGLE_DRIVE_CREDENTIAL_KEY.encode())
    except (ValueError, TypeError):
        raise StorageError("configuration") from None


def oauth_flow(state=None):
    uri = urlsplit(settings.GOOGLE_DRIVE_REDIRECT_URI)
    if (
        not settings.GOOGLE_DRIVE_CLIENT_ID
        or not settings.GOOGLE_DRIVE_CLIENT_SECRET
        or uri.query
        or uri.fragment
        or uri.path != "/storage/google/callback/"
        or not uri.netloc
        or (
            uri.scheme != "https"
            and not (
                not settings.PRODUCTION
                and uri.scheme == "http"
                and uri.hostname in {"localhost", "127.0.0.1"}
            )
        )
    ):
        raise StorageError("configuration")
    cipher()
    return Flow.from_client_config(
        {
            "web": {
                "client_id": settings.GOOGLE_DRIVE_CLIENT_ID,
                "client_secret": settings.GOOGLE_DRIVE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [settings.GOOGLE_DRIVE_REDIRECT_URI],
            }
        },
        scopes=[SCOPE],
        state=state,
        redirect_uri=settings.GOOGLE_DRIVE_REDIRECT_URI,
    )


def hashed(value):
    return hashlib.sha256(value.encode()).hexdigest()


def begin_oauth(request):
    flow = oauth_flow()
    state = secrets.token_urlsafe(32)
    url, _ = flow.authorization_url(
        state=state,
        access_type="offline",
        prompt="consent select_account",
        include_granted_scopes="false",
    )
    with mutation_access(request.user) as user:
        if not user.is_portal_admin:
            raise PermissionDenied
        DriveOAuthAttempt.objects.filter(expires_at__lt=timezone.now()).delete()
        DriveOAuthAttempt.objects.create(
            state_hash=hashed(state),
            session_hash=hashed(request.session.session_key),
            encrypted_verifier=cipher().encrypt(flow.code_verifier.encode()).decode(),
            user=user,
            auth_version=user.auth_version,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
    return url


def finish_oauth(request):
    state = request.GET.get("state", "")
    with mutation_access(request.user) as user:
        if not user.is_portal_admin:
            raise PermissionDenied
        attempt = (
            DriveOAuthAttempt.objects.select_for_update()
            .filter(
                state_hash=hashed(state),
                user=user,
                auth_version=user.auth_version,
                session_hash=hashed(request.session.session_key),
                expires_at__gt=timezone.now(),
            )
            .first()
        )
        if not attempt:
            raise PermissionDenied
        verifier = cipher().decrypt(attempt.encrypted_verifier.encode()).decode()
        attempt.delete()  # Single use, including failed/denied exchanges.
    if request.GET.get("error") or not request.GET.get("code"):
        raise StorageError("reconnect")
    flow = oauth_flow(state)
    flow.code_verifier = verifier
    try:
        flow.fetch_token(code=request.GET["code"], timeout=15)
        credentials = flow.credentials
        granted = credentials.granted_scopes or credentials.scopes
        if SCOPE not in granted:
            raise StorageError("reconnect")
        response = requests.get(
            "https://www.googleapis.com/drive/v3/about",
            params={"fields": "user(permissionId)"},
            headers={"Authorization": f"Bearer {credentials.token}"},
            timeout=(5, 15),
            allow_redirects=False,
        )
        if response.status_code != 200:
            raise StorageError()
        owner_id = response.json()["user"]["permissionId"]
    except StorageError:
        raise
    except Exception:
        raise StorageError("reconnect") from None
    with mutation_access(request.user) as user:
        if not user.is_portal_admin:
            raise PermissionDenied
        DriveConnection.objects.get_or_create(pk=1)
        connection = DriveConnection.objects.select_for_update().get(pk=1)
        if connection.owner_id and owner_id != connection.owner_id:
            raise StorageError("reconnect")  # Never silently switch storage owners.
        if not credentials.refresh_token and connection.encrypted_credentials:
            previous = decrypt(connection.encrypted_credentials)
            credentials = Credentials.from_authorized_user_info(
                {
                    **json.loads(credentials.to_json()),
                    "refresh_token": previous["refresh_token"],
                },
                scopes=[SCOPE],
            )
        if not credentials.refresh_token:
            raise StorageError("reconnect")
        connection.encrypted_credentials = cipher().encrypt(credentials.to_json().encode()).decode()
        connection.owner_id = owner_id
        connection.reconnect_required = False
        connection.save()


def decrypt(value):
    try:
        return json.loads(cipher().decrypt(value.encode()))
    except (InvalidToken, ValueError, KeyError):
        raise StorageError("configuration") from None


class TimedRequest(Request):
    def __call__(self, *args, **kwargs):
        kwargs["timeout"] = (5, 10)
        return super().__call__(*args, **kwargs)


def access_token(force=False):
    # Serialize refresh across workers and keep refreshed tokens encrypted at rest.
    with transaction.atomic():
        connection = DriveConnection.objects.select_for_update().filter(pk=1).first()
        if not connection or not connection.encrypted_credentials or connection.reconnect_required:
            raise StorageError("reconnect")
        info = decrypt(connection.encrypted_credentials)
        info["client_id"] = settings.GOOGLE_DRIVE_CLIENT_ID
        info["client_secret"] = settings.GOOGLE_DRIVE_CLIENT_SECRET
        credentials = Credentials.from_authorized_user_info(info, scopes=[SCOPE])
        if force or not credentials.valid:
            try:
                credentials.refresh(TimedRequest())
            except RefreshError as exc:
                # Commit reconnect flag before raising outside the transaction.
                invalid = any(
                    isinstance(arg, dict) and arg.get("error") == "invalid_grant"
                    for arg in exc.args
                )
                if invalid:
                    connection.reconnect_required = True
                    connection.save(update_fields=["reconnect_required", "updated_at"])
                token = None
            except (TransportError, requests.RequestException):
                token = None
                invalid = False
            else:
                connection.encrypted_credentials = (
                    cipher().encrypt(credentials.to_json().encode()).decode()
                )
                connection.save(update_fields=["encrypted_credentials", "updated_at"])
                token = credentials.token
        else:
            token = credentials.token
    if token is None:
        raise StorageError("reconnect" if invalid else "unavailable") from None
    return token
