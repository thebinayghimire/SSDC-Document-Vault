import secrets
import time

import pyotp
from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction

from audit.services import record

from .models import User


def cipher():
    return Fernet(settings.MFA_ENCRYPTION_KEY.encode())


def encrypt(secret):
    return cipher().encrypt(secret.encode()).decode()


def decrypt(secret):
    return cipher().decrypt(secret.encode()).decode()


def verify(user, token, allow_recovery=True, *, expected_auth_version=None):
    expected_auth_version = (
        user.auth_version if expected_auth_version is None else expected_auth_version
    )
    with transaction.atomic():
        locked = User.objects.select_for_update().get(pk=user.pk)
        if (
            not locked.is_active
            or not locked.mfa_confirmed
            or locked.auth_version != expected_auth_version
        ):
            return False
        if token.isdigit() and len(token) == 6:
            totp = pyotp.TOTP(decrypt(locked.mfa_secret))
            current = int(time.time()) // 30
            for step in (current - 1, current, current + 1):
                if step > locked.mfa_last_step and secrets.compare_digest(
                    totp.at(step * 30), token
                ):
                    locked.mfa_last_step = step
                    locked.save(update_fields=["mfa_last_step"])
                    return True
        if allow_recovery:
            for index, hashed in enumerate(locked.recovery_hashes):
                if check_password(token, hashed):
                    locked.recovery_hashes.pop(index)
                    locked.save(update_fields=["recovery_hashes"])
                    record(locked, "mfa_recovery_used")
                    return True
        return False


def create_recovery_codes():
    codes = [secrets.token_hex(8) for _ in range(8)]
    return codes, [make_password(code) for code in codes]
