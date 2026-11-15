"""One-time email codes: generation, keyed digests, and encrypted outbox payloads."""

import hmac
import secrets
from hashlib import sha256

from django.conf import settings

from accounts.mfa import decrypt, encrypt

OTP_LENGTH = 6


class OtpError(Exception):
    """Base class for safe, user-facing OTP workflow failures."""


class OtpInvalid(OtpError):
    pass


class OtpExpired(OtpError):
    pass


class OtpLocked(OtpError):
    pass


class OtpReplay(OtpError):
    pass


class OtpCooldown(OtpError):
    def __init__(self, retry_after):
        self.retry_after = max(0, int(retry_after))
        super().__init__("Please wait before requesting another code.")


class OtpRateLimited(OtpError):
    pass


def generate_otp():
    """Return a cryptographically random six-digit code, including leading zeros."""
    return f"{secrets.randbelow(10**OTP_LENGTH):0{OTP_LENGTH}d}"


def otp_digest(purpose, subject_id, code):
    """Return a keyed digest bound to one workflow subject."""
    message = f"{purpose}:{subject_id}:{code}".encode()
    return hmac.new(settings.SECRET_KEY.encode(), message, sha256).hexdigest()


def verify_otp(purpose, subject_id, digest, code):
    if not digest or not code:
        return False
    return hmac.compare_digest(otp_digest(purpose, subject_id, code), digest)


def encrypt_otp(code):
    """Encrypt an OTP only so the outbox can deliver it later without plaintext storage."""
    return encrypt(code)


def decrypt_otp(ciphertext):
    return decrypt(ciphertext)
