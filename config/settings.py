import base64
import hashlib
import os
from pathlib import Path

from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
ENVIRONMENT = os.getenv("APP_ENV", "development")
if ENVIRONMENT not in {"development", "test", "production"}:
    raise ImproperlyConfigured("Unknown APP_ENV")
PRODUCTION = ENVIRONMENT == "production"


def env(name, default=None):
    file = os.getenv(f"{name}_FILE")
    if PRODUCTION and not (file or os.getenv(name)):
        raise ImproperlyConfigured(f"{name} must be explicitly configured in production")
    value = Path(file).read_text().strip() if file else os.getenv(name, default)
    if PRODUCTION and not value:
        raise ImproperlyConfigured(f"{name} is required")
    return value


SECRET_KEY = env(
    "SECRET_KEY", None if PRODUCTION else "development-only-ssdc-never-deploy-this-key"
)
MFA_ENCRYPTION_KEY = env(
    "MFA_ENCRYPTION_KEY",
    None
    if PRODUCTION
    else base64.urlsafe_b64encode(hashlib.sha256(b"ssdc-development-only").digest()).decode(),
)
try:
    Fernet(MFA_ENCRYPTION_KEY.encode())
except (ValueError, TypeError) as exc:
    raise ImproperlyConfigured("MFA_ENCRYPTION_KEY must be a valid Fernet key") from exc
if (
    PRODUCTION
    and MFA_ENCRYPTION_KEY
    == base64.urlsafe_b64encode(hashlib.sha256(b"ssdc-development-only").digest()).decode()
):
    raise ImproperlyConfigured("Production cannot use the development MFA key")
DEBUG = os.getenv("DEBUG", "0") == "1" and not PRODUCTION
ALLOWED_HOSTS = env("ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver").split(",")
if PRODUCTION and ("*" in ALLOWED_HOSTS or len(SECRET_KEY) < 50):
    raise ImproperlyConfigured("Production needs explicit hosts and a strong SECRET_KEY")
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "accounts",
    "audit",
    "vault",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "config.middleware.SessionPolicyMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "config.middleware.PrivateHeadersMiddleware",
]
ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB", "ssdc"),
        "USER": env("POSTGRES_USER", "ssdc"),
        "PASSWORD": env("POSTGRES_PASSWORD", "local-development-only"),
        "HOST": env("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": 60 if PRODUCTION else 0,
        "OPTIONS": {"connect_timeout": 5},
    }
}
AUTH_USER_MODEL = "accounts.User"
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Kathmandu"
USE_I18N = True
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}
PRIVATE_STORAGE_ROOT = Path(os.getenv("PRIVATE_STORAGE_ROOT", str(BASE_DIR / "private-media")))
if any(
    PRIVATE_STORAGE_ROOT.resolve().is_relative_to(Path(public).resolve())
    for public in [STATIC_ROOT, *STATICFILES_DIRS]
):
    raise ImproperlyConfigured("Private storage must be outside all public static directories")
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SECURE = PRODUCTION
CSRF_COOKIE_SECURE = PRODUCTION
SESSION_COOKIE_AGE = int(os.getenv("SESSION_ABSOLUTE_SECONDS", "28800"))
SESSION_IDLE_SECONDS = int(os.getenv("SESSION_IDLE_SECONDS", "1800"))
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
SECURE_SSL_REDIRECT = PRODUCTION
SECURE_HSTS_SECONDS = 31536000 if PRODUCTION else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = PRODUCTION
SECURE_HSTS_PRELOAD = False
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
if PRODUCTION:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CSRF_TRUSTED_ORIGINS = (
    os.getenv("CSRF_TRUSTED_ORIGINS", "").split(",") if os.getenv("CSRF_TRUSTED_ORIGINS") else []
)
MFA_ALL_STAFF = os.getenv("MFA_ALL_STAFF", "0") == "1"
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
MAX_STORAGE_BYTES = int(os.getenv("MAX_STORAGE_BYTES", str(10 * 1024**3)))
MAX_IMAGE_PIXELS = int(os.getenv("MAX_IMAGE_PIXELS", "20000000"))
MAX_PDF_PAGES = int(os.getenv("MAX_PDF_PAGES", "500"))
MAX_FOLDERS = int(os.getenv("MAX_FOLDERS", "1000"))
DATA_UPLOAD_MAX_MEMORY_SIZE = MAX_UPLOAD_BYTES + 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024
FILE_UPLOAD_PERMISSIONS = 0o600
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o700
SCAN_MODE = os.getenv("SCAN_MODE", "clamav")
if SCAN_MODE not in {"clamav", "skip-development"} or (PRODUCTION and SCAN_MODE != "clamav"):
    raise ImproperlyConfigured("Production requires ClamAV scanning")
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "127.0.0.1")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"safe": {"()": "config.logging.SafeJSONFormatter"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "safe"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {"django.request": {"handlers": ["console"], "level": "ERROR", "propagate": False}},
}
