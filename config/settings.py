import base64
import hashlib
import os
from pathlib import Path

import dj_database_url
from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

from config.database import database_transport
from config.scanning import scan_mode

BASE_DIR = Path(__file__).resolve().parent.parent
# Neon writes local branch credentials here. Explicit process/container values
# always win, and neither ignored file is required in production.
load_dotenv(BASE_DIR / ".env.local", override=False)
load_dotenv(BASE_DIR / ".env", override=False)
ENVIRONMENT = os.getenv("APP_ENV", "development")
if ENVIRONMENT not in {"development", "test", "production"}:
    raise ImproperlyConfigured("Unknown APP_ENV")
PRODUCTION = ENVIRONMENT == "production"
RENDER_EXTERNAL_HOSTNAME = os.getenv("RENDER_EXTERNAL_HOSTNAME", "")


def positive_int(name, default, maximum):
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ImproperlyConfigured(f"{name} must be an integer") from exc
    if not 1 <= value <= maximum:
        raise ImproperlyConfigured(f"{name} must be between 1 and {maximum}")
    return value


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
ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver").split(",")
    if host.strip()
]
if ".onrender.com" not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append(".onrender.com")
if PRODUCTION and ("*" in ALLOWED_HOSTS or len(SECRET_KEY) < 44):
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
    "config.middleware.RequestReferenceMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "config.middleware.MaintenanceMiddleware",
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
# Upload processing and policy writes use PostgreSQL session advisory locks.
# Neon's transaction pooler cannot preserve that session state, so prefer the
# direct URL Neon supplies and retain DATABASE_URL for non-Neon deployments.
DATABASE_URL = os.getenv("DATABASE_URL_UNPOOLED") or os.getenv("DATABASE_URL")
if DATABASE_URL:
    DATABASES = {
        "default": dj_database_url.parse(
            DATABASE_URL,
            conn_max_age=600,
            ssl_require=not DEBUG,
        )
    }
    DATABASES["default"]["CONN_HEALTH_CHECKS"] = True
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": env("POSTGRES_DB", "ssdc"),
            "USER": env("POSTGRES_USER", "ssdc"),
            "PASSWORD": env("POSTGRES_PASSWORD", "local-development-only"),
            "HOST": env("POSTGRES_HOST", "127.0.0.1"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
            **database_transport(os.environ, PRODUCTION),
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
# Owner OAuth returns through a top-level cross-site GET; CSRF remains mandatory on writes.
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SECURE = PRODUCTION
CSRF_COOKIE_SECURE = PRODUCTION
SESSION_COOKIE_AGE = positive_int("SESSION_ABSOLUTE_SECONDS", 28800, 86400)
SESSION_IDLE_SECONDS = positive_int("SESSION_IDLE_SECONDS", 1800, SESSION_COOKIE_AGE)
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
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CSRF_TRUSTED_ORIGINS = [
    origin.strip() for origin in os.getenv("CSRF_TRUSTED_ORIGINS", "").split(",") if origin.strip()
]
if RENDER_EXTERNAL_HOSTNAME:
    render_origin = f"https://{RENDER_EXTERNAL_HOSTNAME}"
    if render_origin not in CSRF_TRUSTED_ORIGINS:
        CSRF_TRUSTED_ORIGINS.append(render_origin)
MFA_ALL_STAFF = os.getenv("MFA_ALL_STAFF", "0") == "1"
# Local development can temporarily use password-only login. Production always uses MFA.
MFA_ENABLED = PRODUCTION or os.getenv("MFA_ENABLED", "1") == "1"
MAX_UPLOAD_BYTES = positive_int("MAX_UPLOAD_BYTES", 25 * 1024 * 1024, 100 * 1024 * 1024)
MAX_STORAGE_BYTES = positive_int("MAX_STORAGE_BYTES", 10 * 1024**3, 100 * 1024**4)
MAX_IMAGE_PIXELS = positive_int("MAX_IMAGE_PIXELS", 20000000, 50000000)
MAX_PDF_PAGES = positive_int("MAX_PDF_PAGES", 500, 2000)
MAX_FOLDERS = positive_int("MAX_FOLDERS", 1000, 10000)
LOGIN_IP_LIMIT = positive_int("LOGIN_IP_LIMIT", 300, 10000)
LOGIN_ACCOUNT_LIMIT = positive_int("LOGIN_ACCOUNT_LIMIT", 10, 50)
PARSER_CONCURRENCY = positive_int("PARSER_CONCURRENCY", 1, 1)
SCANNER_MAX_SIGNATURE_HOURS = positive_int("SCANNER_MAX_SIGNATURE_HOURS", 72, 168)
DATA_UPLOAD_MAX_MEMORY_SIZE = MAX_UPLOAD_BYTES + 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024
FILE_UPLOAD_PERMISSIONS = 0o600
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o700
FILE_UPLOAD_HANDLERS = [
    "django.core.files.uploadhandler.MemoryFileUploadHandler",
    "vault.upload_handlers.BudgetedTemporaryFileUploadHandler",
]
SCAN_MODE = scan_mode(os.environ, PRODUCTION)
ENABLE_CLAMAV = SCAN_MODE == "clamav"
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "127.0.0.1")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
DOCUMENT_STORAGE_PROVIDER = os.getenv("DOCUMENT_STORAGE_PROVIDER", "gdrive")
if DOCUMENT_STORAGE_PROVIDER not in {"gdrive", "filesystem"}:
    raise ImproperlyConfigured("Unknown DOCUMENT_STORAGE_PROVIDER")


def drive_secret(name, *aliases):
    """Prefer runtime secrets, then fall back to mounted files for local/Compose use."""
    names = (name, *aliases)
    for candidate in names:
        value = os.getenv(candidate)
        if value:
            return value.strip()
    for candidate in names:
        file = os.getenv(f"{candidate}_FILE")
        if file:
            return Path(file).read_text().strip()
    return ""


GOOGLE_DRIVE_CLIENT_ID = drive_secret("GOOGLE_DRIVE_CLIENT_ID", "GOOGLE_CLIENT_ID")
GOOGLE_DRIVE_CLIENT_SECRET = drive_secret("GOOGLE_DRIVE_CLIENT_SECRET", "GOOGLE_CLIENT_SECRET")
GOOGLE_DRIVE_CREDENTIAL_KEY = drive_secret(
    "GOOGLE_DRIVE_CREDENTIAL_KEY", "DRIVE_TOKEN_ENCRYPTION_KEY"
)
GOOGLE_DRIVE_REDIRECT_URI = os.getenv(
    "GOOGLE_DRIVE_REDIRECT_URI",
    f"https://{RENDER_EXTERNAL_HOSTNAME}/storage/google/callback/"
    if RENDER_EXTERNAL_HOSTNAME
    else "",
)
if GOOGLE_DRIVE_CLIENT_SECRET or GOOGLE_DRIVE_CREDENTIAL_KEY:
    # Technical debug pages can disclose inner library locals, even with sensitive_variables.
    DEBUG = False
if GOOGLE_DRIVE_CREDENTIAL_KEY:
    try:
        Fernet(GOOGLE_DRIVE_CREDENTIAL_KEY.encode())
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured(
            "DRIVE_TOKEN_ENCRYPTION_KEY (or GOOGLE_DRIVE_CREDENTIAL_KEY) must be a valid Fernet key"
        ) from exc
if PRODUCTION and DOCUMENT_STORAGE_PROVIDER == "gdrive":
    if not all((GOOGLE_DRIVE_CLIENT_ID, GOOGLE_DRIVE_CLIENT_SECRET, GOOGLE_DRIVE_CREDENTIAL_KEY)):
        raise ImproperlyConfigured("Google Drive server secrets must be configured")
    if not GOOGLE_DRIVE_REDIRECT_URI.startswith("https://"):
        raise ImproperlyConfigured("Google Drive production redirect URI must use HTTPS")
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"safe": {"()": "config.logging.SafeJSONFormatter"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "safe"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {
        "django.request": {"handlers": ["console"], "level": "ERROR", "propagate": False},
        "django.server": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}
