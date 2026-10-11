"""Generate a localhost-only TLS fixture and production smoke environment."""

import datetime
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from generate_secrets import generate, set_permissions

root = Path(__file__).resolve().parent.parent
directory = root / "secrets" / "smoke"
directory.mkdir(parents=True, exist_ok=True, mode=0o700)
linux = os.name == "posix"
if linux and os.geteuid() != 0:
    raise SystemExit("Linux smoke preparation requires root to assign service reader groups")
if not (directory / "db-password").exists():
    generate(directory, root / "recovery-secrets" / "smoke", linux=linux)
tls_directory = directory / "tls"
tls_directory.mkdir(mode=0o700, exist_ok=True)
for filename, value in (
    ("smoke-google-client-id", b"synthetic-not-a-google-client"),
    ("smoke-google-client-secret", b"synthetic-not-a-google-secret"),
    ("smoke-google-credential-key", Fernet.generate_key()),
):
    path = directory / filename
    if not path.exists():
        with path.open("xb") as stream:
            stream.write(value)
    set_permissions(path, 11001 if linux else None)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
now = datetime.datetime.now(datetime.UTC)
certificate = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=5))
    .not_valid_after(now + datetime.timedelta(days=2))
    .add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        ),
        critical=False,
    )
    .sign(key, hashes.SHA256())
)
(tls_directory / "cert.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
(tls_directory / "key.pem").write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
)
set_permissions(tls_directory / "key.pem")
values = {
    "PORTAL_HOST": "localhost",
    "HTTPS_PORT": "8443",
    "TLS_DIRECTORY": tls_directory.as_posix(),
    "APP_IMAGE": "ssdc-vault-app",
    "DB_IMAGE": "ssdc-postgres",
    "SCANNER_IMAGE": "ssdc-clamav",
    "PROXY_IMAGE": "ssdc-proxy",
    "POSTGRES_DB": "ssdc_smoke",
    "POSTGRES_USER": "ssdc_smoke",
    "ALLOWED_HOSTS": "localhost,127.0.0.1",
    "HEALTHCHECK_HOST": "localhost",
    "CSRF_TRUSTED_ORIGINS": "https://localhost:8443,https://127.0.0.1:8443",
    "DB_PASSWORD_FILE": (directory / "db-password").as_posix(),
    "DB_BOOTSTRAP_PASSWORD_FILE": (directory / "db-bootstrap-password").as_posix(),
    "DB_MIGRATION_PASSWORD_FILE": (directory / "db-migration-password").as_posix(),
    "DJANGO_KEY_FILE": (directory / "django-key").as_posix(),
    "MFA_KEY_FILE": (directory / "mfa-key").as_posix(),
    "TLS_CERT_FILE": (tls_directory / "cert.pem").as_posix(),
    "TLS_KEY_FILE": (tls_directory / "key.pem").as_posix(),
    "GOOGLE_DRIVE_CLIENT_ID_FILE": (directory / "smoke-google-client-id").as_posix(),
    "GOOGLE_DRIVE_CLIENT_SECRET_FILE": (directory / "smoke-google-client-secret").as_posix(),
    "GOOGLE_DRIVE_CREDENTIAL_KEY_FILE": (directory / "smoke-google-credential-key").as_posix(),
    "GOOGLE_DRIVE_REDIRECT_URI": "https://localhost:8443/storage/google/callback/",
}
(root / ".env.production-smoke").write_text(
    "\n".join(f'{key}="{value}"' for key, value in values.items()) + "\n"
)
print(
    "Local TLS fixture and .env.production-smoke created; contains no public deployment configuration."
)
