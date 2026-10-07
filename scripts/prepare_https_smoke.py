"""Generate a localhost-only TLS fixture and production smoke environment."""

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

root = Path(__file__).resolve().parent.parent
directory = root / "secrets"
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
(directory / "smoke-cert.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
(directory / "smoke-key.pem").write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
)
values = {
    "POSTGRES_DB": "ssdc_smoke",
    "POSTGRES_USER": "ssdc_smoke",
    "ALLOWED_HOSTS": "localhost,127.0.0.1",
    "HEALTHCHECK_HOST": "localhost",
    "CSRF_TRUSTED_ORIGINS": "https://localhost:8443,https://127.0.0.1:8443",
    "DB_PASSWORD_FILE": (directory / "db-password").as_posix(),
    "DJANGO_KEY_FILE": (directory / "django-key").as_posix(),
    "MFA_KEY_FILE": (directory / "mfa-key").as_posix(),
    "TLS_CERT_FILE": (directory / "smoke-cert.pem").as_posix(),
    "TLS_KEY_FILE": (directory / "smoke-key.pem").as_posix(),
}
(root / ".env.production-smoke").write_text(
    "\n".join(f'{key}="{value}"' for key, value in values.items()) + "\n"
)
print(
    "Local TLS fixture and .env.production-smoke created; contains no public deployment configuration."
)
