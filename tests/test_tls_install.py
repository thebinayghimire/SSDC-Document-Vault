"""Portable TLS installer checks; run on Linux with OpenSSL and cryptography."""

import shutil
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scripts.install_tls import install


def certificate(directory, hostname="vault.example.org", expired=False):
    directory.mkdir()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=3))
        .not_valid_after(now + timedelta(days=-1 if expired else 30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    (directory / "fullchain.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "privkey.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return directory


@unittest.skipUnless(shutil.which("openssl"), "Linux/OpenSSL required")
class TLSInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.first = certificate(self.root / "first")
        self.destination = self.root / "tls"

    def test_pair_rotation_keeps_stable_links_and_private_key_permissions(self):
        install(self.first, self.destination, "vault.example.org")
        first_target = (self.destination / "current").readlink()
        second = certificate(self.root / "second")
        install(second, self.destination, "vault.example.org")
        self.assertNotEqual(first_target, (self.destination / "current").readlink())
        self.assertEqual(
            (self.destination / "cert.pem").read_bytes(), (second / "fullchain.pem").read_bytes()
        )
        self.assertEqual((self.destination / "key.pem").stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.destination / first_target / "cert.pem").exists())

    def test_invalid_pairs_leave_existing_certificate_unchanged(self):
        install(self.first, self.destination, "vault.example.org")
        previous = (self.destination / "current").readlink()
        wrong_host = certificate(self.root / "wrong-host", "other.example.org")
        expired = certificate(self.root / "expired", expired=True)
        mismatch = certificate(self.root / "mismatch")
        (mismatch / "privkey.pem").write_bytes((wrong_host / "privkey.pem").read_bytes())
        for lineage in (wrong_host, expired, mismatch):
            with self.subTest(lineage=lineage):
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    install(lineage, self.destination, "vault.example.org")
                self.assertEqual(previous, (self.destination / "current").readlink())

    def test_unmanaged_pair_is_preserved(self):
        self.destination.mkdir()
        (self.destination / "cert.pem").write_text("existing operator certificate")
        with self.assertRaisesRegex(ValueError, "managed"):
            install(self.first, self.destination, "vault.example.org")
        self.assertEqual(
            (self.destination / "cert.pem").read_text(), "existing operator certificate"
        )

    def test_reload_failure_restores_previous_pair(self):
        install(self.first, self.destination, "vault.example.org")
        previous = (self.destination / "current").readlink()
        real_run = subprocess.run

        def failing_proxy(command, **kwargs):
            if command[0] == "docker":
                raise subprocess.CalledProcessError(1, command)
            return real_run(command, **kwargs)

        with patch("scripts.install_tls.subprocess.run", side_effect=failing_proxy):
            with self.assertRaisesRegex(RuntimeError, "restored"):
                install(
                    certificate(self.root / "second"),
                    self.destination,
                    "vault.example.org",
                    True,
                    self.root,
                    self.root / "environment",
                )
        self.assertEqual(previous, (self.destination / "current").readlink())

    def test_pilot_rotation_reloads_the_pilot_stack(self):
        install(self.first, self.destination, "vault.example.org")
        real_run, commands = subprocess.run, []

        def run(command, **kwargs):
            if command[0] == "docker":
                commands.append(command)
                return subprocess.CompletedProcess(command, 0)
            return real_run(command, **kwargs)

        with patch("scripts.install_tls.subprocess.run", side_effect=run):
            install(
                certificate(self.root / "second"),
                self.destination,
                "vault.example.org",
                True,
                self.root,
                self.root / "pilot.env",
                compose_file="compose.pilot.yaml",
            )
        self.assertEqual(len(commands), 2)
        self.assertTrue(all(str(self.root / "compose.pilot.yaml") in c for c in commands))
        self.assertTrue(all(str(self.root / "compose.prod.yaml") not in c for c in commands))


if __name__ == "__main__":
    unittest.main()
