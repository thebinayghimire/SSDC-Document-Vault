import io
from unittest.mock import patch

import pyotp
import pytest
from cryptography.fernet import Fernet
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError

from accounts.mfa import encrypt
from audit.models import Event


@pytest.mark.django_db
def test_operator_recovery_revokes_all_challenges_and_records_reference(users):
    user = users["admin"]
    user.mfa_secret = encrypt(pyotp.random_base32())
    user.mfa_confirmed = True
    user.recovery_hashes = ["Synthetic"]
    user.save(update_fields=["mfa_secret", "mfa_confirmed", "recovery_hashes"])
    version = user.auth_version
    call_command(
        "recover_admin",
        user.username,
        verified_identity=True,
        policy_reference="SYNTHETIC-APPROVAL",
        stdout=io.StringIO(),
    )
    user.refresh_from_db()
    assert user.auth_version == version + 1
    assert not user.mfa_secret and not user.mfa_confirmed and not user.recovery_hashes
    event = Event.objects.get(kind="operator_admin_recovery")
    assert event.details["policy_reference"] == "SYNTHETIC-APPROVAL"


@pytest.mark.django_db
def test_operator_recovery_audit_failure_rolls_back(users):
    before = users["admin"].auth_version
    with patch(
        "audit.services.Event.objects.create", side_effect=IntegrityError("Synthetic audit failure")
    ):
        with pytest.raises(IntegrityError):
            call_command(
                "recover_admin",
                "admin",
                verified_identity=True,
                policy_reference="TEST",
                stdout=io.StringIO(),
            )
    users["admin"].refresh_from_db()
    assert users["admin"].auth_version == before


@pytest.mark.django_db
def test_seed_rotation_dry_run_and_atomic_execution(users, tmp_path):
    seeds = {name: pyotp.random_base32() for name in ("admin", "manager")}
    for name, seed in seeds.items():
        users[name].mfa_secret = encrypt(seed)
        users[name].save(update_fields=["mfa_secret"])
    previous = {name: user.mfa_secret for name, user in users.items()}
    key = Fernet.generate_key()
    path = tmp_path / "replacement-key"
    path.write_bytes(key)
    call_command("rotate_mfa_key", new_key_file=path, policy_reference="TEST", stdout=io.StringIO())
    for name in seeds:
        users[name].refresh_from_db()
        assert users[name].mfa_secret == previous[name]
    call_command(
        "rotate_mfa_key",
        new_key_file=path,
        policy_reference="TEST",
        execute=True,
        stdout=io.StringIO(),
    )
    for name, seed in seeds.items():
        users[name].refresh_from_db()
        assert Fernet(key).decrypt(users[name].mfa_secret.encode()).decode() == seed
    assert Event.objects.filter(kind="operator_mfa_key_rotated").count() == 1


@pytest.mark.django_db
def test_invalid_seed_prevents_partial_rotation(users, tmp_path):
    users["admin"].mfa_secret = encrypt(pyotp.random_base32())
    users["admin"].save(update_fields=["mfa_secret"])
    users["manager"].mfa_secret = "corrupt"
    users["manager"].save(update_fields=["mfa_secret"])
    before = users["admin"].mfa_secret
    path = tmp_path / "replacement-key"
    path.write_bytes(Fernet.generate_key())
    with pytest.raises(CommandError, match="no changes committed"):
        call_command(
            "rotate_mfa_key",
            new_key_file=path,
            policy_reference="TEST",
            execute=True,
            stdout=io.StringIO(),
        )
    users["admin"].refresh_from_db()
    assert users["admin"].mfa_secret == before
