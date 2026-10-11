import time

import pyotp
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.hashers import check_password
from django.db import transaction
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods, require_POST

from audit.services import allow_rate, identity_reference, record

from .forms import CodeForm, LoginForm, ReauthenticateForm
from .mfa import create_recovery_codes, decrypt, encrypt, verify
from .models import User


def finish_login(request, user, mfa_verified=False):
    # Never upgrade an earlier password proof to a newer authorization version.
    # MFA callers retain this lock from verification through completion.
    with transaction.atomic():
        locked = (
            User.objects.select_for_update()
            .filter(pk=user.pk, is_active=True, auth_version=user.auth_version)
            .first()
        )
        if not locked:
            return False
        if mfa_verified:
            if (
                not locked.mfa_confirmed
                or request.session.get("pending_user") != locked.pk
                or not pending_is_fresh(request)
            ):
                return False
        elif locked.requires_authenticator:
            return False
        login(request, locked, backend="django.contrib.auth.backends.ModelBackend")
        now = time.time()
        request.session.update(
            {
                "auth_version": locked.auth_version,
                "auth_started": now,
                "last_seen": now,
                "reauth_at": now,
                "mfa_verified": mfa_verified,
            }
        )
        for field in ("pending_user", "pending_at", "pending_auth_version", "enrollment_secret"):
            request.session.pop(field, None)
        record(locked, "login")
        return True


def restart_login(request):
    logout(request)
    return redirect("login")


def pending_is_fresh(request):
    return 0 <= time.time() - request.session.get("pending_at", 0) <= 300


def pending_matches(request, user):
    return (
        user is not None
        and user.is_active
        and user.pk == request.session.get("pending_user")
        and user.auth_version == request.session.get("pending_auth_version")
        and pending_is_fresh(request)
    )


def locked_session_user(request):
    """Reload the authenticated account inside the caller's write transaction."""
    user = User.objects.select_for_update().filter(pk=request.user.pk).first()
    now = time.time()
    session = request.session
    if (
        not user
        or not user.is_active
        or user.auth_version != session.get("auth_version")
        or now - session.get("auth_started", 0) > settings.SESSION_COOKIE_AGE
        or now - session.get("last_seen", 0) > settings.SESSION_IDLE_SECONDS
        or (user.requires_authenticator and not session.get("mfa_verified"))
    ):
        return None
    return user


@require_http_methods(["GET", "POST"])
def sign_in(request):
    if request.user.is_authenticated:
        return redirect("library")
    form = LoginForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        identity = form.cleaned_data["staff_id"]
        ip = (
            request.META.get("HTTP_X_REAL_IP")
            if settings.PRODUCTION
            else request.META.get("REMOTE_ADDR")
        )
        ip_ok = allow_rate("login-ip", ip or "unknown", settings.LOGIN_IP_LIMIT)
        account_ok = (
            allow_rate("login-account", identity, settings.LOGIN_ACCOUNT_LIMIT) if ip_ok else False
        )
        if not ip_ok or not account_ok:
            record(
                None,
                "login",
                outcome="throttled",
                details={"identity_hash": identity_reference(identity)},
            )
            form.add_error(None, "Unable to sign in. Please try again later.")
        else:
            with transaction.atomic():
                # Django can upgrade an older password hash during authenticate().
                # Lock before that check so its write cannot undo a concurrent reset.
                password_account = (
                    User.objects.select_for_update().filter(username=identity).first()
                )
                previous_hash = password_account.password if password_account else None
                user = authenticate(
                    request, username=identity, password=form.cleaned_data["password"]
                )
                if password_account:
                    password_account.refresh_from_db(fields=["password", "auth_version"])
                    if password_account.password != previous_hash:
                        record(password_account, "password_hash_upgraded", password_account.pk)
                if user:
                    user = (
                        User.objects.select_for_update()
                        .filter(pk=user.pk, is_active=True, auth_version=user.auth_version)
                        .first()
                    )
                    if user:
                        if user.requires_authenticator:
                            request.session.flush()
                            request.session["pending_user"] = user.pk
                            request.session["pending_at"] = time.time()
                            request.session["pending_auth_version"] = user.auth_version
                            return redirect("mfa_challenge" if user.mfa_confirmed else "mfa_enroll")
                        if finish_login(request, user):
                            return redirect("library")
            record(
                None,
                "login",
                outcome="denied",
                details={"identity_hash": identity_reference(identity)},
            )
            form.add_error(None, "Unable to sign in. Check your credentials.")
    return render(request, "accounts/login.html", {"form": form})


def pending_user(request):
    if not pending_is_fresh(request):
        return None
    user = User.objects.filter(pk=request.session.get("pending_user"), is_active=True).first()
    if pending_matches(request, user):
        return user
    return None


@require_http_methods(["GET", "POST"])
def mfa_challenge(request):
    if not settings.MFA_ENABLED:
        return redirect("library" if request.user.is_authenticated else "login")
    if request.user.is_authenticated:
        return redirect("library")
    user = pending_user(request)
    if not user or not user.mfa_confirmed:
        return restart_login(request)
    form = CodeForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        if allow_rate("mfa", str(user.pk), 10):
            with transaction.atomic():
                user = User.objects.select_for_update().filter(pk=user.pk).first()
                if not pending_matches(request, user) or not user.mfa_confirmed:
                    return restart_login(request)
                verified = verify(
                    user,
                    form.cleaned_data["code"],
                    expected_auth_version=request.session["pending_auth_version"],
                )
                if verified:
                    if finish_login(request, user, True):
                        return redirect("library")
                    transaction.set_rollback(True)
            if verified:
                return restart_login(request)
        record(user, "mfa", outcome="denied")
        form.add_error(None, "Unable to verify this code. Try again later if needed.")
    return render(request, "accounts/form.html", {"form": form, "title": "Verify your identity"})


@require_http_methods(["GET", "POST"])
def mfa_enroll(request):
    if not settings.MFA_ENABLED:
        return redirect("library" if request.user.is_authenticated else "login")
    if request.user.is_authenticated:
        return redirect("library")
    user = pending_user(request)
    if not user or user.mfa_confirmed:
        return restart_login(request)
    if "enrollment_secret" not in request.session:
        request.session["enrollment_secret"] = encrypt(pyotp.random_base32())
    secret = decrypt(request.session["enrollment_secret"])
    form = CodeForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        if allow_rate("mfa-enroll", str(user.pk), 10) and pyotp.TOTP(secret).verify(
            form.cleaned_data["code"]
        ):
            codes, hashes = create_recovery_codes()
            with transaction.atomic():
                user = User.objects.select_for_update().filter(pk=user.pk).first()
                if not pending_matches(request, user) or user.mfa_confirmed:
                    return restart_login(request)
                user.mfa_secret = encrypt(secret)
                user.mfa_confirmed = True
                user.mfa_last_step = int(time.time()) // 30
                user.recovery_hashes = hashes
                user.save(
                    update_fields=[
                        "mfa_secret",
                        "mfa_confirmed",
                        "mfa_last_step",
                        "recovery_hashes",
                    ]
                )
                if finish_login(request, user, True):
                    record(user, "mfa_enrolled")
                    return render(request, "accounts/recovery.html", {"codes": codes})
                transaction.set_rollback(True)
            return restart_login(request)
        form.add_error(None, "Unable to verify this code.")
    return render(
        request,
        "accounts/enroll.html",
        {
            "form": form,
            "secret": secret,
            "uri": pyotp.TOTP(secret).provisioning_uri(user.username, issuer_name="SSDC Vault"),
        },
    )


@login_required
@require_POST
def sign_out(request):
    record(request.user, "logout")
    logout(request)
    return redirect("login")


@login_required
@require_http_methods(["GET", "POST"])
def reauthenticate(request):
    form = ReauthenticateForm(request.POST or None)
    if not request.user.requires_authenticator:
        form.fields.pop("code")
    if request.method == "POST" and form.is_valid():
        allowed = allow_rate("reauth", str(request.user.pk), 10)
        if allowed:
            with transaction.atomic():
                user = locked_session_user(request)
                if not user:
                    record(request.user, "reauthentication", outcome="denied")
                    return restart_login(request)
                # Verify the current hash without a rehash that would change the
                # authorization version of the session being confirmed.
                password_ok = check_password(form.cleaned_data["password"], user.password)
                mfa_ok = password_ok and (
                    not user.requires_authenticator
                    or verify(
                        user,
                        form.cleaned_data["code"],
                        expected_auth_version=request.session["auth_version"],
                    )
                )
                if password_ok and mfa_ok:
                    request.session["reauth_at"] = time.time()
                    record(user, "reauthentication")
                    messages.success(
                        request, "Identity confirmed. You can continue your administrative action."
                    )
                    destination = request.GET.get("next", "")
                    if (
                        destination.startswith("/")
                        and not destination.startswith("//")
                        and "\\" not in destination
                        and not any(ord(character) < 32 for character in destination)
                    ):
                        return redirect(destination)
                    return redirect("library")
        record(request.user, "reauthentication", outcome="denied")
        form.add_error(None, "Unable to confirm your identity.")
    return render(request, "accounts/form.html", {"form": form, "title": "Confirm your identity"})


@login_required
@require_http_methods(["GET", "POST"])
def password_change(request):
    form = PasswordChangeForm(request.user, request.POST or None)
    if request.method == "POST":
        if not allow_rate("password-change", str(request.user.pk), 10):
            return render(
                request,
                "accounts/form.html",
                {"form": form, "title": "Try again later"},
                status=429,
            )
        with transaction.atomic():
            user = locked_session_user(request)
            if not user:
                record(request.user, "password_changed", outcome="denied")
                return restart_login(request)
            form = PasswordChangeForm(user, request.POST)
            if form.is_valid():
                user = form.save(commit=False)
                user.save(update_fields=["password"])
                update_session_auth_hash(request, user)
                request.session["auth_version"] = user.auth_version
                record(user, "password_changed")
                messages.success(request, "Password changed. Other sessions have been revoked.")
                return redirect("library")
    return render(request, "accounts/form.html", {"form": form, "title": "Change password"})
