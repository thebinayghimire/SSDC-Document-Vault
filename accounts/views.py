import time

import pyotp
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.db import transaction
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods, require_POST

from audit.services import allow_rate, record

from .forms import CodeForm, LoginForm, ReauthenticateForm
from .mfa import create_recovery_codes, decrypt, encrypt, verify
from .models import User


def finish_login(request, user, mfa_verified=False):
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    now = time.time()
    request.session.update(
        {
            "auth_version": user.auth_version,
            "auth_started": now,
            "last_seen": now,
            "reauth_at": now,
            "mfa_verified": mfa_verified,
        }
    )
    request.session.pop("pending_user", None)
    request.session.pop("pending_at", None)
    request.session.pop("enrollment_secret", None)
    record(user, "login")


@require_http_methods(["GET", "POST"])
def sign_in(request):
    if request.user.is_authenticated:
        return redirect("library")
    form = LoginForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        identity = form.cleaned_data["staff_id"]
        from django.conf import settings

        ip = (
            request.META.get("HTTP_X_REAL_IP")
            if settings.PRODUCTION
            else request.META.get("REMOTE_ADDR")
        )
        ip_ok = allow_rate("login-ip", ip or "unknown", 30)
        account_ok = allow_rate("login-account", identity, 10) if ip_ok else False
        if not ip_ok or not account_ok:
            record(None, "login", outcome="throttled")
            form.add_error(None, "Unable to sign in. Please try again later.")
        else:
            user = authenticate(request, username=identity, password=form.cleaned_data["password"])
            if user:
                if user.requires_mfa or user.mfa_confirmed:
                    request.session.flush()
                    request.session["pending_user"] = user.pk
                    request.session["pending_at"] = time.time()
                    request.session["pending_auth_version"] = user.auth_version
                    return redirect("mfa_challenge" if user.mfa_confirmed else "mfa_enroll")
                finish_login(request, user)
                return redirect("library")
            record(None, "login", outcome="denied")
            form.add_error(None, "Unable to sign in. Check your credentials.")
    return render(request, "accounts/login.html", {"form": form})


def pending_user(request):
    if time.time() - request.session.get("pending_at", 0) > 300:
        return None
    user = User.objects.filter(pk=request.session.get("pending_user"), is_active=True).first()
    if user and user.auth_version == request.session.get("pending_auth_version"):
        return user
    return None


@require_http_methods(["GET", "POST"])
def mfa_challenge(request):
    user = pending_user(request)
    if not user or not user.mfa_confirmed:
        return redirect("login")
    form = CodeForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        if allow_rate("mfa", str(user.pk), 10) and verify(user, form.cleaned_data["code"]):
            user.refresh_from_db()
            finish_login(request, user, True)
            return redirect("library")
        record(user, "mfa", outcome="denied")
        form.add_error(None, "Unable to verify this code. Try again later if needed.")
    return render(request, "accounts/form.html", {"form": form, "title": "Verify your identity"})


@require_http_methods(["GET", "POST"])
def mfa_enroll(request):
    user = pending_user(request)
    if not user or user.mfa_confirmed:
        return redirect("login")
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
                user = User.objects.select_for_update().get(pk=user.pk)
                if (
                    user.mfa_confirmed
                    or not user.is_active
                    or user.auth_version != request.session.get("pending_auth_version")
                ):
                    return redirect("login")
                user.mfa_secret = encrypt(secret)
                user.mfa_confirmed = True
                user.mfa_last_step = int(time.time()) // 30
                user.recovery_hashes = hashes
                user.save()
            finish_login(request, user, True)
            record(user, "mfa_enrolled")
            return render(request, "accounts/recovery.html", {"codes": codes})
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
    if request.method == "POST" and form.is_valid():
        allowed = allow_rate("reauth", str(request.user.pk), 10)
        password_ok = (
            request.user.check_password(form.cleaned_data["password"]) if allowed else False
        )
        mfa_ok = (
            (not request.user.mfa_confirmed or verify(request.user, form.cleaned_data["code"]))
            if password_ok
            else False
        )
        if password_ok and mfa_ok:
            request.session["reauth_at"] = time.time()
            record(request.user, "reauthentication")
            messages.success(
                request, "Identity confirmed. You can continue your administrative action."
            )
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
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            request.session["auth_version"] = user.auth_version
            record(user, "password_changed")
            messages.success(request, "Password changed. Other sessions have been revoked.")
            return redirect("library")
    return render(request, "accounts/form.html", {"form": form, "title": "Change password"})
