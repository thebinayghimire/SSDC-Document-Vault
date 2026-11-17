import math
import secrets
import time

import pyotp
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import Http404, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.translation import gettext as tr
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST

from audit.services import allow_rate, identity_reference, record

from .forms import (
    CodeForm,
    EmailChangeForm,
    EmailOtpForm,
    LoginForm,
    ReauthenticateForm,
    RegistrationForm,
    RegistrationResendForm,
)
from .mfa import create_recovery_codes, decrypt, encrypt, verify
from .models import StaffRegistrationRequest, User
from .navigation import portal_home, safe_portal_destination, safe_return_destination
from .services.email_changes import (
    EmailChangeConflict,
    EmailChangeDisabled,
    EmailChangeStateError,
    cancel_email_change,
    mask_email,
    pending_for_user,
    resend_email_change,
    start_email_change,
    verify_email_change,
)
from .services.email_claims import normalize_email, resolve
from .services.notifications import notify_admins_of_pending_review
from .services.otp import OtpCooldown, OtpRateLimited
from .services.registration import (
    RegistrationConflict,
    RegistrationDisabled,
    RegistrationInvalid,
    RegistrationStateError,
    register_applicant,
    resend_registration_for_email,
    verify_registration_otp,
)
from .services.registration_tokens import (
    consume_registration_token,
    registration_for_token,
)


def client_ip(request):
    if settings.PRODUCTION:
        return request.META.get("HTTP_X_REAL_IP") or "unknown"
    return request.META.get("REMOTE_ADDR") or "unknown"


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
                "portal_session": secrets.token_hex(16),
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
def sign_in(request, portal=None):
    if request.user.is_authenticated:
        if portal == "staff" and request.user.is_portal_admin:
            record(request.user, "logout")
            logout(request)
            messages.info(
                request,
                tr("You were signed out of the administrator account to access Staff sign in."),
            )
            redirect_url = reverse("staff_login")
            query = request.GET.urlencode()
            if query:
                redirect_url += f"?{query}"
            return redirect(redirect_url)
        if portal == "admin" and not request.user.is_portal_admin:
            record(request.user, "logout")
            logout(request)
            messages.info(
                request,
                tr("You were signed out of the staff account to access Admin sign in."),
            )
            redirect_url = reverse("admin_login")
            query = request.GET.urlencode()
            if query:
                redirect_url += f"?{query}"
            return redirect(redirect_url)
        return redirect(portal_home(request.user))
    form = LoginForm(request.POST or None)
    if portal == "admin":
        form.fields["staff_id"].label = tr("Admin ID")
    elif settings.EMAIL_LOGIN_ENABLED:
        form.fields["staff_id"].label = tr("Staff ID or email address")
        form.fields["staff_id"].help_text = tr(
            "Use your registered email address or your existing Staff ID."
        )
    if request.method == "POST" and form.is_valid():
        identity = form.cleaned_data["staff_id"].strip()
        email_identity = settings.EMAIL_LOGIN_ENABLED and "@" in identity
        if email_identity:
            try:
                rate_identity = normalize_email(identity)
            except ValidationError:
                rate_identity = identity.casefold()
        else:
            rate_identity = identity
        ip = client_ip(request)
        ip_ok = allow_rate("login-ip", ip, settings.LOGIN_IP_LIMIT)
        account_ok = (
            allow_rate("login-account", rate_identity, settings.LOGIN_ACCOUNT_LIMIT)
            if ip_ok
            else False
        )
        if not ip_ok or not account_ok:
            record(
                None,
                "login",
                outcome="throttled",
                details={"identity_hash": identity_reference(rate_identity)},
            )
            form.add_error(None, tr("Unable to sign in. Please try again later."))
        else:
            with transaction.atomic():
                lookup = identity
                if email_identity:
                    resolved = resolve(identity)
                    lookup = resolved.username if resolved else identity
                # Django can upgrade an older password hash during authenticate().
                # Lock before that check so its write cannot undo a concurrent reset.
                password_account = User.objects.select_for_update().filter(username=lookup).first()
                previous_hash = password_account.password if password_account else None
                user = authenticate(
                    request, username=lookup, password=form.cleaned_data["password"]
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
                    correct_portal = user and (
                        portal is None
                        or (portal == "admin" and user.is_portal_admin)
                        or (portal == "staff" and not user.is_portal_admin)
                    )
                    if correct_portal:
                        if user.requires_authenticator:
                            request.session.flush()
                            request.session["pending_user"] = user.pk
                            request.session["pending_at"] = time.time()
                            request.session["pending_auth_version"] = user.auth_version
                            request.session["login_destination"] = request.GET.get("next", "")
                            return redirect("mfa_challenge" if user.mfa_confirmed else "mfa_enroll")
                        if finish_login(request, user):
                            return redirect(
                                safe_portal_destination(request, request.GET.get("next"))
                            )
            record(
                None,
                "login",
                outcome="denied",
                details={"identity_hash": identity_reference(identity)},
            )
            form.add_error(None, tr("Unable to sign in. Check your credentials."))
    return render(request, "accounts/login.html", {"form": form, "portal": portal})


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
        return redirect(portal_home(request.user) if request.user.is_authenticated else "login")
    if request.user.is_authenticated:
        return redirect(portal_home(request.user))
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
                        return redirect(
                            safe_portal_destination(
                                request, request.session.pop("login_destination", None)
                            )
                        )
                    transaction.set_rollback(True)
            if verified:
                return restart_login(request)
        record(user, "mfa", outcome="denied")
        form.add_error(None, tr("Unable to verify this code. Try again later if needed."))
    return render(
        request, "accounts/form.html", {"form": form, "title": tr("Verify your identity")}
    )


@require_http_methods(["GET", "POST"])
def mfa_enroll(request):
    if not settings.MFA_ENABLED:
        return redirect(portal_home(request.user) if request.user.is_authenticated else "login")
    if request.user.is_authenticated:
        return redirect(portal_home(request.user))
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
                    return render(
                        request,
                        "accounts/recovery.html",
                        {
                            "codes": codes,
                            "continue_url": safe_portal_destination(
                                request, request.session.pop("login_destination", None)
                            ),
                        },
                    )
                transaction.set_rollback(True)
            return restart_login(request)
        form.add_error(None, tr("Unable to verify this code."))
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
    login_route = "admin_login" if request.user.is_portal_admin else "staff_login"
    record(request.user, "logout")
    logout(request)
    messages.success(request, tr("You’ve signed out. Sign in to access your portal."))
    return redirect(login_route)


@require_http_methods(["GET", "HEAD"])
def session_status(request):
    """Let restored pages and other tabs check their account against the live session."""
    # Mitigates session identifier disclosure in API responses while providing irreversible account-switch tags
    from .services.account_tag import compute_account_tag

    if not request.user.is_authenticated:
        return JsonResponse(
            {"authenticated": False, "account_tag": None, "home_url": "/accounts/login/"}
        )
    tag = compute_account_tag(request.user, request.session)
    return JsonResponse(
        {"authenticated": True, "account_tag": tag, "home_url": portal_home(request.user)}
    )


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
                        request,
                        tr("Identity confirmed. You can continue your administrative action."),
                    )
                    destination = safe_return_destination(request, request.GET.get("next"), "/")
                    return redirect(destination)
        record(request.user, "reauthentication", outcome="denied")
        form.add_error(None, tr("Unable to confirm your identity."))
    return render(
        request, "accounts/form.html", {"form": form, "title": tr("Confirm your identity")}
    )


@login_required
@require_http_methods(["GET", "POST"])
def password_change(request):
    form = PasswordChangeForm(request.user, request.POST or None)
    if request.method == "POST":
        if not allow_rate("password-change", str(request.user.pk), 10):
            return render(
                request,
                "accounts/form.html",
                {"form": form, "title": tr("Try again later")},
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
                messages.success(request, tr("Password changed. Other sessions have been revoked."))
                return redirect(portal_home(request.user))
    return render(request, "accounts/form.html", {"form": form, "title": tr("Change password")})


def secure_registration_headers(response, referrer_policy="same-origin"):
    # Mitigates token leakage via Referer header and caching of sensitive registration state (Step 2, Item 5)
    # Default to same-origin so browsers do not send opaque 'null' Origin headers on form submissions.
    response["Referrer-Policy"] = referrer_policy
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response["Pragma"] = "no-cache"
    return response


def generic_invalid_link_response(request, status=200):
    # Mitigates account enumeration and token validation oracles by rendering an identical generic response (Step 2, Item 3)
    response = render(request, "accounts/registration_link_invalid.html", status=status)
    return secure_registration_headers(response)


def registration_unavailable():
    raise Http404("Registration is not available.")


def _session_registration(request):
    registration_id = request.session.get("registration_request_id")
    if not registration_id:
        return None
    return (
        StaffRegistrationRequest.objects.select_related("user").filter(pk=registration_id).first()
    )


def _registration_for_email(email):
    try:
        normalized = normalize_email(email)
    except ValidationError:
        return None
    if not normalized:
        return None
    return (
        StaffRegistrationRequest.objects.select_related("user")
        .filter(applicant_email=normalized)
        .order_by("-created_at", "-pk")
        .first()
    )


def _registration_email(registration):
    if registration.applicant_email:
        return registration.applicant_email
    if registration.user_id and registration.user:
        return registration.user.email
    return ""


def _bind_registration_session(request, registration):
    request.session["registration_request_id"] = registration.pk
    request.session.modified = True


def _registration_payload(registration, *, token=None):
    email = _registration_email(registration)
    return {
        "registration": registration,
        "token": token,
        "raw_email": email,
        "masked_email": mask_email(email) if email else "",
        "expiry_minutes": settings.STAFF_REGISTRATION_OTP_MINUTES,
        "resend_form": RegistrationResendForm(initial={"email": email} if email else None),
        "registration_enabled": settings.STAFF_SELF_REGISTRATION_ENABLED,
    }


def _render_registration_submitted(
    request,
    *,
    email="",
    token=None,
    error="",
    resend_attempted=False,
    status=200,
):
    response = render(
        request,
        "accounts/registration_submitted.html",
        {
            "resend_form": RegistrationResendForm(initial={"email": email} if email else None),
            "resend_attempted": resend_attempted,
            "token": token,
            "error": error,
            "masked_email": mask_email(email) if email else "",
            "raw_email": email,
            "expiry_minutes": settings.STAFF_REGISTRATION_OTP_MINUTES,
        },
        status=status,
    )
    return secure_registration_headers(response)


def _render_registration_verify(request, registration, *, token=None, error=""):
    response = render(
        request,
        "accounts/registration_verify.html",
        {
            **_registration_payload(registration, token=token),
            "needs_otp": registration.status == StaffRegistrationRequest.Status.EMAIL_PENDING,
            "error": error,
        },
    )
    return secure_registration_headers(response, referrer_policy="no-referrer")


def _record_verify_denied():
    record(
        None,
        "staff_registration_verify_failed",
        outcome="denied",
        details={"object_type": "staff_registration_verify"},
    )


def _secure_redirect(url_name):
    return secure_registration_headers(redirect(url_name), referrer_policy="no-referrer")


@never_cache
@require_http_methods(["GET", "POST"])
def staff_register(request):
    if not settings.STAFF_SELF_REGISTRATION_ENABLED:
        registration_unavailable()
    form = RegistrationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        ip = client_ip(request)
        allowed = allow_rate(
            "staff-registration-ip",
            ip,
            settings.STAFF_REGISTRATION_IP_LIMIT,
            seconds=3600,
        )
        if allowed:
            allowed = allow_rate(
                "staff-registration-email",
                form.cleaned_data["email"],
                settings.STAFF_REGISTRATION_OTP_HOURLY_LIMIT,
                seconds=3600,
            )
        if not allowed:
            form.add_error(
                None,
                tr("Too many registration attempts. Please try again later."),
            )
            response = render(
                request,
                "accounts/register.html",
                {"form": form},
                status=429,
            )
            return secure_registration_headers(response)
        result = None
        raw_email = form.cleaned_data["email"]
        try:
            result = register_applicant(
                email=raw_email,
                password=form.cleaned_data["password1"],
                language=request.LANGUAGE_CODE,
                base_url=request.build_absolute_uri("/"),
            )
        except RegistrationInvalid as exc:
            form.add_error(None, exc.messages)
        except (RegistrationConflict, RegistrationStateError):
            # An address already on file must produce the same public response
            # as a brand-new application. A fresh verification message is sent
            # to the mailbox owner only; no token, status, or session is exposed.
            try:
                resend_registration_for_email(
                    raw_email,
                    base_url=request.build_absolute_uri("/"),
                )
            except (OtpCooldown, OtpRateLimited):
                pass
        except RegistrationDisabled:
            registration_unavailable()
        if not form.errors:
            if result and result.request:
                # The applicant proved control of this browser session by just
                # submitting the form. OTP proof is still required below.
                request.session["registration_request_id"] = result.request.pk
                request.session.modified = True
            return _render_registration_submitted(request, email=raw_email)
    response = render(request, "accounts/register.html", {"form": form})
    return secure_registration_headers(response)


@never_cache
@require_POST
def staff_register_resend_email(request):
    """Resend the appropriate message for the session's application.

    This endpoint never returns a link token and never binds a session.  The
    response is the same shape whether or not an application exists, so it
    cannot be used to confirm an address.
    """
    ip = client_ip(request)
    if not allow_rate(
        "staff-registration-resend-ip",
        ip,
        settings.STAFF_REGISTRATION_IP_LIMIT,
        seconds=3600,
    ):
        return _render_registration_submitted(
            request,
            email=request.POST.get("email", "").strip(),
            error=tr("Too many requests. Please try again later."),
            resend_attempted=True,
            status=429,
        )

    raw_email = request.POST.get("email", "").strip()
    if not raw_email or "*" in raw_email:
        registration = _session_registration(request)
        if registration is not None:
            raw_email = _registration_email(registration)

    if raw_email and "@" in raw_email and "*" not in raw_email:
        try:
            resend_registration_for_email(
                raw_email,
                base_url=request.build_absolute_uri("/"),
            )
        except (OtpCooldown, OtpRateLimited):
            # A cooldown must look exactly like a successful send.
            pass

    return _render_registration_submitted(
        request,
        email=raw_email,
        resend_attempted=True,
    )


@never_cache
@require_http_methods(["GET", "HEAD", "POST"])
def staff_register_verify(request, token=None):
    """Prefetch-safe email verification endpoint.

    GET is read-only.  A link token proves control of the mailbox but never
    marks an address verified.  Only a valid six-digit OTP moves an application
    into the review queue.  A token on a verified or decided application is
    consumed to bind the status page to a new server-side session.
    """
    ip = client_ip(request)
    if not allow_rate("staff-registration-verify-ip", ip, 60, seconds=3600):
        _record_verify_denied()
        return generic_invalid_link_response(request, status=429)

    if request.method in ("GET", "HEAD"):
        if not token:
            _record_verify_denied()
            return generic_invalid_link_response(request)
        registration = registration_for_token(token)
        if registration is None:
            _record_verify_denied()
            return generic_invalid_link_response(request)
        return _render_registration_verify(request, registration, token=token)

    posted_token = token or request.POST.get("token", "").strip() or None
    token_registration = registration_for_token(posted_token) if posted_token else None
    session_registration = _session_registration(request)
    email = request.POST.get("email", "").strip()
    code = request.POST.get("code", "").strip()

    # A stale or consumed token is rejected generically.  Falling back to an
    # address in the form would turn the link into a status oracle.
    if posted_token and token_registration is None:
        _record_verify_denied()
        return generic_invalid_link_response(request)

    if not code:
        if token_registration is not None:
            if token_registration.status == StaffRegistrationRequest.Status.EMAIL_PENDING:
                _bind_registration_session(request, token_registration)
                return _render_registration_verify(request, token_registration, token=posted_token)
            registration = consume_registration_token(posted_token)
            if registration is None:
                _record_verify_denied()
                return generic_invalid_link_response(request)
            _bind_registration_session(request, registration)
            record(
                None,
                "staff_registration_status_link_used",
                registration.user_id,
                outcome="success",
                details={
                    "object_type": "staff_registration",
                    "object_id": registration.pk,
                    "subject_id": registration.user_id,
                },
            )
            return _secure_redirect("staff_registration_status")
        if session_registration is not None:
            if session_registration.status == StaffRegistrationRequest.Status.EMAIL_PENDING:
                return _render_registration_verify(request, session_registration)
            return _secure_redirect("staff_registration_status")
        if email:
            # An address alone never authorizes status access.
            return _render_registration_submitted(request, email=email)
        _record_verify_denied()
        return generic_invalid_link_response(request)

    registration = token_registration or session_registration
    email_only = False
    if registration is None and email:
        candidate = _registration_for_email(email)
        if (
            candidate is not None
            and candidate.status == StaffRegistrationRequest.Status.EMAIL_PENDING
        ):
            registration = candidate
            email_only = True
    if registration is None:
        _record_verify_denied()
        return _render_registration_submitted(
            request,
            email=email,
            error=tr("That code is not valid. Check it and try again."),
        )

    if registration.status != StaffRegistrationRequest.Status.EMAIL_PENDING:
        if token_registration is not None:
            registration = consume_registration_token(posted_token)
            if registration is not None:
                _bind_registration_session(request, registration)
                return _secure_redirect("staff_registration_status")
        elif session_registration is not None:
            return _secure_redirect("staff_registration_status")
        _record_verify_denied()
        return _render_registration_submitted(
            request,
            email=email,
            error=tr("That code is not valid. Check it and try again."),
        )

    otp_result = verify_registration_otp(registration, code, ip=ip)
    if otp_result.status in {"verified", "already_verified"}:
        if posted_token and token_registration is not None:
            consume_registration_token(posted_token)
        registration.refresh_from_db()
        if registration.status == StaffRegistrationRequest.Status.PENDING_REVIEW:
            notify_admins_of_pending_review(
                registration,
                base_url=request.build_absolute_uri("/"),
            )
        record(
            None,
            "staff_registration_verify_succeeded",
            registration.user_id,
            outcome="success",
            details={
                "object_type": "staff_registration",
                "object_id": registration.pk,
                "subject_id": registration.user_id,
            },
        )
        _bind_registration_session(request, registration)
        messages.success(
            request,
            tr("Your email is verified. Your application is waiting for administrator approval."),
        )
        return _secure_redirect("staff_registration_status")

    if email_only:
        # The feedback must not distinguish a real address from an unknown one
        # or reveal whether an application is already decided.
        _record_verify_denied()
        return _render_registration_submitted(
            request,
            email=email,
            error=tr("That code is not valid. Check it and try again."),
        )

    err_msg = tr("That code is not valid. Check it and try again.")
    if otp_result.status == "locked":
        err_msg = tr("Too many incorrect codes. Request a new code to continue.")
    elif otp_result.status == "code_expired":
        err_msg = tr("That code has expired. Request a new code.")
    elif otp_result.status == "throttled":
        err_msg = tr("Too many attempts. Please try again later.")
    elif otp_result.status == "expired":
        err_msg = tr("This application has expired. Submit a new application.")
    messages.error(request, err_msg)
    return _render_registration_verify(
        request,
        registration,
        token=posted_token if token_registration is not None else None,
        error=err_msg,
    )


@never_cache
@require_http_methods(["GET", "HEAD", "POST"])
def staff_registration_status(request, token=None):
    """Display registration status from a server-side session, or email a link.

    The status page is never authorized by an email address or an application
    ID alone.  Cross-device access requires a single-use link sent to the
    mailbox on file.
    """
    if token:
        return generic_invalid_link_response(request)

    registration = _session_registration(request)
    if registration is not None:
        status = registration.status
        can_reapply = settings.STAFF_SELF_REGISTRATION_ENABLED and (
            status == StaffRegistrationRequest.Status.EXPIRED
            or (
                status == StaffRegistrationRequest.Status.DECLINED
                and registration.reapplication_allowed
            )
        )
        response = render(
            request,
            "accounts/registration_status.html",
            {
                **_registration_payload(registration),
                "status": status,
                "can_reapply": can_reapply,
            },
        )
        return secure_registration_headers(response, referrer_policy="no-referrer")

    submitted = False
    form = RegistrationResendForm(request.POST if request.method == "POST" else None)
    if request.method == "POST":
        ip = client_ip(request)
        if not allow_rate("staff-registration-status-ip", ip, 10, seconds=3600):
            response = render(
                request,
                "accounts/registration_status_lookup.html",
                {"form": form, "submitted": False},
                status=429,
            )
            return secure_registration_headers(response)
        if form.is_valid():
            try:
                resend_registration_for_email(
                    form.cleaned_data["email"],
                    base_url=request.build_absolute_uri("/"),
                )
            except (OtpCooldown, OtpRateLimited):
                pass
            submitted = True

    response = render(
        request,
        "accounts/registration_status_lookup.html",
        {"form": form, "submitted": submitted},
    )
    return secure_registration_headers(response)


@never_cache
@require_http_methods(["GET", "HEAD", "POST"])
def staff_register_resend(request, token=None):
    """Send a fresh message without revealing whether an application exists."""
    if token:
        return generic_invalid_link_response(request)

    ip = client_ip(request)
    form = RegistrationResendForm(request.POST if request.method == "POST" else None)
    submitted = False

    if request.method == "POST":
        if not allow_rate(
            "staff-registration-resend-ip",
            ip,
            settings.STAFF_REGISTRATION_IP_LIMIT,
            seconds=3600,
        ):
            response = render(
                request,
                "accounts/registration_resend.html",
                {"form": form, "submitted": False},
                status=429,
            )
            return secure_registration_headers(response)

        raw_email = form.cleaned_data["email"] if form.is_valid() else ""
        if not raw_email:
            registration = _session_registration(request)
            if registration is not None:
                raw_email = _registration_email(registration)

        if raw_email:
            try:
                resend_registration_for_email(
                    raw_email,
                    base_url=request.build_absolute_uri("/"),
                )
            except (OtpCooldown, OtpRateLimited):
                pass
            submitted = True

    prefilled_email = ""
    registration = _session_registration(request)
    if registration is not None and not submitted:
        prefilled_email = _registration_email(registration)

    response = render(
        request,
        "accounts/registration_resend.html",
        {"form": form, "submitted": submitted, "email": prefilled_email},
    )
    return secure_registration_headers(response)


@never_cache
@require_http_methods(["GET", "HEAD", "POST"])
def staff_registration_status_legacy(request, token):
    # Mitigates legacy signed token replay by rejecting all legacy signed URLs with generic page
    return generic_invalid_link_response(request)


@never_cache
@require_http_methods(["GET", "HEAD", "POST"])
def staff_register_resend_legacy(request, token):
    # Mitigates legacy signed token replay by rejecting all legacy signed URLs with generic page
    return generic_invalid_link_response(request)


@login_required
@never_cache
@require_http_methods(["GET", "POST"])
def email_change(request):
    if not (settings.EMAIL_LOGIN_ENABLED and settings.SELF_REGISTERED_EMAIL_CHANGE_ENABLED):
        registration_unavailable()
    pending = pending_for_user(request.user)
    start_form = EmailChangeForm()
    otp_form = EmailOtpForm()
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "start":
            if not allow_rate(
                "email-change-ip",
                client_ip(request),
                settings.STAFF_REGISTRATION_IP_LIMIT,
                seconds=3600,
            ):
                messages.error(request, tr("Too many requests. Please try again later."))
                return redirect("email_change")
            start_form = EmailChangeForm(request.POST)
            if start_form.is_valid():
                try:
                    start_email_change(
                        request.user,
                        start_form.cleaned_data["new_email"],
                        language=request.LANGUAGE_CODE,
                        base_url=request.build_absolute_uri("/"),
                    )
                except EmailChangeConflict as exc:
                    start_form.add_error("new_email", str(exc))
                except OtpRateLimited:
                    start_form.add_error(
                        None,
                        tr("Too many verification emails were requested."),
                    )
                except EmailChangeDisabled:
                    registration_unavailable()
                except EmailChangeStateError:
                    messages.error(request, tr("Your account cannot change email right now."))
                    return redirect("email_change")
                else:
                    messages.success(
                        request,
                        tr("A verification code was sent to the new address."),
                    )
                    return redirect("email_change")
            return render(
                request,
                "accounts/email_change.html",
                {
                    "start_form": start_form,
                    "otp_form": otp_form,
                    "pending": pending,
                    "masked_current": mask_email(request.user.email),
                    "masked_new": mask_email(pending.new_email) if pending else "",
                    "expiry_minutes": settings.EMAIL_CHANGE_OTP_MINUTES,
                },
                status=400,
            )
        if pending is None:
            messages.error(request, tr("There is no pending email change."))
            return redirect("email_change")
        if action == "verify":
            if not allow_rate(
                "email-change-verify",
                str(request.user.pk),
                20,
                seconds=3600,
            ):
                messages.error(request, tr("Too many attempts. Please try again later."))
                return redirect("email_change")
            otp_form = EmailOtpForm(request.POST)
            if otp_form.is_valid():
                result = verify_email_change(
                    request.user,
                    otp_form.cleaned_data["code"],
                    request_id=pending.pk,
                    base_url=request.build_absolute_uri("/"),
                )
                if result.status == "applied":
                    logout(request)
                    messages.success(
                        request,
                        tr("Your email address changed. Sign in again with the new address."),
                    )
                    return redirect("staff_login")
                if result.status in {"expired", "not_pending"}:
                    messages.error(request, tr("That email change is no longer pending."))
                    return redirect("email_change")
                if result.status == "locked":
                    otp_form.add_error(
                        None,
                        tr("Too many incorrect codes. Request a new code to continue."),
                    )
                elif result.status == "code_expired":
                    otp_form.add_error(None, tr("That code has expired. Request a new code."))
                elif result.status in {"stale", "conflict"}:
                    messages.error(
                        request,
                        tr("The email change could not be completed. Start again."),
                    )
                    return redirect("email_change")
                else:
                    otp_form.add_error(None, tr("That code is not valid. Check it and try again."))
            return render(
                request,
                "accounts/email_change.html",
                {
                    "start_form": start_form,
                    "otp_form": otp_form,
                    "pending": pending,
                    "masked_current": mask_email(request.user.email),
                    "masked_new": mask_email(pending.new_email),
                    "expiry_minutes": settings.EMAIL_CHANGE_OTP_MINUTES,
                },
                status=400,
            )
        if action == "resend":
            if not allow_rate(
                "email-change-resend",
                str(request.user.pk),
                settings.EMAIL_CHANGE_OTP_HOURLY_LIMIT,
                seconds=3600,
            ):
                messages.error(request, tr("Too many requests. Please try again later."))
                return redirect("email_change")
            try:
                result = resend_email_change(
                    request.user,
                    request_id=pending.pk,
                    base_url=request.build_absolute_uri("/"),
                )
            except OtpCooldown as exc:
                messages.error(
                    request,
                    tr("Please wait %(seconds)s seconds before requesting another code.")
                    % {"seconds": max(1, math.ceil(exc.retry_after))},
                )
            except OtpRateLimited:
                messages.error(request, tr("Too many verification emails were requested."))
            else:
                if result.status == "sent":
                    messages.success(request, tr("A new verification code has been sent."))
                elif result.status == "expired":
                    messages.error(request, tr("That email change has expired."))
                else:
                    messages.error(request, tr("There is no pending email change."))
            return redirect("email_change")
        if action == "cancel":
            if cancel_email_change(request.user, request_id=pending.pk):
                messages.success(request, tr("The pending email change was cancelled."))
            else:
                messages.error(request, tr("There is no pending email change."))
            return redirect("email_change")
        raise Http404("Unknown email change action.")
    return render(
        request,
        "accounts/email_change.html",
        {
            "start_form": start_form,
            "otp_form": otp_form,
            "pending": pending,
            "masked_current": mask_email(request.user.email),
            "masked_new": mask_email(pending.new_email) if pending else "",
            "expiry_minutes": settings.EMAIL_CHANGE_OTP_MINUTES,
        },
    )
