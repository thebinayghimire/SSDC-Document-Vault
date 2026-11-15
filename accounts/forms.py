from django import forms
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _

from .services.email_claims import normalize_email


class LoginForm(forms.Form):
    staff_id = forms.CharField(
        max_length=150,
        label=_("Staff ID"),
        widget=forms.TextInput(attrs={"autocomplete": "username", "autocapitalize": "none"}),
    )
    password = forms.CharField(
        label=_("Password"), widget=forms.PasswordInput(attrs={"autocomplete": "current-password"})
    )


class RegistrationForm(forms.Form):
    email = forms.EmailField(
        max_length=254,
        label=_("Email address"),
        widget=forms.EmailInput(
            attrs={"autocomplete": "email", "autocapitalize": "none", "spellcheck": "false"}
        ),
    )
    password1 = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )
    password2 = forms.CharField(
        label=_("Confirm password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )

    def clean_email(self):
        try:
            return normalize_email(self.cleaned_data.get("email", ""))
        except ValidationError as exc:
            raise forms.ValidationError(exc.messages) from exc

    def clean(self):
        cleaned = super().clean()
        password1 = cleaned.get("password1")
        password2 = cleaned.get("password2")
        if password1 and password2 and password1 != password2:
            self.add_error("password2", _("The two passwords do not match."))
        elif password1:
            try:
                validate_password(password1)
            except ValidationError as exc:
                self.add_error("password1", exc)
        return cleaned


class RegistrationResendForm(forms.Form):
    email = forms.EmailField(
        max_length=254,
        label=_("Email address"),
        widget=forms.EmailInput(attrs={"autocomplete": "email", "autocapitalize": "none"}),
    )

    def clean_email(self):
        try:
            return normalize_email(self.cleaned_data.get("email", ""))
        except ValidationError as exc:
            raise forms.ValidationError(exc.messages) from exc


class CodeForm(forms.Form):
    code = forms.CharField(
        max_length=64,
        label=_("Authenticator or recovery code"),
        widget=forms.TextInput(
            attrs={"autocomplete": "one-time-code", "autocapitalize": "none", "spellcheck": "false"}
        ),
    )


class EmailOtpForm(forms.Form):
    code = forms.CharField(
        min_length=6,
        max_length=6,
        label=_("Six-digit code"),
        validators=[RegexValidator(r"^\d{6}$", _("Enter the six-digit code."))],
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "pattern": "[0-9]{6}",
                "autocapitalize": "none",
                "spellcheck": "false",
            }
        ),
    )


class EmailChangeForm(forms.Form):
    new_email = forms.EmailField(
        max_length=254,
        label=_("New email address"),
        widget=forms.EmailInput(
            attrs={"autocomplete": "email", "autocapitalize": "none", "spellcheck": "false"}
        ),
    )

    def clean_new_email(self):
        try:
            return normalize_email(self.cleaned_data.get("new_email", ""))
        except ValidationError as exc:
            raise forms.ValidationError(exc.messages) from exc


class RegistrationDecisionForm(forms.Form):
    note = forms.CharField(
        required=False,
        max_length=2000,
        label=_("Review note"),
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    allow_reapplication = forms.BooleanField(
        required=False,
        label=_("Allow this applicant to reapply"),
    )


class ReauthenticateForm(forms.Form):
    password = forms.CharField(
        label=_("Password"), widget=forms.PasswordInput(attrs={"autocomplete": "current-password"})
    )
    code = forms.CharField(
        max_length=64,
        required=False,
        label=_("MFA code (if enabled)"),
        widget=forms.TextInput(attrs={"autocomplete": "one-time-code", "autocapitalize": "none"}),
    )
