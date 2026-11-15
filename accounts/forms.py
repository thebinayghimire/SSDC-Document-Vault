from django import forms
from django.utils.translation import gettext_lazy as _


class LoginForm(forms.Form):
    staff_id = forms.CharField(
        max_length=150,
        label=_("Staff ID"),
        widget=forms.TextInput(attrs={"autocomplete": "username", "autocapitalize": "none"}),
    )
    password = forms.CharField(
        label=_("Password"), widget=forms.PasswordInput(attrs={"autocomplete": "current-password"})
    )


class CodeForm(forms.Form):
    code = forms.CharField(
        max_length=64,
        label=_("Authenticator or recovery code"),
        widget=forms.TextInput(
            attrs={"autocomplete": "one-time-code", "autocapitalize": "none", "spellcheck": "false"}
        ),
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
