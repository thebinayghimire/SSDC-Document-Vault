from django import forms


class LoginForm(forms.Form):
    staff_id = forms.CharField(
        max_length=150,
        label="Staff ID",
        widget=forms.TextInput(attrs={"autocomplete": "username", "autocapitalize": "none"}),
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"})
    )


class CodeForm(forms.Form):
    code = forms.CharField(
        max_length=64,
        label="Authenticator or recovery code",
        widget=forms.TextInput(
            attrs={"autocomplete": "one-time-code", "autocapitalize": "none", "spellcheck": "false"}
        ),
    )


class ReauthenticateForm(forms.Form):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"})
    )
    code = forms.CharField(
        max_length=64,
        required=False,
        label="MFA code (if enabled)",
        widget=forms.TextInput(attrs={"autocomplete": "one-time-code", "autocapitalize": "none"}),
    )
