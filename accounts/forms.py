from django import forms


class LoginForm(forms.Form):
    staff_id = forms.CharField(max_length=150, label="Staff ID")
    password = forms.CharField(widget=forms.PasswordInput)


class CodeForm(forms.Form):
    code = forms.CharField(max_length=64, label="Authenticator or recovery code")


class ReauthenticateForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput)
    code = forms.CharField(max_length=64, required=False, label="MFA code (if enabled)")
