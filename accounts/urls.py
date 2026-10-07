from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.sign_in, name="login"),
    path("logout/", views.sign_out, name="logout"),
    path("mfa/", views.mfa_challenge, name="mfa_challenge"),
    path("mfa/enroll/", views.mfa_enroll, name="mfa_enroll"),
    path("confirm/", views.reauthenticate, name="reauthenticate"),
    path("password/", views.password_change, name="password_change"),
]
