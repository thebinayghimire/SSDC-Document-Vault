from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.sign_in, name="login"),
    path("admin/login/", views.sign_in, {"portal": "admin"}, name="admin_login"),
    path("staff/login/", views.sign_in, {"portal": "staff"}, name="staff_login"),
    path("session/", views.session_status, name="session_status"),
    path("logout/", views.sign_out, name="logout"),
    path("mfa/", views.mfa_challenge, name="mfa_challenge"),
    path("mfa/enroll/", views.mfa_enroll, name="mfa_enroll"),
    path("confirm/", views.reauthenticate, name="reauthenticate"),
    path("password/", views.password_change, name="password_change"),
    path("register/", views.staff_register, name="staff_register"),
    path(
        "register/resend/",
        views.staff_register_resend_email,
        name="staff_register_resend_email",
    ),
    path(
        "register/verify/<str:token>/",
        views.staff_register_verify,
        name="staff_register_verify",
    ),
    path(
        "register/resend/<str:token>/",
        views.staff_register_resend,
        name="staff_register_resend",
    ),
    path(
        "register/status/<str:token>/",
        views.staff_registration_status,
        name="staff_registration_status",
    ),
    path("email/change/", views.email_change, name="email_change"),
]
