from django.urls import include, path

from .admin import site
from .views import health, live, privacy, terms

urlpatterns = [
    path("health/", health, name="health"),
    path("live/", live, name="live"),
    path("privacy/", privacy, name="privacy"),
    path("terms/", terms, name="terms"),
    path("accounts/", include("accounts.urls")),
    path("admin/", site.urls),
    path("", include("vault.urls")),
]
