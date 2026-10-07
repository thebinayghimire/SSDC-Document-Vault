from django.urls import include, path

from .admin import site
from .views import health

urlpatterns = [
    path("health/", health, name="health"),
    path("accounts/", include("accounts.urls")),
    path("admin/", site.urls),
    path("", include("vault.urls")),
]
