from django.urls import include, path
from django.views.i18n import JavaScriptCatalog

from .admin import site
from .views import health, live, privacy, terms

urlpatterns = [
    path("jsi18n/", JavaScriptCatalog.as_view(domain="django"), name="javascript-catalog"),
    path("i18n/", include("django.conf.urls.i18n")),
    path("health/", health, name="health"),
    path("live/", live, name="live"),
    path("privacy/", privacy, name="privacy"),
    path("terms/", terms, name="terms"),
    path("accounts/", include("accounts.urls")),
    path("admin/", site.urls),
    path("", include("vault.urls")),
]
