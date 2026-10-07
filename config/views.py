from django.db import connection
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods


@require_http_methods(["GET", "HEAD"])
def health(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return JsonResponse({"status": "ok"})
    except Exception:
        return JsonResponse({"status": "unavailable"}, status=503)
