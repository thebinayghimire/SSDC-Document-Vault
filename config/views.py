import logging

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from .readiness import readiness_failures


@require_http_methods(["GET", "HEAD"])
def privacy(request):
    return render(request, "privacy.html")


@require_http_methods(["GET", "HEAD"])
def terms(request):
    return render(request, "terms.html")


@require_http_methods(["GET", "HEAD"])
def health(request):
    failures = readiness_failures()
    for failure in failures:
        logging.getLogger(__name__).error("Readiness unavailable", extra={"event_code": failure})
    return JsonResponse(
        {"status": "unavailable" if failures else "ok"}, status=503 if failures else 200
    )


@require_http_methods(["GET", "HEAD"])
def live(request):
    return JsonResponse({"status": "alive"})
