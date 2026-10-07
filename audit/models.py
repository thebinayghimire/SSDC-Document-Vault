from django.conf import settings
from django.db import models
from django.utils import timezone


class Event(models.Model):
    at = models.DateTimeField(auto_now_add=True, db_index=True)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    kind = models.CharField(max_length=64, db_index=True)
    target = models.CharField(max_length=64, blank=True)
    outcome = models.CharField(max_length=24, default="success")

    class Meta:
        ordering = ["-at"]


class RateBucket(models.Model):
    key = models.CharField(max_length=64, primary_key=True)
    window = models.BigIntegerField()
    count = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(default=timezone.now, db_index=True)
