from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from audit.models import RateBucket
from audit.services import allow_rate


@pytest.mark.django_db
def test_shared_rate_bucket_and_cleanup():
    assert allow_rate("test", "identity", 2)
    assert allow_rate("test", "identity", 2)
    assert not allow_rate("test", "identity", 2)
    bucket = RateBucket.objects.get()
    assert "identity" not in bucket.key
    RateBucket.objects.filter(pk=bucket.pk).update(updated_at=timezone.now() - timedelta(days=2))
    call_command("clear_rates")
    assert not RateBucket.objects.exists()
