"""Garbage-collect expired / delivered ciphertext (architecture §5).

Run periodically (cron / celery beat). Mirrors mesh relay GC: drop events past
TTL or already delivered, and expired coordination deltas. Storing ciphertext
longer than necessary is a liability, so retention is short by design.
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from apps.sync.models import Event, BlobFragment, Receipt
from apps.coordination.models import CoordDelta
from apps.common.models import Challenge


class Command(BaseCommand):
    help = "Delete expired/delivered ciphertext and stale auth challenges."

    def handle(self, *args, **opts):
        now = timezone.now()
        counts = {
            "events_expired": Event.objects.filter(ttl_expires_at__lte=now).delete()[0],
            "events_delivered": Event.objects.filter(delivered=True).delete()[0],
            "fragments": BlobFragment.objects.filter(ttl_expires_at__lte=now).delete()[0],
            "receipts": Receipt.objects.filter(ttl_expires_at__lte=now).delete()[0],
            "coord": CoordDelta.objects.filter(expires_at__lte=now).delete()[0],
            "challenges": Challenge.objects.filter(consumed=True).delete()[0],
        }
        self.stdout.write(self.style.SUCCESS(f"GC complete: {counts}"))
