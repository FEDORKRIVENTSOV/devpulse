from datetime import timedelta

from celery import shared_task
from django.core.cache import cache
from django.utils import timezone

from .models import Monitor
from .services import check_monitor

LOCK_SECONDS = 120


@shared_task
def check_monitor_task(monitor_id):
    # Lock: if this monitor is already being checked, skip (avoids double counting failures).
    lock_key = f"monitor-check-lock:{monitor_id}"
    if not cache.add(lock_key, "1", timeout=LOCK_SECONDS):
        return "locked"
    try:
        try:
            monitor = Monitor.objects.get(pk=monitor_id, is_active=True)
        except Monitor.DoesNotExist:
            return "missing"
        check_monitor(monitor)
        return "checked"
    finally:
        cache.delete(lock_key)


@shared_task
def run_due_checks():
    """Runs every 30 s via Celery Beat. Queues checks for monitors whose interval has passed."""
    now = timezone.now()
    queued = 0
    for monitor in Monitor.objects.filter(is_active=True).only(
        "id", "interval_seconds", "last_checked_at"
    ):
        due = (
            monitor.last_checked_at is None
            or monitor.last_checked_at + timedelta(seconds=monitor.interval_seconds) <= now
        )
        if due:
            check_monitor_task.delay(monitor.id)
            queued += 1
    return queued
