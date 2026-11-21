import logging
import time

import requests
from django.db import transaction

from . import notifications
from .models import CheckResult, Incident, Monitor
from .security import UnsafeURLError, safe_get

logger = logging.getLogger(__name__)

# A single failed check can be a network glitch. We confirm an outage only
# after this many failed checks in a row.
FAILURE_THRESHOLD = 2


def _perform_request(url):
    """Returns (status_code, is_success, error_message). Never raises."""
    try:
        response = safe_get(url, timeout=10)
    except UnsafeURLError as exc:
        return None, False, f"Blocked: {exc}"[:255]
    except requests.exceptions.Timeout:
        return None, False, "Timeout"
    except requests.exceptions.RequestException as exc:
        return None, False, (str(exc) or type(exc).__name__)[:255]

    status_code = response.status_code
    is_success = 200 <= status_code < 400
    return status_code, is_success, "" if is_success else f"HTTP {status_code}"


def _apply_result(monitor, result):
    """Updates monitor state and incidents. Returns ("opened"|"resolved", incident) or None."""
    monitor.last_checked_at = result.checked_at
    open_incident = monitor.incidents.filter(resolved_at__isnull=True).first()
    event = None

    if result.is_success:
        monitor.consecutive_failures = 0
        monitor.current_status = Monitor.Status.UP
        if open_incident:
            open_incident.resolved_at = result.checked_at
            open_incident.save(update_fields=["resolved_at"])
            event = ("resolved", open_incident)
    else:
        monitor.consecutive_failures += 1
        if monitor.consecutive_failures >= FAILURE_THRESHOLD:
            monitor.current_status = Monitor.Status.DOWN
            if open_incident is None:
                incident = Incident.objects.create(
                    monitor=monitor,
                    started_at=result.checked_at,
                    cause=result.error_message,
                )
                event = ("opened", incident)

    monitor.save(
        update_fields=["last_checked_at", "consecutive_failures", "current_status"]
    )
    return event


def check_monitor(monitor):
    start = time.monotonic()
    status_code, is_success, error_message = _perform_request(monitor.url)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    with transaction.atomic():
        # Lock the row so two parallel checks cannot create duplicate incidents.
        locked = Monitor.objects.select_for_update().get(pk=monitor.pk)
        result = CheckResult.objects.create(
            monitor=locked,
            status_code=status_code,
            response_time_ms=elapsed_ms,
            is_success=is_success,
            error_message=error_message,
        )
        event = _apply_result(locked, result)

    monitor.refresh_from_db()

    # Notify only AFTER the transaction is saved, and exactly once per event.
    if event:
        kind, incident = event
        try:
            if kind == "opened":
                notifications.notify_incident_opened(incident)
            else:
                notifications.notify_incident_resolved(incident)
        except Exception:
            logger.exception("Notification failed")
    return result
