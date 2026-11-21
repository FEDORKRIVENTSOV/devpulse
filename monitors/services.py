import time
import requests
from .models import CheckResult, Monitor

def check_monitor(monitor):
    status_code= None
    error_message = ""
    start = time.monotonic()

    try:
        response = requests.get(monitor.url, timeout=10, allow_redirects=False)
        status_code = response.status_code
        is_success = 200 <= status_code < 400
        if not is_success:
            error_message = f"HTTP {status_code}"
    except requests.exceptions.Timeout:
        is_success = False
        error_message = "Timeout"
    except requests.exceptions.RequestException as exc:
        is_success = False
        error_message = str(exc)[:255]

    elapsed_ms = int((time.monotonic() - start) * 1000)

    result = CheckResult.objects.create(monitor=monitor, status_code=status_code, response_time_ms=elapsed_ms, is_success=is_success, error_message=error_message)

    monitor.current_status = Monitor.Status.UP if is_success else Monitor.Status.DOWN
    monitor.save(update_fields=['current_status'])
    return result
