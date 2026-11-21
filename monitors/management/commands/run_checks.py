from django.core.management.base import BaseCommand

from monitors.models import Monitor
from monitors.services import check_monitor


class Command(BaseCommand):
    help = "Check all active monitors once (no Celery needed). Useful for debugging."

    def add_arguments(self, parser):
        parser.add_argument("--monitor-id", type=int, help="Check only this monitor")

    def handle(self, *args, **options):
        monitors = Monitor.objects.filter(is_active=True)
        if options["monitor_id"]:
            monitors = monitors.filter(pk=options["monitor_id"])
        for monitor in monitors:
            result = check_monitor(monitor)
            self.stdout.write(
                f"{monitor.name}: success={result.is_success} "
                f"status={result.status_code} {result.error_message}"
            )
