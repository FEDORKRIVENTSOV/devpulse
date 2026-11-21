from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Q


class Monitor(models.Model):
    class Status(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        UP = "up", "Up"
        DOWN = "down", "Down"

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="monitors",
    )
    name = models.CharField(max_length=100)
    url = models.URLField()
    interval_seconds = models.PositiveIntegerField(default=300)
    is_active = models.BooleanField(default=True)
    current_status = models.CharField(
        max_length=10, choices=Status.choices, default=Status.UNKNOWN
    )
    # Number of failed checks in a row. Reset to 0 by any successful check.
    consecutive_failures = models.PositiveIntegerField(default=0)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    # Numeric chat id (e.g. 123456789 or -100123...) or a channel like @mychannel.
    telegram_chat_id = models.CharField(
        max_length=64,
        blank=True,
        validators=[RegexValidator(r"^(-?\d+|@\w+)$", "Use a numeric chat id or @channel.")],
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.url})"


class CheckResult(models.Model):
    monitor = models.ForeignKey(
        Monitor, on_delete=models.CASCADE, related_name="checks"
    )
    checked_at = models.DateTimeField(auto_now_add=True)
    status_code = models.PositiveSmallIntegerField(null=True, blank=True)
    response_time_ms = models.PositiveIntegerField(null=True, blank=True)
    is_success = models.BooleanField()
    error_message = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-checked_at"]
        indexes = [models.Index(fields=["monitor", "-checked_at"])]

    def __str__(self):
        return f"{self.monitor.name} @ {self.checked_at:%Y-%m-%d %H:%M} -> {self.is_success}"


class Incident(models.Model):
    """A confirmed outage: from the moment it is confirmed until the site recovers."""

    monitor = models.ForeignKey(
        Monitor, on_delete=models.CASCADE, related_name="incidents"
    )
    started_at = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)
    cause = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-started_at"]
        constraints = [
            # The database itself guarantees: at most ONE open incident per monitor.
            models.UniqueConstraint(
                fields=["monitor"],
                condition=Q(resolved_at__isnull=True),
                name="unique_open_incident_per_monitor",
            )
        ]

    @property
    def is_open(self):
        return self.resolved_at is None

    def __str__(self):
        state = "open" if self.is_open else "resolved"
        return f"Incident of {self.monitor.name} ({state})"
