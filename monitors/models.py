from django.conf import settings
from django.db import models

class Monitor(models.Model):
    class Status(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        UP = "up", "Up"
        DOWN = "down", "Down"

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='monitors',)

    name = models.CharField(max_length=100)
    url = models.URLField()
    interval_seconds = models.PositiveIntegerField(default=300)
    is_active = models.BooleanField(default=True)
    current_status = models.CharField(choices=Status.choices, max_length=10, default=Status.UNKNOWN)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.url})"

class CheckResult(models.Model):
        monitor = models.ForeignKey(Monitor, on_delete=models.CASCADE, related_name='checks',)
        checked_at = models.DateTimeField(auto_now_add=True)
        status_code = models.PositiveSmallIntegerField(null=True, blank=True)
        response_time_ms = models.PositiveIntegerField(null=True, blank=True)
        is_success = models.BooleanField()
        error_message = models.CharField(max_length=255, blank=True, null=True)

        class Meta:
            ordering = ['checked_at']
            indexes = [
                models.Index(fields=['monitor', '-checked_at']),
            ]

        def __str__(self):
            return f"{self.monitor.name} @ {self.checked_at:%Y-%m-%d %H:%M} -> {self.is_success}"
# Create your models here.
