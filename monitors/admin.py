from django.contrib import admin

from .models import CheckResult, Incident, Monitor


@admin.register(Monitor)
class MonitorAdmin(admin.ModelAdmin):
    list_display = ("name", "url", "owner", "current_status", "is_active", "last_checked_at")
    list_filter = ("current_status", "is_active")
    search_fields = ("name", "url", "owner__username")


@admin.register(CheckResult)
class CheckResultAdmin(admin.ModelAdmin):
    list_display = ("monitor", "checked_at", "is_success", "status_code", "response_time_ms")
    list_filter = ("is_success",)
    list_select_related = ("monitor",)


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("monitor", "started_at", "resolved_at", "cause")
    list_select_related = ("monitor",)
