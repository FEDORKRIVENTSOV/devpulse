from datetime import timedelta

from django.conf import settings
from django.db.models import Avg, Count, Q
from django.utils import timezone
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from rest_framework import generics, permissions, viewsets
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from .models import Monitor
from .serializers import (
    CheckResultSerializer,
    IncidentSerializer,
    MonitorSerializer,
    RegisterSerializer,
)
from .services import check_monitor


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]
    authentication_classes = []


class LoginView(ObtainAuthToken):
    # The stock view has no throttling at all, which allows password brute force.
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"
    authentication_classes = []


class MonitorViewSet(viewsets.ModelViewSet):
    serializer_class = MonitorSerializer
    permission_classes = [permissions.IsAuthenticated]
    throttle_scope = None

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):  # API docs generation
            return Monitor.objects.none()
        # Data isolation: a user only ever sees their own monitors.
        queryset = Monitor.objects.filter(owner=self.request.user).order_by("id")
        if self.action == "list":
            params = self.request.query_params
            status = params.get("status")
            if status in Monitor.Status.values:
                queryset = queryset.filter(current_status=status)
            is_active = params.get("is_active")
            if is_active in ("true", "false"):
                queryset = queryset.filter(is_active=(is_active == "true"))
        return queryset

    def perform_create(self, serializer):
        limit = settings.MAX_MONITORS_PER_USER
        if Monitor.objects.filter(owner=self.request.user).count() >= limit:
            raise ValidationError({"detail": f"Monitor limit reached ({limit})."})
        serializer.save(owner=self.request.user)

    @action(detail=True, methods=["get"])
    def checks(self, request, pk=None):
        monitor = self.get_object()
        queryset = monitor.checks.all()
        is_success = request.query_params.get("is_success")
        if is_success in ("true", "false"):
            queryset = queryset.filter(is_success=(is_success == "true"))
        page = self.paginate_queryset(queryset)
        return self.get_paginated_response(CheckResultSerializer(page, many=True).data)

    @action(detail=True, methods=["get"])
    def incidents(self, request, pk=None):
        monitor = self.get_object()
        page = self.paginate_queryset(monitor.incidents.all())
        return self.get_paginated_response(IncidentSerializer(page, many=True).data)

    @extend_schema(request=None, responses=CheckResultSerializer)
    @action(
        detail=True,
        methods=["post"],
        url_path="check-now",
        throttle_classes=[ScopedRateThrottle],
        throttle_scope="check_now",
    )
    def check_now(self, request, pk=None):
        monitor = self.get_object()
        result = check_monitor(monitor)
        return Response(CheckResultSerializer(result).data)

    @extend_schema(responses=OpenApiTypes.OBJECT)
    @action(detail=True, methods=["get"])
    def stats(self, request, pk=None):
        monitor = self.get_object()
        try:
            days = int(request.query_params.get("days", 7))
        except ValueError:
            raise ValidationError({"days": "Must be an integer."})
        if not 1 <= days <= 90:
            raise ValidationError({"days": "Must be between 1 and 90."})

        since = timezone.now() - timedelta(days=days)
        aggregated = monitor.checks.filter(checked_at__gte=since).aggregate(
            total=Count("id"),
            successful=Count("id", filter=Q(is_success=True)),
            avg_response=Avg("response_time_ms"),
        )
        total = aggregated["total"]
        successful = aggregated["successful"]
        avg_response = aggregated["avg_response"]
        return Response(
            {
                "monitor": monitor.id,
                "period_days": days,
                "current_status": monitor.current_status,
                "total_checks": total,
                "successful_checks": successful,
                "uptime_percent": round(successful / total * 100, 2) if total else None,
                "avg_response_ms": round(avg_response, 1) if avg_response is not None else None,
                "incidents_count": monitor.incidents.filter(started_at__gte=since).count(),
            }
        )
