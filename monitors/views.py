from django.shortcuts import render
from rest_framework import viewsets, permissions
from rest_framework.response import Response
from rest_framework.decorators import action

from .models import Monitor
from .serializers import CheckResultSerializer, MonitorSerializer
from .services import check_monitor

from rest_framework import generics
from .serializers import RegisterSerializer

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

class MonitorViewSet(viewsets.ModelViewSet):
    serializer_class = MonitorSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Monitor.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    @action(detail=True, methods=['get'])
    def checks(self, request, pk=None):
        monitor = self.get_object()
        serializer = CheckResultSerializer(monitor.checks.all()[:50], many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='check-now')
    def check_now(self, request, pk=None):
        monitor = self.get_object()
        result = check_monitor(monitor)
        return Response(CheckResultSerializer(result).data)


# Create your views here.
