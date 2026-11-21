from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from .models import CheckResult, Incident, Monitor
from .security import UnsafeURLError, validate_url_syntax

User = get_user_model()


class MonitorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Monitor
        fields = [
            "id", "name", "url", "interval_seconds", "is_active",
            "current_status", "consecutive_failures", "last_checked_at",
            "telegram_chat_id", "created_at",
        ]
        # The server computes these; the client must never set them.
        read_only_fields = [
            "id", "current_status", "consecutive_failures",
            "last_checked_at", "created_at",
        ]
        extra_kwargs = {"interval_seconds": {"min_value": 60, "max_value": 86400}}

    def validate_url(self, value):
        try:
            validate_url_syntax(value)
        except UnsafeURLError as exc:
            raise serializers.ValidationError(str(exc))
        return value


class CheckResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = CheckResult
        fields = [
            "id", "checked_at", "status_code",
            "response_time_ms", "is_success", "error_message",
        ]


class IncidentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Incident
        fields = ["id", "started_at", "resolved_at", "cause", "is_open"]


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["id", "username", "email", "password"]

    def validate_password(self, value):
        validate_password(value)
        return value

    def create(self, validated_data):
        # create_user hashes the password; plain create() would store it as text.
        return User.objects.create_user(**validated_data)
