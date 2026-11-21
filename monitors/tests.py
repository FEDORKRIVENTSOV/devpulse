import socket
from datetime import timedelta
from unittest.mock import MagicMock, patch

import requests
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APITestCase

from .models import CheckResult, Incident, Monitor
from .security import UnsafeURLError, safe_get, validate_public_url, validate_url_syntax
from .services import check_monitor
from .tasks import check_monitor_task, run_due_checks

User = get_user_model()


def fake_response(status=200):
    return MagicMock(status_code=status)


def public_dns(host, port, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]


def private_dns(host, port, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]


# --------------------------------------------------------------------------
# API: access control and data isolation
# --------------------------------------------------------------------------
class MonitorAccessTests(APITestCase):
    def setUp(self):
        cache.clear()  # reset rate limits between tests
        self.alice = User.objects.create_user(username="alice", password="pass12345x")
        self.bob = User.objects.create_user(username="bob", password="pass12345x")
        self.alice_monitor = Monitor.objects.create(
            owner=self.alice, name="Alice site", url="https://example.com"
        )

    def test_anonymous_cannot_list_monitors(self):
        response = self.client.get("/api/monitors/")
        self.assertEqual(response.status_code, 401)

    def test_user_sees_only_own_monitors(self):
        self.client.force_authenticate(user=self.bob)
        response = self.client.get("/api/monitors/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 0)

    def test_owner_sees_own_monitor(self):
        self.client.force_authenticate(user=self.alice)
        response = self.client.get("/api/monitors/")
        self.assertEqual(response.data["count"], 1)

    def test_cannot_read_other_users_monitor(self):
        self.client.force_authenticate(user=self.bob)
        response = self.client.get(f"/api/monitors/{self.alice_monitor.id}/")
        self.assertEqual(response.status_code, 404)

    def test_cannot_update_other_users_monitor(self):
        self.client.force_authenticate(user=self.bob)
        response = self.client.patch(
            f"/api/monitors/{self.alice_monitor.id}/", {"name": "Hacked"}
        )
        self.assertEqual(response.status_code, 404)
        self.alice_monitor.refresh_from_db()
        self.assertEqual(self.alice_monitor.name, "Alice site")

    def test_cannot_delete_other_users_monitor(self):
        self.client.force_authenticate(user=self.bob)
        response = self.client.delete(f"/api/monitors/{self.alice_monitor.id}/")
        self.assertEqual(response.status_code, 404)
        self.assertTrue(Monitor.objects.filter(id=self.alice_monitor.id).exists())

    def test_cannot_see_other_users_checks_incidents_stats(self):
        self.client.force_authenticate(user=self.bob)
        for suffix in ("checks", "incidents", "stats"):
            response = self.client.get(f"/api/monitors/{self.alice_monitor.id}/{suffix}/")
            self.assertEqual(response.status_code, 404, suffix)

    def test_cannot_check_other_users_monitor(self):
        self.client.force_authenticate(user=self.bob)
        response = self.client.post(f"/api/monitors/{self.alice_monitor.id}/check-now/")
        self.assertEqual(response.status_code, 404)

    def test_owner_is_taken_from_request(self):
        self.client.force_authenticate(user=self.bob)
        response = self.client.post(
            "/api/monitors/",
            {"name": "Bob site", "url": "https://example.org", "owner": self.alice.id},
        )
        self.assertEqual(response.status_code, 201)
        monitor = Monitor.objects.get(id=response.data["id"])
        self.assertEqual(monitor.owner, self.bob)

    def test_client_cannot_set_server_fields(self):
        self.client.force_authenticate(user=self.alice)
        response = self.client.post(
            "/api/monitors/",
            {
                "name": "Fake",
                "url": "https://example.net",
                "current_status": "up",
                "consecutive_failures": 99,
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["current_status"], "unknown")
        self.assertEqual(response.data["consecutive_failures"], 0)


# --------------------------------------------------------------------------
# API: validation, limits, filters, endpoints
# --------------------------------------------------------------------------
class MonitorApiTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.alice = User.objects.create_user(username="alice", password="pass12345x")
        self.client.force_authenticate(user=self.alice)
        self.monitor = Monitor.objects.create(
            owner=self.alice, name="Site", url="https://example.com"
        )

    def test_rejects_localhost_url(self):
        response = self.client.post(
            "/api/monitors/", {"name": "Evil", "url": "http://localhost:8000/admin/"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("url", response.data)

    def test_rejects_cloud_metadata_url(self):
        response = self.client.post(
            "/api/monitors/",
            {"name": "Evil", "url": "http://169.254.169.254/latest/meta-data/"},
        )
        self.assertEqual(response.status_code, 400)

    def test_rejects_too_short_interval(self):
        response = self.client.post(
            "/api/monitors/",
            {"name": "Fast", "url": "https://example.org", "interval_seconds": 5},
        )
        self.assertEqual(response.status_code, 400)

    @override_settings(MAX_MONITORS_PER_USER=2)
    def test_monitor_limit_per_user(self):
        # setUp already created one monitor
        ok = self.client.post("/api/monitors/", {"name": "Two", "url": "https://example.org"})
        self.assertEqual(ok.status_code, 201)
        blocked = self.client.post("/api/monitors/", {"name": "Three", "url": "https://example.net"})
        self.assertEqual(blocked.status_code, 400)

    def test_filter_by_status(self):
        Monitor.objects.create(
            owner=self.alice, name="Down", url="https://down.example.com",
            current_status=Monitor.Status.DOWN,
        )
        response = self.client.get("/api/monitors/?status=down")
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["name"], "Down")

    @patch("monitors.services.safe_get", return_value=fake_response(200))
    def test_check_now(self, mock_get):
        response = self.client.post(f"/api/monitors/{self.monitor.id}/check-now/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["is_success"])
        self.monitor.refresh_from_db()
        self.assertEqual(self.monitor.current_status, Monitor.Status.UP)

    def test_checks_endpoint_is_paginated(self):
        for _ in range(3):
            CheckResult.objects.create(monitor=self.monitor, is_success=True, status_code=200)
        response = self.client.get(f"/api/monitors/{self.monitor.id}/checks/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 3)

    def test_incidents_endpoint(self):
        Incident.objects.create(
            monitor=self.monitor, started_at=timezone.now(), cause="HTTP 500"
        )
        response = self.client.get(f"/api/monitors/{self.monitor.id}/incidents/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertTrue(response.data["results"][0]["is_open"])

    def test_stats(self):
        for ms, ok in [(100, True), (200, True), (300, True), (400, False)]:
            CheckResult.objects.create(
                monitor=self.monitor, is_success=ok, response_time_ms=ms,
                status_code=200 if ok else 500,
            )
        response = self.client.get(f"/api/monitors/{self.monitor.id}/stats/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["total_checks"], 4)
        self.assertEqual(response.data["uptime_percent"], 75.0)
        self.assertEqual(response.data["avg_response_ms"], 250.0)

    def test_stats_without_checks(self):
        response = self.client.get(f"/api/monitors/{self.monitor.id}/stats/")
        self.assertIsNone(response.data["uptime_percent"])

    def test_stats_rejects_bad_days(self):
        for value in ("abc", "0", "1000"):
            response = self.client.get(f"/api/monitors/{self.monitor.id}/stats/?days={value}")
            self.assertEqual(response.status_code, 400, value)


# --------------------------------------------------------------------------
# Registration and tokens
# --------------------------------------------------------------------------
class AuthTests(APITestCase):
    def setUp(self):
        cache.clear()

    def test_register_hashes_password_and_hides_it(self):
        response = self.client.post(
            "/api/auth/register/", {"username": "carol", "password": "StrongPass123x"}
        )
        self.assertEqual(response.status_code, 201)
        self.assertNotIn("password", response.data)
        user = User.objects.get(username="carol")
        self.assertNotEqual(user.password, "StrongPass123x")
        self.assertTrue(user.check_password("StrongPass123x"))

    def test_register_rejects_weak_password(self):
        response = self.client.post(
            "/api/auth/register/", {"username": "dave", "password": "12345678"}
        )
        self.assertEqual(response.status_code, 400)

    def test_token_login_and_use(self):
        User.objects.create_user(username="erin", password="StrongPass123x")
        response = self.client.post(
            "/api/auth/token/", {"username": "erin", "password": "StrongPass123x"}
        )
        self.assertEqual(response.status_code, 200)
        token = response.data["token"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        self.assertEqual(self.client.get("/api/monitors/").status_code, 200)

    def test_wrong_password_rejected(self):
        User.objects.create_user(username="erin", password="StrongPass123x")
        response = self.client.post(
            "/api/auth/token/", {"username": "erin", "password": "wrong"}
        )
        self.assertEqual(response.status_code, 400)


# --------------------------------------------------------------------------
# Core business logic: "two failures in a row = incident"
# --------------------------------------------------------------------------
class IncidentLogicTests(TestCase):
    def setUp(self):
        user = User.objects.create_user(username="alice", password="pass12345x")
        self.monitor = Monitor.objects.create(
            owner=user, name="Site", url="https://example.com"
        )

    @patch("monitors.notifications.notify_incident_opened")
    @patch("monitors.services.safe_get", side_effect=requests.exceptions.ConnectionError("boom"))
    def test_first_failure_is_recorded_but_no_incident(self, mock_get, mock_notify):
        result = check_monitor(self.monitor)
        self.assertFalse(result.is_success)
        self.assertEqual(CheckResult.objects.count(), 1)
        self.assertEqual(Incident.objects.count(), 0)
        self.monitor.refresh_from_db()
        self.assertEqual(self.monitor.consecutive_failures, 1)
        self.assertEqual(self.monitor.current_status, Monitor.Status.UNKNOWN)
        mock_notify.assert_not_called()

    @patch("monitors.notifications.notify_incident_opened")
    @patch("monitors.services.safe_get", return_value=fake_response(500))
    def test_second_failure_opens_incident_and_notifies_once(self, mock_get, mock_notify):
        check_monitor(self.monitor)
        check_monitor(self.monitor)
        self.assertEqual(Incident.objects.count(), 1)
        incident = Incident.objects.get()
        self.assertTrue(incident.is_open)
        self.assertEqual(incident.cause, "HTTP 500")
        self.monitor.refresh_from_db()
        self.assertEqual(self.monitor.current_status, Monitor.Status.DOWN)
        mock_notify.assert_called_once()

    @patch("monitors.notifications.notify_incident_opened")
    @patch("monitors.services.safe_get", return_value=fake_response(503))
    def test_more_failures_do_not_duplicate_incident_or_notification(self, mock_get, mock_notify):
        for _ in range(5):
            check_monitor(self.monitor)
        self.assertEqual(Incident.objects.count(), 1)
        mock_notify.assert_called_once()

    @patch("monitors.notifications.notify_incident_resolved")
    @patch("monitors.notifications.notify_incident_opened")
    @patch(
        "monitors.services.safe_get",
        side_effect=[
            requests.exceptions.ConnectionError("down"),
            requests.exceptions.ConnectionError("down"),
            fake_response(200),
        ],
    )
    def test_recovery_closes_incident(self, mock_get, mock_opened, mock_resolved):
        check_monitor(self.monitor)
        check_monitor(self.monitor)
        check_monitor(self.monitor)
        incident = Incident.objects.get()
        self.assertFalse(incident.is_open)
        self.monitor.refresh_from_db()
        self.assertEqual(self.monitor.current_status, Monitor.Status.UP)
        self.assertEqual(self.monitor.consecutive_failures, 0)
        mock_opened.assert_called_once()
        mock_resolved.assert_called_once()

    @patch("monitors.services.safe_get", side_effect=[
        requests.exceptions.ConnectionError("glitch"),
        fake_response(200),
    ])
    def test_single_glitch_never_creates_incident(self, mock_get):
        check_monitor(self.monitor)
        check_monitor(self.monitor)
        self.assertEqual(Incident.objects.count(), 0)
        self.monitor.refresh_from_db()
        self.assertEqual(self.monitor.consecutive_failures, 0)

    @patch("monitors.services.safe_get", side_effect=requests.exceptions.Timeout())
    def test_timeout_is_recorded(self, mock_get):
        result = check_monitor(self.monitor)
        self.assertEqual(result.error_message, "Timeout")
        self.assertIsNone(result.status_code)

    @patch("monitors.services.safe_get", side_effect=UnsafeURLError("private address"))
    def test_blocked_url_is_a_failed_check(self, mock_get):
        result = check_monitor(self.monitor)
        self.assertFalse(result.is_success)
        self.assertTrue(result.error_message.startswith("Blocked"))

    @patch("monitors.notifications.notify_incident_opened", side_effect=RuntimeError("tg down"))
    @patch("monitors.services.safe_get", return_value=fake_response(500))
    def test_notification_failure_does_not_break_check(self, mock_get, mock_notify):
        check_monitor(self.monitor)
        check_monitor(self.monitor)
        self.assertEqual(Incident.objects.count(), 1)


# --------------------------------------------------------------------------
# SSRF protection
# --------------------------------------------------------------------------
class SecurityTests(SimpleTestCase):
    def test_syntax_blocks_dangerous_urls(self):
        bad = [
            "ftp://example.com",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "http://localhost/",
            "http://app.localhost/",
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://user:pass@example.com/",
        ]
        for url in bad:
            with self.subTest(url=url):
                with self.assertRaises(UnsafeURLError):
                    validate_url_syntax(url)

    def test_syntax_allows_normal_urls(self):
        for url in ("https://example.com", "http://example.org/path?q=1", "https://8.8.8.8/"):
            with self.subTest(url=url):
                validate_url_syntax(url)

    @patch("monitors.security.socket.getaddrinfo", side_effect=private_dns)
    def test_domain_resolving_to_private_ip_is_blocked(self, mock_dns):
        with self.assertRaises(UnsafeURLError):
            validate_public_url("https://sneaky.example.com")

    @patch("monitors.security.socket.getaddrinfo", side_effect=public_dns)
    def test_domain_resolving_to_public_ip_is_allowed(self, mock_dns):
        validate_public_url("https://example.com")

    @patch("monitors.security.socket.getaddrinfo", side_effect=socket.gaierror)
    def test_unresolvable_domain_is_rejected(self, mock_dns):
        with self.assertRaises(UnsafeURLError):
            validate_public_url("https://no-such-host.example")

    @patch("monitors.security.requests.get")
    @patch("monitors.security.socket.getaddrinfo", side_effect=public_dns)
    def test_redirect_to_internal_address_is_blocked(self, mock_dns, mock_get):
        mock_get.return_value = MagicMock(
            status_code=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
        )
        with self.assertRaises(UnsafeURLError):
            safe_get("https://example.com")
        self.assertEqual(mock_get.call_count, 1)  # the internal address was never requested

    @patch("monitors.security.requests.get")
    @patch("monitors.security.socket.getaddrinfo", side_effect=public_dns)
    def test_safe_redirect_is_followed(self, mock_dns, mock_get):
        mock_get.side_effect = [
            MagicMock(status_code=301, headers={"Location": "/new"}),
            MagicMock(status_code=200, headers={}),
        ]
        response = safe_get("https://example.com/old")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_get.call_args.args[0], "https://example.com/new")

    @patch("monitors.security.requests.get")
    @patch("monitors.security.socket.getaddrinfo", side_effect=public_dns)
    def test_redirect_loop_is_stopped(self, mock_dns, mock_get):
        mock_get.return_value = MagicMock(
            status_code=302, headers={"Location": "https://example.com/loop"}
        )
        with self.assertRaises(requests.exceptions.TooManyRedirects):
            safe_get("https://example.com")


# --------------------------------------------------------------------------
# Background tasks
# --------------------------------------------------------------------------
class TaskTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username="alice", password="pass12345x")

    def make(self, **kwargs):
        defaults = {"owner": self.user, "name": "S", "url": "https://example.com"}
        defaults.update(kwargs)
        return Monitor.objects.create(**defaults)

    @patch("monitors.tasks.check_monitor_task.delay")
    def test_run_due_checks_queues_only_due_active_monitors(self, mock_delay):
        never_checked = self.make(name="never")
        self.make(name="fresh", last_checked_at=timezone.now())
        overdue = self.make(
            name="overdue", interval_seconds=60,
            last_checked_at=timezone.now() - timedelta(seconds=120),
        )
        self.make(name="inactive", is_active=False)

        queued = run_due_checks()

        self.assertEqual(queued, 2)
        queued_ids = {call.args[0] for call in mock_delay.call_args_list}
        self.assertEqual(queued_ids, {never_checked.id, overdue.id})

    @patch("monitors.tasks.check_monitor")
    def test_check_task_runs_check(self, mock_check):
        monitor = self.make()
        self.assertEqual(check_monitor_task(monitor.id), "checked")
        mock_check.assert_called_once()

    @patch("monitors.tasks.check_monitor")
    def test_check_task_skips_inactive_monitor(self, mock_check):
        monitor = self.make(is_active=False)
        self.assertEqual(check_monitor_task(monitor.id), "missing")
        mock_check.assert_not_called()

    @patch("monitors.tasks.check_monitor")
    def test_check_task_respects_lock(self, mock_check):
        monitor = self.make()
        cache.add(f"monitor-check-lock:{monitor.id}", "1", timeout=60)
        self.assertEqual(check_monitor_task(monitor.id), "locked")
        mock_check.assert_not_called()
