from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

from .models import Monitor

User = get_user_model()

class MonitorAccessTests(APITestCase):
    def setUp(self):
        self.alice = User.objects.create_user(username='alice', password='pass12345x')
        self.bob = User.objects.create_user(username="bob", password="pass12345x")
        self.alice_monitor = Monitor.objects.create(owner=self.alice, name='Alice site', url='http://example.com')

    def test_anonymous_cannot_list_monitors(self):
        response = self.client.get('/api/monitors/')
        self.assertEqual(response.status_code, 401)

    def test_user_sees_only_own_monitors(self):
        self.client.force_authenticate(user=self.bob)
        response = self.client.get('/api/monitors/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 0)

    def test_cannot_read_other_users_monitor(self):
        self.client.force_authenticate(user=self.bob)
        response = self.client.get('/api/monitors/{self.alice_monitor.id}/')
        self.assertEqual(response.status_code, 404)

    def test_cannot_delete_other_users_monitor(self):
        self.client.force_authenticate(user=self.bob)
        response = self.client.delete(f'/api/monitors/{self.alice_monitor.id}/')
        self.assertEqual(response.status_code, 404)
        self.assertTrue(Monitor.objects.filter(id=self.alice_monitor.id).exists())

    def test_owner_is_taken_from_request(self):
        self.client.force_authenticate(user=self.bob)
        response = self.client.post(
            "/api/monitors/",
            {"name": "Bob site", "url": "https://example.org", "owner": self.alice.id},
        )
        self.assertEqual(response.status_code, 201)
        monitor = Monitor.objects.get(id=response.data["id"])
        self.assertEqual(monitor.owner, self.bob)

    def test_client_cannot_set_current_status(self):
        self.client.force_authenticate(user=self.alice)
        response = self.client.post(
            "/api/monitors/",
            {"name": "Fake", "url": "https://example.net", "current_status": "up"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["current_status"], "unknown")
# Create your tests here.
