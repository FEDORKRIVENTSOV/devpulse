import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("config")
# All settings that start with CELERY_ in settings.py are picked up here.
app.config_from_object("django.conf:settings", namespace="CELERY")
# Finds monitors/tasks.py automatically.
app.autodiscover_tasks()
