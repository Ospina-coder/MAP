"""Aplicación Celery del proyecto, configurada desde settings de Django."""

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
app = Celery("mallab")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
