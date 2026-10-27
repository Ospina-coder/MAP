"""Inicializa Celery junto con el proyecto Django."""

from .celery import app as celery_app

__all__ = ("celery_app",)
