"""Configuración de la aplicación."""

from django.apps import AppConfig


class MallabConfig(AppConfig):
    """Registra la aplicación de análisis de muestras."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "mallab"
    verbose_name = "MalLab Analyzer"
