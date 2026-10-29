"""Configuración aislada para pruebas; no usar en despliegues."""

from config.settings import *  # noqa: F403 - mismo middleware y rutas que el proyecto

SECRET_KEY = "tests-only-not-for-deployment"
AUTH_USER_MODEL = "mallab.User"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
YARA_RULES_DIR = None
CLAMAV_ENABLED = False
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
