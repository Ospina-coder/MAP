"""Entidades de usuarios, muestras y reportes de MalLab Analyzer."""

import secrets
import uuid

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractUser
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    """Usuario nativo extendido; las contraseñas usan el hash de Django."""

    class Role(models.TextChoices):
        """Roles funcionales, independientes de los permisos del administrador."""

        USER = "USER", "Usuario"
        ANALYST = "ANALYST", "Analista"
        ADMIN = "ADMIN", "Administrador"

    user_id = models.BigAutoField(primary_key=True, db_column="user_Id")
    name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.USER)
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    api_key = models.CharField(max_length=128, blank=True, default="", editable=False)
    daily_uploads = models.PositiveIntegerField(default=0)

    # AbstractUser aporta password, is_active, date_joined, username y permisos.
    REQUIRED_FIELDS = ["email", "name"]

    class Meta:
        verbose_name = "usuario"
        verbose_name_plural = "usuarios"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(role__in=["USER", "ANALYST", "ADMIN"]),
                name="mallab_user_valid_role",
            ),
        ]

    def __str__(self):
        """Identifica al usuario sin revelar credenciales."""
        return f"{self.name or self.username} <{self.email}>"

    def rotate_api_key(self):
        """Guarda el hash de una clave nueva y devuelve su secreto una sola vez."""
        raw_key = secrets.token_urlsafe(32)
        self.api_key = make_password(raw_key)
        self.save(update_fields=["api_key"])
        return raw_key

    def check_api_key(self, raw_key):
        """Comprueba una clave para un usuario ya identificado y activo."""
        return bool(self.is_active and self.api_key and check_password(raw_key, self.api_key))


def sample_upload_path(instance, filename):
    """Asigna un identificador opaco al binario, sin usar el nombre del cliente."""
    return f"quarantine/{uuid.uuid4().hex}"


class Sample(models.Model):
    """Metadatos y referencia al binario en almacenamiento privado."""

    id = models.BigAutoField(primary_key=True, db_column="Id")
    file_name = models.CharField(max_length=255)
    file = models.FileField(upload_to=sample_upload_path, blank=True, max_length=255)
    file_size = models.PositiveBigIntegerField(help_text="Tamaño en bytes.")
    hash = models.CharField(
        max_length=64,
        db_index=True,
        validators=[RegexValidator(
            regex=r"\A(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{64})\Z",
            message="Introduce un MD5 de 32 o un SHA-256 de 64 caracteres hexadecimales.",
        )],
    )
    file_type = models.CharField(max_length=100)
    creation_date = models.DateTimeField(default=timezone.now, editable=False)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="samples",
        null=True,
        blank=True,
    )

    class Meta:
        verbose_name = "muestra"
        verbose_name_plural = "muestras"
        indexes = [
            models.Index(fields=["-creation_date"], name="mallab_sample_created_idx"),
            models.Index(fields=["uploaded_by", "-creation_date"], name="mallab_sample_user_date_idx"),
        ]

    def __str__(self):
        """Muestra el nombre y una referencia breve del hash."""
        return f"{self.file_name} ({self.hash[:12]})"


class AnalysisReport(models.Model):
    """Reporte único de una muestra, creado al iniciar su análisis."""

    class Status(models.TextChoices):
        """Estados persistentes del procesamiento."""

        PENDING = "PENDING", "Pendiente"
        PROCESSING = "PROCESSING", "Procesando"
        COMPLETED = "COMPLETED", "Completado"
        FAILED = "FAILED", "Fallido"

    id_analysis = models.BigAutoField(primary_key=True, db_column="Id_analysis")
    sample = models.OneToOneField(
        Sample,
        db_column="Id",
        on_delete=models.CASCADE,
        related_name="analysis_report",
    )
    yara_matches = models.JSONField(default=list, blank=True)
    pe_headers = models.JSONField(default=dict, blank=True)
    entropy = models.FloatField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0.0), MaxValueValidator(8.0)],
        help_text="Entropía de Shannon por byte (0–8); nula mientras no se calcule.",
    )
    status = models.CharField(
        max_length=10, choices=Status.choices, default=Status.PENDING, db_index=True,
    )

    class Meta:
        verbose_name = "reporte de análisis"
        verbose_name_plural = "reportes de análisis"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(status__in=["PENDING", "PROCESSING", "COMPLETED", "FAILED"]),
                name="mallab_report_valid_status",
            ),
            models.CheckConstraint(
                condition=models.Q(entropy__isnull=True) | models.Q(entropy__gte=0, entropy__lte=8),
                name="mallab_report_entropy_range",
            ),
        ]

    def __str__(self):
        """Identifica el reporte sin consultar su muestra."""
        return f"Reporte {self.pk} · muestra {self.sample_id} · {self.get_status_display()}"
