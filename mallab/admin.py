"""Administración de usuarios, muestras y resultados de análisis."""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import AnalysisReport, Sample, User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    """Conserva los formularios seguros de creación y cambio de contraseñas."""

    list_display = ("username", "name", "email", "role", "is_active", "daily_uploads")
    list_filter = DjangoUserAdmin.list_filter + ("role",)
    search_fields = ("username", "name", "email")
    readonly_fields = ("user_id", "date_joined", "last_login", "last_ip", "daily_uploads")
    fieldsets = DjangoUserAdmin.fieldsets + (
        ("MalLab", {"fields": ("user_id", "name", "role", "last_ip", "daily_uploads")}),
    )
    add_fieldsets = DjangoUserAdmin.add_fieldsets + (
        ("MalLab", {"fields": ("name", "email", "role")}),
    )


@admin.register(Sample)
class SampleAdmin(admin.ModelAdmin):
    """Permite buscar muestras y filtrar por metadatos."""

    list_display = ("id", "file_name", "file_size", "file_type", "uploaded_by", "creation_date")
    list_filter = ("file_type", "creation_date")
    search_fields = ("file_name", "hash", "uploaded_by__username", "uploaded_by__email")
    autocomplete_fields = ("uploaded_by",)
    readonly_fields = ("id", "creation_date")
    list_select_related = ("uploaded_by",)
    date_hierarchy = "creation_date"
    ordering = ("-creation_date", "-pk")


@admin.register(AnalysisReport)
class AnalysisReportAdmin(admin.ModelAdmin):
    """Facilita la inspección de estados y resultados estructurados."""

    list_display = ("id_analysis", "sample", "status", "entropy")
    list_filter = ("status",)
    search_fields = ("sample__file_name", "sample__hash")
    autocomplete_fields = ("sample",)
    readonly_fields = ("id_analysis",)
    list_select_related = ("sample",)
    ordering = ("-pk",)
