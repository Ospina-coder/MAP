"""Rutas de subida y consulta de muestras."""

from django.urls import path

from . import views

app_name = "mallab"
urlpatterns = [
    path("samples/", views.upload_sample, name="upload-sample"),
    path("samples/<int:sample_id>/report/", views.get_analysis_report, name="analysis-report"),
]
