"""Tareas Celery que transportan identificadores, nunca archivos o modelos."""

from celery import shared_task

from .models import Sample
from .services.analyzer import AnalysisInProgress, process_sample


@shared_task(ignore_result=True, soft_time_limit=110, time_limit=120)
def analyze_sample_task(sample_id):
    """Ejecuta el pipeline; el estado definitivo se consulta en AnalysisReport."""
    try:
        report = process_sample(sample_id)
    except Sample.DoesNotExist:
        return {"sample_id": sample_id, "status": "DELETED"}
    except AnalysisInProgress:
        return {"sample_id": sample_id, "status": "PROCESSING"}
    return {"report_id": report.pk, "status": report.status}
