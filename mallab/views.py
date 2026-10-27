"""API JSON autenticada con acceso a reportes por propietario."""

import hashlib
import logging

from django.db import transaction
from django.http import JsonResponse
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authentication import BasicAuthentication, SessionAuthentication, TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes, renderer_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer

from .models import AnalysisReport, Sample
from .tasks import analyze_sample_task
from .upload_handlers import upload_limit

logger = logging.getLogger(__name__)


@transaction.non_atomic_requests
@csrf_exempt
@never_cache
@api_view(["POST"])
@authentication_classes([BasicAuthentication, TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
@renderer_classes([JSONRenderer])
def upload_sample(request):
    """Acepta un único archivo, crea PENDING y publica la tarea tras el commit."""
    if request.content_type.split(";", 1)[0].strip() != "multipart/form-data":
        return JsonResponse({"error": "multipart_required"}, status=415)

    files = request.FILES
    if getattr(request, "sample_upload_too_large", False):
        return JsonResponse({"error": "file_too_large", "max_bytes": upload_limit()}, status=413)
    if set(files) != {"file"} or len(files.getlist("file")) != 1:
        return JsonResponse({"error": "exactly_one_file_required", "field": "file"}, status=400)
    uploaded = files["file"]
    if uploaded.size > upload_limit():
        return JsonResponse({"error": "file_too_large", "max_bytes": upload_limit()}, status=413)
    if not uploaded.name or len(uploaded.name) > 255:
        return JsonResponse({"error": "invalid_file_name"}, status=400)

    # Identificación ligera durante la ingestión. PE, entropía y YARA son del worker.
    digest = hashlib.sha256()
    size = 0
    for chunk in uploaded.chunks():
        size += len(chunk)
        if size > upload_limit():
            return JsonResponse({"error": "file_too_large", "max_bytes": upload_limit()}, status=413)
        digest.update(chunk)
    uploaded.seek(0)

    sample = Sample(
        file=uploaded, file_name=uploaded.name, file_size=size,
        hash=digest.hexdigest(), file_type="application/octet-stream",
        uploaded_by=request.user,
    )
    # File Storage no participa en transacciones: limpiar si falla la escritura SQL.
    try:
        with transaction.atomic():
            sample.save()
            report = AnalysisReport.objects.create(sample=sample)
    except Exception:
        if sample.file.name and sample.file._committed:
            try:
                sample.file.storage.delete(sample.file.name)
            except Exception:
                logger.exception("Could not clean up failed sample upload")
        raise

    dispatch_failed = False

    def enqueue():
        """Registra fallos del broker sin confundirlos con una cola aceptada."""
        nonlocal dispatch_failed
        try:
            analyze_sample_task.apply_async(args=[sample.pk], retry=False)
        except Exception:
            dispatch_failed = True
            logger.exception("Could not enqueue sample %s", sample.pk)
            # Una publicación ambigua podría haber llegado al worker: no pisarlo.
            AnalysisReport.objects.filter(pk=report.pk, status=AnalysisReport.Status.PENDING).update(
                status=AnalysisReport.Status.FAILED,
                pe_headers={"error": {"stage": "enqueue", "message": "No se pudo confirmar el envío a la cola."}},
            )

    transaction.on_commit(enqueue)
    report.refresh_from_db(fields=["status"])
    report_url = reverse("mallab:analysis-report", kwargs={"sample_id": sample.pk})
    body = {"sample_id": sample.pk, "report_id": report.pk, "status": report.status, "report_url": report_url}
    if dispatch_failed:
        body["error"] = "queue_unavailable"
    response = JsonResponse(body, status=503 if dispatch_failed else 202)
    response["Location"] = report_url
    return response


@never_cache
@api_view(["GET"])
@authentication_classes([BasicAuthentication, TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
@renderer_classes([JSONRenderer])
def get_analysis_report(request, sample_id):
    """Devuelve el estado y, al completar, resultados de una muestra propia."""
    sample = Sample.objects.filter(pk=sample_id, uploaded_by=request.user).first()
    if sample is None:
        return JsonResponse({"error": "sample_not_found"}, status=404)
    report = AnalysisReport.objects.filter(sample=sample).first()
    if report is None:
        return JsonResponse({"error": "report_not_found"}, status=404)
    body = {
        "sample_id": sample.pk, "report_id": report.pk, "status": report.status,
        "file_name": sample.file_name,
    }
    if report.status == AnalysisReport.Status.COMPLETED:
        payload = report.pe_headers
        body["results"] = {
            "entropy": report.entropy,
            "hashes": payload.get("file", {}).get("hashes", {}),
            "file_size": sample.file_size,
            "file_type": sample.file_type,
            "pe_headers": payload.get("pe", {}),
            "yara_matches": report.yara_matches,
            "yara": payload.get("yara", {}),
        }
    elif report.status == AnalysisReport.Status.FAILED:
        # La API no devuelve detalles del parser ni rutas internas en fallos.
        body["error"] = {"stage": report.pe_headers.get("error", {}).get("stage", "analysis"), "message": "No se pudo completar el análisis."}
    response = JsonResponse(body)
    if report.status in (AnalysisReport.Status.PENDING, AnalysisReport.Status.PROCESSING):
        response["Retry-After"] = "3"
    return response
