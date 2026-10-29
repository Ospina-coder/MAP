"""Análisis estático sobre una instantánea de bytes; nunca ejecuta muestras.

Las funciones de extracción no dependen del ORM. ``process_sample`` coordina
almacenamiento, estados y persistencia. Ejecutarlo desde un worker separado.
"""

import hashlib
import logging
import math
from collections import Counter
from datetime import datetime, timezone

import pefile
import yara
from billiard.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.db import transaction

from mallab.models import AnalysisReport, Sample

from .clamav import scan_clamav
from .exceptions import AnalysisInputError
from .heuristics import evaluate_heuristics
from .yara_scanner import scan_yara, scan_yara_result

logger = logging.getLogger(__name__)


class AnalysisInProgress(RuntimeError):
    """Otra invocación ya reclamó el análisis de esta muestra."""


def calculate_hashes(data: bytes) -> dict:
    """Calcula identificadores MD5 (no criptográfico) y SHA-256 del contenido."""
    return {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def calculate_entropy(data: bytes) -> float:
    """Devuelve Shannon en bits por byte (0–8); un archivo vacío vale 0."""
    if not data:
        return 0.0
    length = len(data)
    value = -sum((count / length) * math.log2(count / length) for count in Counter(data).values())
    return min(8.0, max(0.0, value))


def detect_file_type(data: bytes) -> str:
    """Identifica firmas conocidas sin confiar en la extensión del archivo.

    Es una clasificación por encabezados, no una validación completa del formato.
    Los archivos desconocidos reciben application/octet-stream.
    """
    if len(data) >= 64 and data.startswith(b"MZ"):
        offset = int.from_bytes(data[60:64], "little")
        if offset >= 64 and data[offset:offset + 4] == b"PE\0\0":
            return "application/vnd.microsoft.portable-executable"
        return "application/x-dosexec"
    for signature, mime in (
        (b"\x7fELF", "application/x-elf"),
        (b"%PDF-", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"PK\x05\x06", "application/zip"),
        (b"\x1f\x8b", "application/gzip"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
    ):
        if data.startswith(signature):
            return mime
    return "application/octet-stream"


def _decode(value: bytes) -> str:
    """Convierte nombres del binario en texto serializable a JSON."""
    return value.rstrip(b"\0").decode("utf-8", errors="replace")


def analyze_pe(data: bytes, *, max_sections=96, max_imports=4096) -> dict:
    """Extrae cabeceras, secciones e imports o describe un formato no PE.

    Un timestamp PE es un valor declarado por el archivo, no una fecha fiable.
    PEFormatError es un resultado de formato; otros errores abortan el pipeline.
    """
    for limit in (max_sections, max_imports):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise AnalysisInputError("Los límites PE deben ser enteros positivos.")
    if not data.startswith(b"MZ"):
        return {"is_pe": False, "reason": "missing_dos_signature"}
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        return {"is_pe": False, "reason": "invalid_pe", "detail": str(exc)[:500]}

    try:
        if len(pe.sections) > max_sections:
            raise AnalysisInputError("El PE supera el límite de secciones.")
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]],
        )
        import_entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        if len(import_entries) > max_imports or sum(len(entry.imports) for entry in import_entries) > max_imports:
            raise AnalysisInputError("El PE supera el límite de importaciones.")
        timestamp = int(pe.FILE_HEADER.TimeDateStamp)
        return {
            "is_pe": True,
            "entry_point_rva": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "compilation_timestamp": timestamp,
            "compilation_time_utc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
            "sections": [
                {
                    "name": _decode(section.Name),
                    "virtual_size": int(section.Misc_VirtualSize),
                    "raw_size": int(section.SizeOfRawData),
                    "raw_offset": int(section.PointerToRawData),
                    "virtual_address": int(section.VirtualAddress),
                    "characteristics": int(section.Characteristics),
                    "observed_size": len(section.get_data()),
                    "entropy": calculate_entropy(section.get_data()),
                }
                for section in pe.sections
            ],
            "imports": [
                {
                    "dll": _decode(entry.dll),
                    "functions": [
                        {
                            "name": _decode(item.name) if item.name else None,
                            "ordinal": item.ordinal,
                            "iat_address": int(item.address),
                        }
                        for item in entry.imports
                    ],
                }
                for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            ],
            "warnings": [str(warning)[:500] for warning in pe.get_warnings()[:20]],
        }
    except pefile.PEFormatError as exc:
        return {"is_pe": True, "reason": "malformed_pe", "detail": str(exc)[:500]}
    finally:
        pe.close()


def _read_sample(sample: Sample, max_bytes: int) -> bytes:
    """Lee desde Storage, incluido almacenamiento remoto, con límite real."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise AnalysisInputError("ANALYZER_MAX_FILE_BYTES debe ser un entero positivo.")
    if not sample.file:
        raise AnalysisInputError("La muestra no tiene un archivo asociado.")
    with sample.file.open("rb") as source:
        data = source.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise AnalysisInputError("La muestra supera ANALYZER_MAX_FILE_BYTES.")
    return data


def process_sample(sample_id: int) -> AnalysisReport:
    """Reclama una muestra, analiza y persiste COMPLETED o FAILED.

    Devuelve el reporte también en fallos de análisis; consultar ``status``.
    Sample.DoesNotExist, AnalysisInProgress y errores de base de datos se propagan.
    COMPLETED es idempotente; FAILED permite reintentar. Un worker terminado
    abruptamente exige recuperar manualmente el estado PROCESSING.
    """
    sample = Sample.objects.get(pk=sample_id)
    report, _ = AnalysisReport.objects.get_or_create(sample=sample)
    # La actualización condicional evita que dos workers analicen el mismo reporte.
    claimed = AnalysisReport.objects.filter(
        pk=report.pk,
        status__in=[AnalysisReport.Status.PENDING, AnalysisReport.Status.FAILED],
    ).update(
        status=AnalysisReport.Status.PROCESSING,
        pe_headers={}, yara_matches=[], entropy=None,
    )
    if not claimed:
        report.refresh_from_db()
        if report.status == AnalysisReport.Status.COMPLETED:
            return report
        raise AnalysisInProgress(f"La muestra {sample_id} ya está en procesamiento.")

    payload = {
        "schema_version": 2,
        "yara": {"status": "SKIPPED", "reason": "not_reached"},
        "clamav": {"status": "SKIPPED", "reason": "not_reached", "signatures": []},
        "heuristics": {"status": "SKIPPED", "reason": "not_reached", "findings": []},
    }
    entropy = None
    matches = []
    stage = "read_file"
    try:
        data = _read_sample(sample, getattr(settings, "ANALYZER_MAX_FILE_BYTES", 64 * 1024 * 1024))
        stage = "file_metadata"
        hashes = calculate_hashes(data)
        mime = detect_file_type(data)
        payload["file"] = {"size": len(data), "mime_type": mime, "hashes": hashes}
        stage = "entropy"
        entropy = calculate_entropy(data)
        stage = "pe"
        payload["pe"] = analyze_pe(
            data, max_sections=getattr(settings, "PE_MAX_SECTIONS", 96),
            max_imports=getattr(settings, "PE_MAX_IMPORTS", 4096),
        )
        stage = "heuristics"
        payload["heuristics"] = evaluate_heuristics(
            file_size=len(data), entropy=entropy, pe=payload["pe"],
            entropy_threshold=getattr(settings, "HEURISTIC_ENTROPY_THRESHOLD", 7.5),
            min_entropy_bytes=getattr(settings, "HEURISTIC_MIN_ENTROPY_BYTES", 4096),
        )
        stage = "yara"
        directory = getattr(settings, "YARA_RULES_DIR", None)
        if directory is None:
            payload["yara"] = {"status": "SKIPPED", "reason": "rules_directory_not_configured"}
        else:
            try:
                result = scan_yara_result(
                    data, directory, timeout=getattr(settings, "YARA_SCAN_TIMEOUT", 30),
                    max_files=getattr(settings, "YARA_MAX_RULE_FILES", 256),
                    max_bytes=getattr(settings, "YARA_MAX_RULE_BYTES", 4 * 1024 * 1024),
                    max_matches=getattr(settings, "YARA_MAX_MATCHES", 1000),
                )
                matches = result.pop("matches")
                payload["yara"] = {**result, "match_count": len(matches)}
            except SoftTimeLimitExceeded:
                raise
            except Exception as exc:
                logger.exception("YARA scan failed for sample %s", sample_id)
                reason = "timeout" if isinstance(exc, yara.TimeoutError) else "scan_error"
                payload["yara"] = {"status": "ERROR", "reason": reason}
                payload["error"] = {"stage": stage, "type": type(exc).__name__, "message": "Falló la etapa YARA."}
        stage = "clamav"
        payload["clamav"] = scan_clamav(
            data, enabled=getattr(settings, "CLAMAV_ENABLED", False),
            socket_path=getattr(settings, "CLAMAV_SOCKET_PATH", "/run/clamav/clamd.ctl"),
            timeout=getattr(settings, "CLAMAV_TIMEOUT", 30),
            max_bytes=getattr(settings, "ANALYZER_MAX_FILE_BYTES", 64 * 1024 * 1024),
            max_response_bytes=getattr(settings, "CLAMAV_MAX_RESPONSE_BYTES", 8192),
        )
        if payload["clamav"]["status"] in {"UNAVAILABLE", "ERROR"}:
            payload.setdefault("error", {"stage": stage, "type": "ClamAVStageError", "message": "Falló la etapa ClamAV."})
    except Exception as exc:
        logger.exception("Static analysis failed for sample %s at %s", sample_id, stage)
        # El detalle queda en logs privados: no filtrar rutas o contenido al JSON.
        payload["error"] = {"stage": stage, "type": type(exc).__name__, "message": "No se pudo completar el análisis; consultar los logs del worker."}
        if stage in {"yara", "clamav", "heuristics"}:
            payload[stage] = {**payload[stage], "status": "ERROR", "reason": "stage_error"}
        AnalysisReport.objects.filter(pk=report.pk).update(
            status=AnalysisReport.Status.FAILED, pe_headers=payload,
            entropy=entropy, yara_matches=matches,
        )
    else:
        # No se mantiene ninguna transacción abierta durante el análisis costoso.
        # Si falla la base de datos, propagar el error para alertar al worker.
        with transaction.atomic():
            Sample.objects.filter(pk=sample_id).update(
                hash=hashes["sha256"], file_size=len(data), file_type=mime,
            )
            AnalysisReport.objects.filter(pk=report.pk).update(
                status=AnalysisReport.Status.FAILED if "error" in payload else AnalysisReport.Status.COMPLETED,
                pe_headers=payload,
                entropy=entropy, yara_matches=matches,
            )
    report.refresh_from_db()
    return report
