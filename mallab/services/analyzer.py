"""Análisis estático sobre una instantánea de bytes; nunca ejecuta muestras.

Las funciones de extracción no dependen del ORM. ``process_sample`` coordina
almacenamiento, estados y persistencia. Ejecutarlo desde un worker separado.
"""

import hashlib
import logging
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pefile
import yara
from django.conf import settings
from django.db import transaction

from mallab.models import AnalysisReport, Sample

logger = logging.getLogger(__name__)


class AnalysisInProgress(RuntimeError):
    """Otra invocación ya reclamó el análisis de esta muestra."""


class AnalysisInputError(ValueError):
    """El archivo o la configuración no permiten completar el análisis."""


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


def analyze_pe(data: bytes) -> dict:
    """Extrae cabeceras, secciones e imports o describe un formato no PE.

    Un timestamp PE es un valor declarado por el archivo, no una fecha fiable.
    PEFormatError es un resultado de formato; otros errores abortan el pipeline.
    """
    if not data.startswith(b"MZ"):
        return {"is_pe": False, "reason": "missing_dos_signature"}
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        return {"is_pe": False, "reason": "invalid_pe", "detail": str(exc)[:500]}

    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]],
        )
        timestamp = int(pe.FILE_HEADER.TimeDateStamp)
        return {
            "is_pe": True,
            "compilation_timestamp": timestamp,
            "compilation_time_utc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
            "sections": [
                {
                    "name": _decode(section.Name),
                    "virtual_size": int(section.Misc_VirtualSize),
                    "raw_size": int(section.SizeOfRawData),
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
            "warnings": pe.get_warnings(),
        }
    except pefile.PEFormatError as exc:
        return {"is_pe": True, "reason": "malformed_pe", "detail": str(exc)[:500]}
    finally:
        pe.close()


def scan_yara(data: bytes, rules_directory: str | Path, *, timeout: int = 30) -> list:
    """Compila reglas .yar/.yara recursivamente y devuelve coincidencias JSON.

    Cada archivo tiene un namespace propio. No se admiten includes; distribuir
    reglas autocontenidas de confianza. Errores de compilación/timeout se propagan.
    No se guardan los bytes de cadenas coincidentes en el reporte.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1:
        raise AnalysisInputError("YARA timeout debe ser un entero positivo.")
    root = Path(rules_directory).resolve(strict=True)
    if not root.is_dir():
        raise AnalysisInputError("El directorio YARA no es un directorio.")
    paths = sorted(path for path in root.rglob("*") if path.suffix.lower() in {".yar", ".yara"} and path.is_file())
    if not paths:
        raise AnalysisInputError("El directorio YARA no contiene reglas .yar/.yara.")
    for path in paths:
        if not path.resolve().is_relative_to(root):
            raise AnalysisInputError("Una regla YARA apunta fuera del directorio configurado.")
    rules = yara.compile(
        filepaths={f"rules_{index}": str(path) for index, path in enumerate(paths)},
        includes=False,
        error_on_warning=True,
    )
    matches = rules.match(data=data, timeout=timeout)
    return [
        {"rule": match.rule, "namespace": match.namespace, "tags": list(match.tags), "meta": dict(match.meta)}
        for match in matches
    ]


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

    payload = {"schema_version": 1}
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
        payload["pe"] = analyze_pe(data)
        stage = "yara"
        directory = getattr(settings, "YARA_RULES_DIR", None)
        if directory is None:
            payload["yara"] = {"status": "SKIPPED", "reason": "rules_directory_not_configured"}
        else:
            matches = scan_yara(data, directory, timeout=getattr(settings, "YARA_SCAN_TIMEOUT", 30))
            payload["yara"] = {"status": "COMPLETED"}
    except Exception as exc:
        logger.exception("Static analysis failed for sample %s at %s", sample_id, stage)
        # El detalle queda en logs privados: no filtrar rutas o contenido al JSON.
        payload["error"] = {"stage": stage, "type": type(exc).__name__, "message": "No se pudo completar el análisis; consultar los logs del worker."}
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
                status=AnalysisReport.Status.COMPLETED, pe_headers=payload,
                entropy=entropy, yara_matches=matches,
            )
    report.refresh_from_db()
    return report
