"""Reglas locales confiables: instantáneas acotadas y caché por contenido."""

import hashlib
from collections import OrderedDict
from pathlib import Path
from threading import RLock

import yara

from .exceptions import AnalysisInputError

_CACHE = OrderedDict()
_LOCK = RLock()
_CACHE_SIZE = 2  # Por proceso worker; no se persisten binarios compilados.


def clear_rules_cache():
    """Invalida la caché local (operación administrativa y pruebas)."""
    with _LOCK:
        _CACHE.clear()


def _positive_integer(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AnalysisInputError(f"{name} debe ser un entero positivo.")


def _snapshot(directory, max_files, max_bytes):
    _positive_integer(max_files, "YARA_MAX_RULE_FILES")
    _positive_integer(max_bytes, "YARA_MAX_RULE_BYTES")
    root = Path(directory).resolve(strict=True)
    if not root.is_dir():
        raise AnalysisInputError("El directorio YARA no es un directorio.")
    paths = []
    for path in root.rglob("*"):
        if path.suffix.lower() not in {".yar", ".yara"}:
            continue
        if not path.resolve(strict=True).is_relative_to(root):
            raise AnalysisInputError("Una regla YARA apunta fuera del directorio configurado.")
        if path.is_file():
            paths.append(path)
            if len(paths) > max_files:
                raise AnalysisInputError("Demasiados archivos de reglas YARA.")
    if not paths:
        raise AnalysisInputError("El directorio YARA no contiene reglas .yar/.yara.")
    sources = {}
    manifest = []
    total = 0
    for index, path in enumerate(sorted(paths)):
        # El hash y el compilador usan exactamente los mismos bytes. Los límites
        # se verifican incluso si la revisión anterior estaba en caché.
        with path.open("rb") as source:
            data = source.read(max_bytes - total + 1)
        total += len(data)
        if total > max_bytes:
            raise AnalysisInputError("Las reglas YARA superan el límite de bytes.")
        relative = path.relative_to(root).as_posix()
        manifest.append((relative, hashlib.sha256(data).hexdigest()))
        sources[f"rules_{index}"] = data.decode("utf-8-sig")
    digest = hashlib.sha256(repr(manifest).encode("utf-8")).hexdigest()
    return digest, sources


def scan_yara_result(data: bytes, directory, *, timeout=30, max_files=256,
                     max_bytes=4 * 1024 * 1024, max_matches=1000):
    """Un escaneo correcto puede tener cero matches: no certifica inocuidad.

    La falta de configuración se resuelve en el coordinador, no aquí. Errores
    de lectura, compilación o timeout se propagan; nunca se usa una revisión
    anterior como fallback silencioso.
    """
    _positive_integer(timeout, "YARA_SCAN_TIMEOUT")
    _positive_integer(max_matches, "YARA_MAX_MATCHES")
    digest, sources = _snapshot(directory, max_files, max_bytes)
    with _LOCK:
        rules = _CACHE.get(digest)
        if rules is None:
            rules = yara.compile(sources=sources, includes=False, error_on_warning=True)
            _CACHE[digest] = rules
            if len(_CACHE) > _CACHE_SIZE:
                _CACHE.popitem(last=False)
        else:
            _CACHE.move_to_end(digest)
    count = 0

    def on_match(_):
        nonlocal count
        count += 1
        return yara.CALLBACK_ABORT if count > max_matches else yara.CALLBACK_CONTINUE

    matches = rules.match(data=data, timeout=timeout, callback=on_match, which_callbacks=yara.CALLBACK_MATCHES)
    if count > max_matches:
        raise AnalysisInputError("Las coincidencias YARA superan el límite; escaneo incompleto.")
    return {
        "status": "COMPLETED",
        "ruleset_sha256": digest,
        "rule_file_count": len(sources),
        "matches": [
            {"rule": match.rule, "namespace": match.namespace, "tags": list(match.tags), "meta": dict(match.meta)}
            for match in matches
        ],
    }


def scan_yara(data: bytes, rules_directory, *, timeout=30):
    """Contrato histórico que devuelve solo la lista de coincidencias."""
    return scan_yara_result(data, rules_directory, timeout=timeout)["matches"]
