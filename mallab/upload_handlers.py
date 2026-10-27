"""Límite de bytes durante la recepción, antes del almacenamiento de Django."""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.files.uploadhandler import FileUploadHandler, StopUpload


def upload_limit():
    """Devuelve un límite coherente con el tamaño admitido por el analizador."""
    analyzer_limit = getattr(settings, "ANALYZER_MAX_FILE_BYTES", 64 * 1024 * 1024)
    limit = getattr(settings, "SAMPLE_MAX_UPLOAD_BYTES", analyzer_limit)
    for value in (limit, analyzer_limit):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ImproperlyConfigured("Los límites de muestra deben ser enteros positivos.")
    return min(limit, analyzer_limit)


class SampleSizeUploadHandler(FileUploadHandler):
    """Limita el total de bytes de archivos de una petición multipart."""

    def __init__(self, request=None):
        super().__init__(request)
        self.total = 0

    def receive_data_chunk(self, raw_data, start):
        """Detiene la recepción antes de escribir un bloque que supera el límite."""
        self.total += len(raw_data)
        if self.total > upload_limit():
            self.request.sample_upload_too_large = True
            raise StopUpload(connection_reset=False)
        return raw_data

    def file_complete(self, file_size):
        """Delega la construcción del archivo a los handlers nativos."""
        return None
