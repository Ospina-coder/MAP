"""Cliente clamd INSTREAM exclusivamente local; sin shell ni archivos temporales."""

import errno
import math
import socket
import struct
import time


def _result(status, *, reason=None, signatures=()):
    result = {"status": status, "signatures": list(signatures)}
    if reason:
        result["reason"] = reason
    return result


def scan_clamav(data: bytes, *, enabled=False, socket_path="/run/clamav/clamd.ctl",
                timeout=30, max_bytes=64 * 1024 * 1024, max_response_bytes=8192):
    """Escanea una instantánea por AF_UNIX; nunca acepta host/puerto TCP.

    NO_DETECTION significa solo que el daemon respondió OK con su configuración
    y firmas actuales. INSTREAM no garantiza enumerar todas las firmas posibles.
    Los errores no incluyen mensajes arbitrarios ni rutas devueltas por clamd.
    """
    if enabled is False:
        return _result("SKIPPED", reason="disabled")
    if enabled is not True:
        return _result("ERROR", reason="invalid_configuration")
    if (not isinstance(socket_path, str) or not socket_path.startswith("/") or "\0" in socket_path
            or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0
            or isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1
            or isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int)
            or not 32 <= max_response_bytes <= 65536):
        return _result("ERROR", reason="invalid_configuration")
    if len(data) > max_bytes:
        return _result("ERROR", reason="input_size_limit")
    if not hasattr(socket, "AF_UNIX"):
        return _result("UNAVAILABLE", reason="unix_socket_not_supported")

    deadline = time.monotonic() + timeout

    def set_remaining(connection):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ClamAV deadline exceeded")
        connection.settimeout(remaining)

    connected = False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            set_remaining(connection)
            connection.connect(socket_path)
            connected = True
            set_remaining(connection)
            connection.sendall(b"zINSTREAM\0")
            for offset in range(0, len(data), 65536):
                chunk = data[offset:offset + 65536]
                set_remaining(connection)
                connection.sendall(struct.pack("!I", len(chunk)) + chunk)
            set_remaining(connection)
            connection.sendall(b"\0\0\0\0")
            response = bytearray()
            while b"\0" not in response:
                set_remaining(connection)
                block = connection.recv(min(4096, max_response_bytes + 1 - len(response)))
                if not block:
                    return _result("ERROR", reason="incomplete_response")
                response.extend(block)
                if len(response) > max_response_bytes:
                    return _result("ERROR", reason="response_size_limit")
    except (TimeoutError, socket.timeout):
        return _result("ERROR", reason="timeout")
    except OSError as exc:
        if not connected:
            reason = "permission_denied" if exc.errno in {errno.EACCES, errno.EPERM} else "connection_unavailable"
            return _result("UNAVAILABLE", reason=reason)
        return _result("ERROR", reason="transport_error")

    try:
        message = bytes(response).removesuffix(b"\0").decode("utf-8")
    except UnicodeDecodeError:
        return _result("ERROR", reason="invalid_response")
    if message == "stream: OK":
        return _result("NO_DETECTION")
    if message.startswith("stream: ") and message.endswith(" FOUND"):
        signature = message[len("stream: "):-len(" FOUND")]
        if signature and not any(ord(char) < 32 for char in signature):
            return _result("DETECTED", signatures=[signature])
    if message.endswith(" ERROR"):
        return _result("ERROR", reason="daemon_error")
    return _result("ERROR", reason="invalid_response")
