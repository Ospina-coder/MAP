"""Protocolo ClamAV simulado; integración real opcional sobre socket local."""

import errno
import os
import struct
from types import SimpleNamespace
from unittest import skipUnless
from unittest.mock import patch

from django.test import SimpleTestCase

from mallab.services.clamav import scan_clamav


class ClamAVTests(SimpleTestCase):
    def setUp(self):
        self.family_patch = patch("mallab.services.clamav.socket.AF_UNIX", 99, create=True)
        self.family_patch.start()
        self.addCleanup(self.family_patch.stop)
        self.factory_patch = patch("mallab.services.clamav.socket.socket")
        self.factory = self.factory_patch.start()
        self.addCleanup(self.factory_patch.stop)
        self.connection = self.factory.return_value.__enter__.return_value
        self.connection.recv.return_value = b"stream: OK\0"

    def scan(self, data=b"innocuous text", **kwargs):
        return scan_clamav(data, enabled=True, **kwargs)

    def test_disabled_does_not_open_socket(self):
        self.assertEqual(scan_clamav(b"text")["status"], "SKIPPED")
        self.factory.assert_not_called()

    def test_platform_without_unix_sockets_is_unavailable(self):
        with patch("mallab.services.clamav.socket", SimpleNamespace()):
            self.assertEqual(self.scan()["reason"], "unix_socket_not_supported")
        self.factory.assert_not_called()

    def test_stream_framing_and_signature_are_preserved(self):
        self.connection.recv.side_effect = [b"stream: MAP.Test", b".Signature FOUND\0"]
        result = self.scan(b"abc")
        self.assertEqual(result, {"status": "DETECTED", "signatures": ["MAP.Test.Signature"]})
        self.assertEqual([call.args[0] for call in self.connection.sendall.call_args_list],
                         [b"zINSTREAM\0", struct.pack("!I", 3) + b"abc", b"\0\0\0\0"])
        self.factory.return_value.__exit__.assert_called_once()

    def test_no_detection_and_empty_input(self):
        self.assertEqual(self.scan(b"")["status"], "NO_DETECTION")
        self.assertEqual(self.scan()["signatures"], [])

    def test_missing_socket_and_permission_denied(self):
        for code, reason in ((errno.ENOENT, "connection_unavailable"), (errno.EACCES, "permission_denied")):
            self.connection.connect.side_effect = OSError(code, "private filesystem path")
            self.assertEqual(self.scan(), {"status": "UNAVAILABLE", "signatures": [], "reason": reason})

    def test_timeout_and_total_deadline(self):
        self.connection.recv.side_effect = TimeoutError("private error")
        self.assertEqual(self.scan()["reason"], "timeout")
        self.connection.recv.side_effect = None
        with patch("mallab.services.clamav.time.monotonic", side_effect=[0, 0, 31]):
            self.assertEqual(self.scan(timeout=30)["reason"], "timeout")

    def test_daemon_errors_and_malformed_replies_never_mean_clean(self):
        for reply in (b"INSTREAM size limit exceeded. ERROR\0", b"unknown\0", b"stream: \xff FOUND\0",
                      b"stream: OK", b"stream: OK\0garbage", b"stream: bad\nname FOUND\0"):
            with self.subTest(reply=reply):
                self.connection.recv.side_effect = [reply, b""]
                result = self.scan()
                self.assertEqual(result["status"], "ERROR")
                self.assertEqual(result["signatures"], [])

    def test_response_input_limits_and_transport_error(self):
        self.connection.recv.return_value = b"x" * 33
        self.assertEqual(self.scan(max_response_bytes=32)["reason"], "response_size_limit")
        self.assertEqual(self.scan(b"abc", max_bytes=2)["reason"], "input_size_limit")
        self.connection.recv.side_effect = OSError("closed")
        self.assertEqual(self.scan()["reason"], "transport_error")

    def test_network_addresses_and_bad_configuration_are_rejected(self):
        for kwargs in ({"socket_path": "127.0.0.1:3310"}, {"socket_path": "tcp://remote:3310"},
                       {"timeout": -1}, {"timeout": float("nan")}, {"max_bytes": True}):
            self.assertEqual(self.scan(**kwargs)["reason"], "invalid_configuration")
        self.factory.assert_not_called()

    def test_only_unix_socket_is_used_and_large_input_is_chunked(self):
        import socket
        self.assertEqual(self.scan(b"x" * 65537)["status"], "NO_DETECTION")
        self.factory.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        frames = [call.args[0] for call in self.connection.sendall.call_args_list]
        self.assertEqual(struct.unpack("!I", frames[1][:4])[0], 65536)
        self.assertEqual(struct.unpack("!I", frames[2][:4])[0], 1)


@skipUnless(os.name == "posix" and os.environ.get("MAP_TEST_CLAMAV_SOCKET"),
            "Requiere clamd real y MAP_TEST_CLAMAV_SOCKET en Unix; no es un test simulado.")
class LiveClamAVTests(SimpleTestCase):
    def test_local_daemon_accepts_innocuous_text(self):
        result = scan_clamav(b"MAP innocuous local integration check", enabled=True,
                             socket_path=os.environ["MAP_TEST_CLAMAV_SOCKET"])
        self.assertEqual(result["status"], "NO_DETECTION", result)
