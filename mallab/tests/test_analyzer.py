"""Comprueba extracción real, errores de reglas y persistencia de estados."""

import json
import struct
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yara
from django.core.files.base import ContentFile
from django.test import SimpleTestCase, TestCase, override_settings

from mallab.models import AnalysisReport, Sample, User
from mallab.services.analyzer import (
    AnalysisInProgress, AnalysisInputError, analyze_pe, calculate_entropy,
    calculate_hashes, detect_file_type, process_sample, scan_yara,
)


def minimal_pe():
    """Construye un PE32 sintético sin código ejecutable para probar el parser."""
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 132, 0x14C, 1, 1700000000, 0, 0, 224, 0x102)
    optional = 152
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 4096, 512)
    struct.pack_into("<II", data, optional + 56, 8192, 512)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 224
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 512, 4096, 512, 512)
    data[512:] = bytes(range(256)) * 2
    return bytes(data)


class ExtractionTests(SimpleTestCase):
    """Verifica los cálculos y los parsers sin base de datos."""

    def test_hashes_and_entropy(self):
        self.assertEqual(calculate_hashes(b"abc"), {
            "md5": "900150983cd24fb0d6963f7d28e17f72",
            "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        })
        self.assertEqual(calculate_entropy(b""), 0)
        self.assertEqual(calculate_entropy(b"a" * 1000), 0)
        self.assertEqual(calculate_entropy(bytes(range(256))), 8)
        self.assertEqual(calculate_entropy(b"ab"), 1)

    def test_real_pe_and_non_pe(self):
        data = minimal_pe()
        self.assertEqual(detect_file_type(data), "application/vnd.microsoft.portable-executable")
        result = analyze_pe(data)
        self.assertTrue(result["is_pe"])
        self.assertEqual(result["compilation_timestamp"], 1700000000)
        self.assertEqual(result["sections"][0]["name"], ".text")
        self.assertEqual(result["sections"][0]["virtual_size"], 512)
        self.assertEqual(result["sections"][0]["entropy"], 8)
        self.assertEqual(result["imports"], [])
        self.assertFalse(analyze_pe(b"MZbroken")["is_pe"])
        self.assertEqual(analyze_pe(b"ordinary bytes")["reason"], "missing_dos_signature")
        json.dumps(result)

    def test_imports_including_ordinal(self):
        from types import SimpleNamespace
        fake = SimpleNamespace(
            FILE_HEADER=SimpleNamespace(TimeDateStamp=0), sections=[],
            OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0),
            DIRECTORY_ENTRY_IMPORT=[SimpleNamespace(dll=b"KERNEL32.dll", imports=[
                SimpleNamespace(name=b"CreateFileW", ordinal=None, address=4096),
                SimpleNamespace(name=None, ordinal=12, address=4100),
            ])],
            parse_data_directories=lambda **kwargs: None,
            get_warnings=lambda: [], close=lambda: None,
        )
        with patch("mallab.services.analyzer.pefile.PE", return_value=fake):
            imports = analyze_pe(b"MZ")["imports"]
        self.assertEqual(imports[0]["dll"], "KERNEL32.dll")
        self.assertEqual(imports[0]["functions"][0]["name"], "CreateFileW")
        self.assertEqual(imports[0]["functions"][1]["ordinal"], 12)

    def test_real_yara_match_and_invalid_rules(self):
        with TemporaryDirectory() as folder:
            rule = Path(folder) / "marker.yar"
            rule.write_text('rule marker : test { strings: $a = "MALLAB_TEST" condition: $a }', encoding="utf-8")
            matches = scan_yara(b"MALLAB_TEST", folder)
            self.assertEqual(matches[0]["rule"], "marker")
            self.assertEqual(matches[0]["tags"], ["test"])
            self.assertEqual(scan_yara(b"clean", folder), [])
            json.dumps(matches)
            rule.write_text("invalid yara", encoding="utf-8")
            with self.assertRaises(yara.SyntaxError):
                scan_yara(b"data", folder)
        with TemporaryDirectory() as folder:
            with self.assertRaises(AnalysisInputError):
                scan_yara(b"data", folder)

    def test_yara_timeout_propagates(self):
        with TemporaryDirectory() as folder:
            (Path(folder) / "a.yar").write_text("rule a { condition: true }", encoding="utf-8")
            with patch("mallab.services.yara_scanner.yara.compile") as compile_rules:
                compile_rules.return_value.match.side_effect = yara.TimeoutError("timeout")
                with self.assertRaises(yara.TimeoutError):
                    scan_yara(b"data", folder, timeout=1)


class PipelineTests(TestCase):
    """Comprueba el contrato de estados, archivos privados y reintentos."""

    def setUp(self):
        self.media = TemporaryDirectory()
        self.addCleanup(self.media.cleanup)
        override = override_settings(MEDIA_ROOT=self.media.name, YARA_RULES_DIR=None)
        override.enable()
        self.addCleanup(override.disable)
        self.user = User.objects.create_user(username="tester", email="test@example.test", name="Test")
        self.sample = Sample.objects.create(
            uploaded_by=self.user, file_name="../../fake.exe", file_size=0,
            hash="0" * 64, file_type="unknown",
            file=ContentFile(b"abc", name="../../fake.exe"),
        )

    def test_success_and_idempotence(self):
        report = process_sample(self.sample.pk)
        self.assertEqual(report.status, AnalysisReport.Status.COMPLETED)
        self.assertEqual(report.pe_headers["file"]["hashes"], calculate_hashes(b"abc"))
        self.assertEqual(report.pe_headers["yara"]["status"], "SKIPPED")
        self.sample.refresh_from_db()
        self.assertEqual(self.sample.hash, calculate_hashes(b"abc")["sha256"])
        self.assertEqual(self.sample.file_size, 3)
        self.assertTrue(self.sample.file.name.startswith("quarantine/"))
        with patch("mallab.services.analyzer._read_sample") as read:
            self.assertEqual(process_sample(self.sample.pk).pk, report.pk)
            read.assert_not_called()

    def test_failed_limit_and_retry(self):
        with override_settings(ANALYZER_MAX_FILE_BYTES=2), self.assertLogs("mallab.services.analyzer", level="ERROR"):
            report = process_sample(self.sample.pk)
        self.assertEqual(report.status, AnalysisReport.Status.FAILED)
        self.assertEqual(report.pe_headers["error"]["stage"], "read_file")
        self.assertEqual(process_sample(self.sample.pk).status, AnalysisReport.Status.COMPLETED)

    def test_missing_file(self):
        Sample.objects.filter(pk=self.sample.pk).update(file="")
        with self.assertLogs("mallab.services.analyzer", level="ERROR"):
            report = process_sample(self.sample.pk)
        self.assertEqual(report.status, AnalysisReport.Status.FAILED)

    def test_yara_failure_and_partial_results(self):
        with TemporaryDirectory() as folder:
            (Path(folder) / "invalid.yar").write_text("bad rules", encoding="utf-8")
            with override_settings(YARA_RULES_DIR=folder), self.assertLogs("mallab.services.analyzer", level="ERROR"):
                report = process_sample(self.sample.pk)
        self.assertEqual(report.status, AnalysisReport.Status.FAILED)
        self.assertEqual(report.pe_headers["error"]["stage"], "yara")
        self.assertIn("file", report.pe_headers)
        self.assertIsNotNone(report.entropy)

    def test_processing_is_not_claimed_twice(self):
        AnalysisReport.objects.create(sample=self.sample, status=AnalysisReport.Status.PROCESSING)
        with self.assertRaises(AnalysisInProgress):
            process_sample(self.sample.pk)

    def test_missing_sample(self):
        with self.assertRaises(Sample.DoesNotExist):
            process_sample(999999)
