"""Integración del pipeline v2: herramientas independientes y datos persistidos."""

import json
import struct
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import yara
from billiard.exceptions import SoftTimeLimitExceeded
from django.core.files.base import ContentFile
from django.test import SimpleTestCase, TestCase, override_settings

from mallab.models import AnalysisReport, Sample, User
from mallab.services.analyzer import AnalysisInputError, analyze_pe, process_sample
from mallab.tests.test_analyzer import minimal_pe


class PEResourceTests(SimpleTestCase):
    def test_new_metadata_is_extracted_from_a_real_synthetic_pe(self):
        data = bytearray(minimal_pe())
        struct.pack_into("<I", data, 152 + 16, 4096)
        struct.pack_into("<I", data, 376 + 36, 0xE0000020)
        pe = analyze_pe(bytes(data))
        self.assertEqual(pe["entry_point_rva"], 4096)
        self.assertEqual(pe["sections"][0]["characteristics"], 0xE0000020)
        self.assertEqual(pe["sections"][0]["raw_offset"], 512)
        self.assertEqual(pe["sections"][0]["observed_size"], 512)

    def test_section_limit_is_enforced_on_synthetic_pe(self):
        data = bytearray(minimal_pe())
        struct.pack_into("<H", data, 134, 3)
        data[416:456] = data[376:416]
        data[456:496] = data[376:416]
        with self.assertRaises(AnalysisInputError):
            analyze_pe(bytes(data), max_sections=2)

    def test_import_limit_closes_parser_and_does_not_return_partial_success(self):
        fake = SimpleNamespace(
            sections=[], DIRECTORY_ENTRY_IMPORT=[SimpleNamespace(imports=[object(), object()])],
            parse_data_directories=lambda **kwargs: None, close=lambda: None,
        )
        with patch("mallab.services.analyzer.pefile.PE", return_value=fake), patch.object(fake, "close") as close:
            with self.assertRaises(AnalysisInputError):
                analyze_pe(b"MZ", max_imports=1)
            close.assert_called_once()
        fake.DIRECTORY_ENTRY_IMPORT = [SimpleNamespace(imports=[]), SimpleNamespace(imports=[])]
        with patch("mallab.services.analyzer.pefile.PE", return_value=fake):
            with self.assertRaises(AnalysisInputError):
                analyze_pe(b"MZ", max_imports=1)


@override_settings(YARA_RULES_DIR=None, CLAMAV_ENABLED=False)
class EngineV2Tests(TestCase):
    def setUp(self):
        self.media = TemporaryDirectory()
        self.addCleanup(self.media.cleanup)
        override = override_settings(MEDIA_ROOT=self.media.name)
        override.enable()
        self.addCleanup(override.disable)
        self.user = User.objects.create_user(username="engine", email="engine@example.test", name="Engine")
        self.sample = Sample.objects.create(
            uploaded_by=self.user, file_name="test.txt", file_size=3, hash="0" * 64,
            file_type="unknown", file=ContentFile(b"abc", name="test.txt"),
        )

    def retry(self):
        AnalysisReport.objects.filter(sample=self.sample).update(status="FAILED")
        return process_sample(self.sample.pk)

    def test_disabled_tools_are_explicit_and_results_are_versioned(self):
        report = process_sample(self.sample.pk)
        self.assertEqual(report.status, "COMPLETED")
        payload = report.pe_headers
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["yara"], {"status": "SKIPPED", "reason": "rules_directory_not_configured"})
        self.assertEqual(payload["clamav"]["status"], "SKIPPED")
        self.assertEqual(payload["heuristics"]["status"], "COMPLETED")
        self.assertEqual(payload["heuristics"]["findings"], [])
        json.dumps(payload)

    def test_yara_success_without_matches_and_innocuous_match(self):
        directory = Path(__file__).resolve().parents[2] / "yara_rules" / "testing"
        with override_settings(YARA_RULES_DIR=directory):
            report = process_sample(self.sample.pk)
            self.assertEqual(report.status, "COMPLETED")
            self.assertEqual(report.pe_headers["yara"]["match_count"], 0)
            self.assertEqual(report.yara_matches, [])
            self.sample.file.save("marker.txt", ContentFile(b"MAP_STATIC_ANALYSIS_INNOCUOUS_TEST_v1"))
            report = self.retry()
        self.assertEqual(report.pe_headers["yara"]["match_count"], 1)
        self.assertEqual(report.yara_matches[0]["rule"], "MAP_Innocuous_Smoke_Test")
        self.assertEqual(report.status, "COMPLETED")  # Estado de ejecución, no veredicto.

    def test_yara_timeout_does_not_prevent_independent_clamav_stage(self):
        with override_settings(YARA_RULES_DIR="configured", CLAMAV_ENABLED=True):
            with patch("mallab.services.analyzer.scan_yara_result", side_effect=yara.TimeoutError("private path")):
                with patch("mallab.services.analyzer.scan_clamav", return_value={"status": "NO_DETECTION", "signatures": []}) as clam:
                    with self.assertLogs("mallab.services.analyzer", level="ERROR"):
                        report = process_sample(self.sample.pk)
        self.assertEqual(report.status, "FAILED")
        self.assertEqual(report.pe_headers["yara"], {"status": "ERROR", "reason": "timeout"})
        self.assertEqual(report.pe_headers["clamav"]["status"], "NO_DETECTION")
        self.assertEqual(report.pe_headers["heuristics"]["status"], "COMPLETED")
        self.assertEqual(clam.call_args.args, (b"abc",))
        self.assertNotIn("private path", json.dumps(report.pe_headers))

    def test_clamav_detected_and_no_detection_both_complete_execution(self):
        with override_settings(CLAMAV_ENABLED=True):
            for result in ({"status": "DETECTED", "signatures": ["MAP.Simulated.Signature"]},
                           {"status": "NO_DETECTION", "signatures": []}):
                with patch("mallab.services.analyzer.scan_clamav", return_value=result) as clam:
                    report = self.retry()
                self.assertEqual(report.status, "COMPLETED")
                self.assertEqual(report.pe_headers["clamav"], result)
                self.assertTrue(clam.call_args.kwargs["enabled"])

    def test_clamav_enabled_unavailable_or_error_marks_report_failed(self):
        with override_settings(CLAMAV_ENABLED=True):
            for status in ("UNAVAILABLE", "ERROR"):
                with patch("mallab.services.analyzer.scan_clamav", return_value={"status": status, "reason": "test", "signatures": []}):
                    report = self.retry()
                self.assertEqual(report.status, "FAILED")
                self.assertEqual(report.pe_headers["error"]["stage"], "clamav")
                self.assertEqual(report.pe_headers["clamav"]["status"], status)
                self.assertIn("file", report.pe_headers)

    def test_both_tool_errors_remain_visible_and_first_error_is_preserved(self):
        with override_settings(YARA_RULES_DIR="configured", CLAMAV_ENABLED=True):
            with patch("mallab.services.analyzer.scan_yara_result", side_effect=yara.SyntaxError("bad rule")):
                with patch("mallab.services.analyzer.scan_clamav", return_value={"status": "UNAVAILABLE", "signatures": []}):
                    with self.assertLogs("mallab.services.analyzer", level="ERROR"):
                        report = self.retry()
        self.assertEqual(report.status, "FAILED")
        self.assertEqual(report.pe_headers["error"]["stage"], "yara")
        self.assertEqual(report.pe_headers["yara"]["status"], "ERROR")
        self.assertEqual(report.pe_headers["clamav"]["status"], "UNAVAILABLE")

    def test_soft_limit_is_not_swallowed_to_start_another_tool(self):
        with override_settings(YARA_RULES_DIR="configured", CLAMAV_ENABLED=True):
            with patch("mallab.services.analyzer.scan_yara_result", side_effect=SoftTimeLimitExceeded()):
                with patch("mallab.services.analyzer.scan_clamav") as clam:
                    with self.assertLogs("mallab.services.analyzer", level="ERROR"):
                        report = process_sample(self.sample.pk)
        self.assertEqual(report.status, "FAILED")
        self.assertEqual(report.pe_headers["yara"]["status"], "ERROR")
        self.assertEqual(report.pe_headers["clamav"]["reason"], "not_reached")
        clam.assert_not_called()

    def test_resource_failure_preserves_tool_stages_as_not_reached(self):
        with override_settings(ANALYZER_MAX_FILE_BYTES=2):
            with self.assertLogs("mallab.services.analyzer", level="ERROR"):
                report = process_sample(self.sample.pk)
        self.assertEqual(report.status, "FAILED")
        self.assertEqual(report.pe_headers["error"]["stage"], "read_file")
        self.assertEqual(report.pe_headers["clamav"]["reason"], "not_reached")

    def test_real_pe_metadata_feeds_persisted_explainable_findings(self):
        data = bytearray(minimal_pe())
        struct.pack_into("<I", data, 152 + 16, 4096)
        struct.pack_into("<I", data, 376 + 36, 0xE0000020)
        self.sample.file.save("synthetic.pe", ContentFile(bytes(data)))
        report = process_sample(self.sample.pk)
        self.assertEqual(report.status, "COMPLETED")
        findings = report.pe_headers["heuristics"]["findings"]
        writable = next(item for item in findings if item["id"] == "writable_executable_section")
        self.assertEqual(writable["evidence"]["characteristics"], 0xE0000020)
        self.assertIn("JIT", writable["limitations"])
