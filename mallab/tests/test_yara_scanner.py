"""Pruebas reales de YARA con marcadores inocuos y revisiones de reglas."""

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yara
from django.test import SimpleTestCase

from mallab.services.exceptions import AnalysisInputError
from mallab.services.yara_scanner import clear_rules_cache, scan_yara_result


class YaraScannerTests(SimpleTestCase):
    def setUp(self):
        clear_rules_cache()
        self.addCleanup(clear_rules_cache)
        self.folder = TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.rule = self.root / "marker.yar"
        self.rule.write_text('rule marker { strings: $a = "MAP_TEST_A" condition: $a }', encoding="utf-8")

    def test_innocuous_repository_rule_and_no_match(self):
        folder = Path(__file__).resolve().parents[2] / "yara_rules" / "testing"
        result = scan_yara_result(b"MAP_STATIC_ANALYSIS_INNOCUOUS_TEST_v1", folder)
        self.assertEqual(result["matches"][0]["rule"], "MAP_Innocuous_Smoke_Test")
        self.assertEqual(result["matches"][0]["meta"]["purpose"], "testing_only")
        empty = scan_yara_result(b"ordinary text", folder)
        self.assertEqual(empty["status"], "COMPLETED")
        self.assertEqual(empty["matches"], [])
        self.assertEqual(empty["ruleset_sha256"], result["ruleset_sha256"])

    def test_cache_content_invalidation_even_with_same_mtime_and_size(self):
        with patch("mallab.services.yara_scanner.yara.compile", wraps=yara.compile) as compile_rules:
            first = scan_yara_result(b"MAP_TEST_A", self.root)
            scan_yara_result(b"MAP_TEST_A", self.root)
            self.assertEqual(compile_rules.call_count, 1)
            before = self.rule.stat()
            self.rule.write_text(self.rule.read_text().replace("MAP_TEST_A", "MAP_TEST_B"), encoding="utf-8")
            os.utime(self.rule, ns=(before.st_atime_ns, before.st_mtime_ns))
            changed = scan_yara_result(b"MAP_TEST_A", self.root)
            self.assertNotEqual(changed["ruleset_sha256"], first["ruleset_sha256"])
            self.assertEqual(changed["matches"], [])
            self.assertEqual(compile_rules.call_count, 2)

    def test_parallel_first_use_compiles_once(self):
        with patch("mallab.services.yara_scanner.yara.compile", wraps=yara.compile) as compile_rules:
            with ThreadPoolExecutor(max_workers=4) as executor:
                results = list(executor.map(lambda _: scan_yara_result(b"MAP_TEST_A", self.root), range(4)))
            self.assertEqual(compile_rules.call_count, 1)
            self.assertTrue(all(item["matches"] for item in results))

    def test_invalid_revision_does_not_fall_back_to_cached_rules(self):
        scan_yara_result(b"MAP_TEST_A", self.root)
        self.rule.write_text("not valid yara", encoding="utf-8")
        with self.assertRaises(yara.SyntaxError):
            scan_yara_result(b"MAP_TEST_A", self.root)

    def test_limits_apply_even_when_cached(self):
        scan_yara_result(b"MAP_TEST_A", self.root)
        with self.assertRaises(AnalysisInputError):
            scan_yara_result(b"test", self.root, max_bytes=2)
        (self.root / "second.yar").write_text("rule second { condition: true }", encoding="utf-8")
        with self.assertRaises(AnalysisInputError):
            scan_yara_result(b"test", self.root, max_files=1)

    def test_timeout_empty_missing_directory_and_includes(self):
        with patch("mallab.services.yara_scanner.yara.compile") as compile_rules:
            compile_rules.return_value.match.side_effect = yara.TimeoutError("timeout")
            with self.assertRaises(yara.TimeoutError):
                scan_yara_result(b"test", self.root)
        clear_rules_cache()
        self.rule.write_text('include "outside.yar"', encoding="utf-8")
        with self.assertRaises(yara.SyntaxError):
            scan_yara_result(b"test", self.root)
        self.rule.unlink()
        with self.assertRaises(AnalysisInputError):
            scan_yara_result(b"test", self.root)
        with self.assertRaises(FileNotFoundError):
            scan_yara_result(b"test", self.root / "missing")

    def test_cache_is_bounded(self):
        with patch("mallab.services.yara_scanner.yara.compile", wraps=yara.compile) as compile_rules:
            for name in ("one", "two", "three", "one"):
                self.rule.write_text(f"rule {name} {{ condition: true }}", encoding="utf-8")
                scan_yara_result(b"test", self.root)
            self.assertEqual(compile_rules.call_count, 4)

    def test_match_limit_aborts_instead_of_returning_a_partial_success(self):
        self.rule.write_text("rule one { condition: true } rule two { condition: true }", encoding="utf-8")
        with self.assertRaises(AnalysisInputError):
            scan_yara_result(b"test", self.root, max_matches=1)

    def test_rule_symlink_outside_root_is_rejected(self):
        # Mock solo del enlace resuelto; no requiere privilegios de symlink en Windows.
        original = Path.resolve
        external = self.root.parent / "external.yar"

        def resolve(path, *args, **kwargs):
            return external if path == self.rule else original(path, *args, **kwargs)

        with patch.object(Path, "resolve", resolve):
            with self.assertRaises(AnalysisInputError):
                scan_yara_result(b"test", self.root)
