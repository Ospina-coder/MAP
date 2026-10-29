"""Evidencias heurísticas controladas, incluyendo límites y casos legítimos."""

import json

from django.test import SimpleTestCase

from mallab.services.exceptions import AnalysisInputError
from mallab.services.heuristics import evaluate_heuristics


class HeuristicsTests(SimpleTestCase):
    def evaluate(self, **kwargs):
        arguments = {"file_size": 8192, "entropy": 0, "pe": {"is_pe": False}}
        arguments.update(kwargs)
        return evaluate_heuristics(**arguments)

    def ids(self, result):
        for finding in result["findings"]:
            for field in ("description", "evidence", "technical_rationale", "limitations"):
                self.assertTrue(finding[field])
        json.dumps(result)
        self.assertNotIn("score", result)
        self.assertNotIn("probability", result)
        return {finding["id"] for finding in result["findings"]}

    def test_plain_data_and_small_high_entropy_do_not_trigger(self):
        self.assertEqual(self.ids(self.evaluate()), set())
        self.assertEqual(self.ids(self.evaluate(file_size=256, entropy=8)), set())

    def test_global_entropy_is_an_observation_with_explicit_threshold(self):
        result = self.evaluate(entropy=7.5)
        self.assertEqual(self.ids(result), {"high_file_entropy"})
        self.assertEqual(result["parameters"]["entropy_threshold"], 7.5)
        self.assertEqual(self.ids(self.evaluate(entropy=7.49)), set())
        self.assertEqual(self.ids(self.evaluate(entropy=7.5, entropy_threshold=7.8)), set())

    def test_sections_entrypoint_and_observed_size(self):
        pe = {"is_pe": True, "entry_point_rva": 20000, "sections": [{
            "name": ".text", "characteristics": 0xE0000020, "virtual_address": 4096,
            "virtual_size": 4096, "raw_offset": 512, "raw_size": 8192,
            "observed_size": 4096, "entropy": 8,
        }]}
        self.assertEqual(self.ids(self.evaluate(pe=pe)), {
            "writable_executable_section", "section_raw_out_of_bounds", "high_section_entropy",
            "entry_point_outside_executable_section",
        })
        pe["sections"][0].update(characteristics=0x60000020, raw_size=4096, observed_size=256)
        pe["entry_point_rva"] = 4096
        self.assertEqual(self.ids(self.evaluate(pe=pe)), set())

    def test_import_combination_requires_all_three_and_keeps_evidence(self):
        pe = {"is_pe": True, "imports": [{"dll": "KERNEL32.dll", "functions": [
            {"name": "VirtualAllocEx"}, {"name": "WriteProcessMemory"}, {"name": None, "ordinal": 3},
        ]}]}
        self.assertEqual(self.ids(self.evaluate(pe=pe)), set())
        pe["imports"][0]["functions"].append({"name": "CreateRemoteThread"})
        result = self.evaluate(pe=pe)
        self.assertEqual(self.ids(result), {"remote_process_memory_api_combination"})
        self.assertEqual(len(result["findings"][0]["evidence"]["imports"]), 3)

    def test_malformed_pe_and_warnings_are_observations(self):
        self.assertEqual(self.ids(self.evaluate(pe={"is_pe": False, "reason": "invalid_pe"})),
                         {"invalid_pe_structure"})
        self.assertEqual(self.ids(self.evaluate(pe={"is_pe": True, "warnings": ["truncated section"]})),
                         {"pe_parser_warnings"})

    def test_bad_configuration_is_rejected(self):
        for kwargs in ({"entropy_threshold": float("nan")}, {"entropy_threshold": 9},
                       {"min_entropy_bytes": 0}, {"min_entropy_bytes": True}):
            with self.assertRaises(AnalysisInputError):
                self.evaluate(**kwargs)
