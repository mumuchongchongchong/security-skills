import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = SKILL_ROOT / "scripts" / "audit_skill.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

SPEC = importlib.util.spec_from_file_location("audit_skill", SCRIPT_PATH)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


def fixture(name: str) -> Path:
    return FIXTURES / name


def audit(name: str, limits=None):
    return AUDIT.audit_directory(fixture(name), limits=limits)


def rule_ids(report):
    return {finding["rule_id"] for finding in report["findings"]}


def capability_names(report):
    return {
        capability["name"]
        for capability in report["capability_manifest"]["capabilities"]
    }


class AuditSkillTests(unittest.TestCase):
    def test_benign_local_skill_is_allow(self):
        report = audit("benign-local-skill")
        self.assertEqual("ALLOW", report["scanner_verdict"])
        self.assertEqual("complete", report["coverage"]["status"])
        self.assertEqual([], report["findings"])

    def test_declared_network_skill_is_not_blocked_as_malicious(self):
        report = audit("declared-network-skill")
        self.assertEqual("REVIEW", report["scanner_verdict"])
        self.assertNotIn("ASC-004", rule_ids(report))
        self.assertTrue(report["declaration_analysis"]["flags"]["network_declared"])
        self.assertIn("network.download", capability_names(report))

    def test_declared_network_endpoint_and_boundary_are_reported(self):
        report = audit("declared-network-skill")
        endpoints = report["capability_manifest"]["external_endpoints"]
        self.assertTrue(any(item["domain"] == "api.example.invalid" for item in endpoints))
        self.assertTrue(report["declaration_analysis"]["permission_boundaries"])

    def test_offline_claim_and_network_capability_mismatch(self):
        report = audit("exfiltration-skill")
        self.assertIn("ASC-012", rule_ids(report))
        self.assertTrue(report["declaration_analysis"]["mismatches"])

    def test_exfiltration_chain_blocks(self):
        report = audit("exfiltration-skill")
        self.assertEqual("BLOCK", report["scanner_verdict"])
        self.assertIn("ASC-006", rule_ids(report))
        self.assertTrue(any(item["id"] == "ASC-C01" for item in report["correlations"]))

    def test_download_execute_chain_blocks(self):
        report = audit("download-execute-skill")
        self.assertEqual("BLOCK", report["scanner_verdict"])
        self.assertTrue(any(item["id"] == "ASC-C02" for item in report["correlations"]))
        self.assertIn("ASC-007", rule_ids(report))

    def test_poisoned_reference_is_detected_as_untrusted_text(self):
        report = audit("poisoned-reference-skill")
        self.assertIn("ASC-001", rule_ids(report))
        self.assertIn("ASC-013", rule_ids(report))
        paths = {
            item["path"]
            for finding in report["findings"]
            for item in finding["evidence"]
        }
        self.assertIn("references/note.md", paths)

    def test_hidden_unicode_codepoints_are_detected_without_raw_bidi_output(self):
        report = audit("hidden-unicode-skill")
        rendered = AUDIT.render_json(report)
        self.assertIn("ASC-002", rule_ids(report))
        self.assertIn("U+202E", rendered)
        self.assertIn("U+200B", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertNotIn("\u200b", rendered)

    def test_disguised_binary_header_is_detected(self):
        report = audit("disguised-binary-skill")
        self.assertIn("ASC-010", rule_ids(report))
        self.assertEqual("BLOCK", report["scanner_verdict"])
        self.assertTrue(any(
            item["id"] == "ASC-C05" for item in report["correlations"]
        ))
        entry = next(
            item for item in report["capability_manifest"]["files"]
            if item["path"] == "references/manual.md"
        )
        self.assertEqual("PE/MZ", entry["header_type"])
        self.assertFalse(entry["extension_matches_header"])

    def test_destructive_and_persistence_behavior_is_detected(self):
        report = audit("destructive-skill")
        self.assertIn("ASC-008", rule_ids(report))
        capabilities = capability_names(report)
        self.assertIn("filesystem.delete", capabilities)
        self.assertIn("system.persistence", capabilities)

    def test_file_count_limit_forces_inconclusive(self):
        report = audit(
            "benign-local-skill",
            AUDIT.Limits(max_files=1),
        )
        self.assertEqual("INCONCLUSIVE", report["scanner_verdict"])
        self.assertTrue(report["coverage"]["discovery_truncated"])

    def test_file_size_limit_forces_inconclusive(self):
        report = audit(
            "benign-local-skill",
            AUDIT.Limits(max_file_bytes=16),
        )
        self.assertEqual("INCONCLUSIVE", report["scanner_verdict"])
        self.assertTrue(any(
            item["kind"] == "max_file_bytes_reached"
            for item in report["limitations"]
        ))

    def test_total_size_limit_forces_inconclusive(self):
        report = audit(
            "benign-local-skill",
            AUDIT.Limits(max_total_bytes=32),
        )
        self.assertEqual("INCONCLUSIVE", report["scanner_verdict"])
        self.assertTrue(any(
            item["kind"] == "max_total_bytes_reached"
            for item in report["limitations"]
        ))

    def test_python_syntax_error_does_not_crash(self):
        report = audit("malformed-skill")
        self.assertEqual("INCONCLUSIVE", report["scanner_verdict"])
        self.assertTrue(any(
            item["kind"] == "python_parse_error"
            for item in report["limitations"]
        ))

    def test_target_script_is_never_executed(self):
        marker = fixture("exfiltration-skill") / "scripts" / "marker-created.txt"
        self.assertFalse(marker.exists())
        audit("exfiltration-skill")
        self.assertFalse(marker.exists())

    def test_report_does_not_contain_target_absolute_path(self):
        target = fixture("exfiltration-skill").resolve()
        report = audit("exfiltration-skill")
        serialized = AUDIT.render_json(report)
        self.assertNotIn(str(target), serialized)
        self.assertNotIn(str(target.parent), serialized)

    def test_sensitive_values_are_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "synthetic-redaction-skill"
            root.mkdir()
            (root / "SKILL.md").write_text(
                "---\nname: synthetic-redaction-skill\n"
                "description: Inspect local text.\n---\n",
                encoding="utf-8",
            )
            secret = "synthetic-secret-value-0000"
            (root / "sample.py").write_text(
                'endpoint = "https://collector.example.invalid/?token='
                + secret + '"\n',
                encoding="utf-8",
            )
            report = AUDIT.audit_directory(root)
            rendered = AUDIT.render_json(report)
            self.assertNotIn(secret, rendered)
            self.assertIn("[REDACTED]", rendered)

    def test_repeated_scan_has_stable_report(self):
        first = audit("declared-network-skill")
        second = audit("declared-network-skill")
        self.assertEqual(first, second)
        self.assertEqual(AUDIT.render_markdown(first), AUDIT.render_markdown(second))

    def test_missing_skill_md_is_not_allow(self):
        report = audit("malformed-skill")
        self.assertNotEqual("ALLOW", report["scanner_verdict"])
        self.assertIn("ASC-012", rule_ids(report))
        self.assertFalse(report["target"]["skill_md_present"])

    def test_missing_target_returns_exit_code_three(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code = AUDIT.main([str(FIXTURES / "does-not-exist")])
        self.assertEqual(3, code)

    def test_json_and_markdown_reports_are_generated(self):
        with tempfile.TemporaryDirectory() as temp:
            json_path = Path(temp) / "audit.json"
            markdown_path = Path(temp) / "audit.md"
            code = AUDIT.main([
                str(fixture("benign-local-skill")),
                "--json-out", str(json_path),
                "--markdown-out", str(markdown_path),
            ])
            self.assertEqual(0, code)
            self.assertEqual("1.0", json.loads(json_path.read_text(encoding="utf-8"))["schema_version"])
            markdown = markdown_path.read_text(encoding="utf-8")
            for heading in range(1, 10):
                self.assertIn(f"## {heading}.", markdown)

    def test_reports_cannot_be_written_inside_target(self):
        target = fixture("benign-local-skill")
        output = target / "audit.json"
        self.assertFalse(output.exists())
        with contextlib.redirect_stderr(io.StringIO()):
            code = AUDIT.main([
                str(target), "--json-out", str(output),
            ])
        self.assertEqual(3, code)
        self.assertFalse(output.exists())

    def test_finding_contract_is_complete(self):
        report = audit("exfiltration-skill")
        required = {
            "rule_id", "title", "severity", "confidence", "category",
            "evidence", "explanation", "remediation",
        }
        for finding in report["findings"]:
            self.assertTrue(required.issubset(finding))
            self.assertIn(
                finding["severity"],
                {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
            )
            self.assertIn(finding["confidence"], {"LOW", "MEDIUM", "HIGH"})
            self.assertTrue(finding["evidence"])
            for item in finding["evidence"]:
                self.assertIn("path", item)
                self.assertIn("snippet", item)
                self.assertIn("detection", item)
                self.assertTrue(
                    item["line"] is not None or item["byte_offset"] is not None
                )

    def test_document_command_examples_do_not_create_runtime_capabilities(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "synthetic-doc-skill"
            root.mkdir()
            (root / "SKILL.md").write_text(
                "---\nname: synthetic-doc-skill\n"
                "description: Explain local command syntax.\n---\n\n"
                "Example only: curl https://docs.example.invalid/file ; rm -rf sample\n",
                encoding="utf-8",
            )
            report = AUDIT.audit_directory(root)
            self.assertNotIn("network.download", capability_names(report))
            self.assertNotIn("filesystem.delete", capability_names(report))
            self.assertEqual("ALLOW", report["scanner_verdict"])

    def test_symlink_is_recorded_and_not_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "synthetic-link-skill"
            root.mkdir()
            (root / "SKILL.md").write_text(
                "---\nname: synthetic-link-skill\n"
                "description: Inspect local text.\n---\n",
                encoding="utf-8",
            )
            outside = Path(temp) / "outside-secret.txt"
            outside_value = "synthetic-outside-value-never-read"
            outside.write_text(outside_value, encoding="utf-8")
            link = root / "linked.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("Symbolic links are unavailable for this user.")
            report = AUDIT.audit_directory(root)
            rendered = AUDIT.render_json(report)
            self.assertEqual(1, report["coverage"]["symlinks_not_followed"])
            self.assertIn("ASC-009", rule_ids(report))
            self.assertNotIn(outside_value, rendered)

    def test_limits_cannot_be_disabled_or_raised(self):
        for arguments in (
            {"max_files": 0},
            {"max_files": AUDIT.DEFAULT_MAX_FILES + 1},
            {"max_file_bytes": AUDIT.DEFAULT_MAX_FILE_BYTES + 1},
            {"max_total_bytes": AUDIT.DEFAULT_MAX_TOTAL_BYTES + 1},
        ):
            with self.assertRaises(ValueError):
                AUDIT.Limits(**arguments)

    def test_block_is_preserved_when_coverage_is_incomplete(self):
        report = audit(
            "exfiltration-skill",
            AUDIT.Limits(max_file_bytes=4096, max_total_bytes=4096),
        )
        self.assertEqual("BLOCK", report["scanner_verdict"])
        self.assertTrue(report["correlations"])


if __name__ == "__main__":
    unittest.main()
