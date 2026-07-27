import importlib.util
import json
import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = SKILL_ROOT / "scripts" / "audit_trace.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

SPEC = importlib.util.spec_from_file_location("audit_trace", SCRIPT_PATH)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class AuditTraceTests(unittest.TestCase):
    def setUp(self):
        self.safe_policy = {
            "allowed_tools": ["read_file", "fetch_url"],
            "high_risk_tools": ["shell_command", "write_file"],
            "max_repeated_calls": 3,
        }

    def test_safe_trace_has_limited_no_findings_result(self):
        report = AUDIT.audit_content(fixture("safe_trace.jsonl"), self.safe_policy)
        self.assertEqual("NO_FINDINGS", report["status"])
        self.assertEqual([], report["findings"])
        self.assertEqual([], report["pending_evidence"])
        self.assertEqual(
            ["user_input", "model_plan", "tool_call", "tool_result", "final_answer"],
            [event["event_type"] for event in report["timeline"]],
        )

    def test_unauthorized_high_risk_tool_is_reported(self):
        report = AUDIT.audit_content(
            fixture("unauthorized_tool.jsonl"), self.safe_policy
        )
        rules = {finding["rule_id"] for finding in report["findings"]}
        self.assertEqual("RISK_DETECTED", report["status"])
        self.assertIn("ATR-002", rules)
        self.assertIn("ATR-004", rules)

    def test_injection_and_secret_are_detected_without_secret_copy(self):
        report = AUDIT.audit_content(
            fixture("injection_and_secret.jsonl"), self.safe_policy
        )
        serialized = json.dumps(report, ensure_ascii=False)
        rules = {finding["rule_id"] for finding in report["findings"]}
        self.assertIn("ATR-001", rules)
        self.assertIn("ATR-003", rules)
        self.assertNotIn("EXAMPLE_REDACTED_VALUE", serialized)
        self.assertIn("masked", serialized)

    def test_sensitive_field_value_is_masked_in_timeline_and_findings(self):
        trace = "\n".join([
            json.dumps({"type": "user_input", "content": "Inspect."}),
            json.dumps({
                "type": "tool_call", "event_id": "call-1", "call_id": "c-1",
                "tool_name": "read_file",
                "arguments": {"path": "x", "password": "hunter2"},
            }),
            json.dumps({
                "type": "tool_result", "event_id": "result-1", "call_id": "c-1",
                "status": "success", "result": "ok",
            }),
            json.dumps({
                "type": "final_answer", "event_id": "final-1",
                "content": {"password": "hunter2"},
            }),
        ])
        report = AUDIT.audit_content(trace, self.safe_policy)
        self.assertNotIn("hunter2", json.dumps(report, ensure_ascii=False))
        self.assertTrue(any(
            finding["rule_id"] == "ATR-003" for finding in report["findings"]
        ))

    def test_unknown_structure_is_inconclusive(self):
        report = AUDIT.audit_content('{"unexpected": "shape"}', self.safe_policy)
        self.assertEqual("INCONCLUSIVE", report["status"])
        self.assertTrue(any(
            item["issue"] == "unrecognized_event_structures"
            for item in report["pending_evidence"]
        ))

    def test_repeated_calls_over_threshold_trigger_atr_005(self):
        lines = [json.dumps({"type": "user_input", "content": "Check once."})]
        for index in range(3):
            lines.extend([
                json.dumps({
                    "type": "tool_call",
                    "event_id": f"call-{index}",
                    "call_id": f"c-{index}",
                    "tool_name": "read_file",
                    "arguments": {"path": "sample.txt"},
                }),
                json.dumps({
                    "type": "tool_result",
                    "event_id": f"result-{index}",
                    "call_id": f"c-{index}",
                    "tool_name": "read_file",
                    "status": "success",
                    "result": "ok",
                }),
            ])
        lines.append(json.dumps({"type": "final_answer", "content": "Three reads."}))
        policy = dict(self.safe_policy, max_repeated_calls=2)
        report = AUDIT.audit_content("\n".join(lines), policy)
        self.assertTrue(any(
            finding["rule_id"] == "ATR-005" for finding in report["findings"]
        ))

    def test_failed_evidence_and_certainty_trigger_atr_006(self):
        trace = "\n".join([
            json.dumps({"type": "user_input", "content": "Apply change."}),
            json.dumps({
                "type": "tool_call", "event_id": "call-1", "call_id": "c-1",
                "tool_name": "write_file",
                "arguments": {"path": "x", "content": "y"}, "approved": True,
            }),
            json.dumps({
                "type": "tool_result", "event_id": "result-1", "call_id": "c-1",
                "status": "failed", "error": "permission denied",
            }),
            json.dumps({
                "type": "final_answer", "event_id": "final-1", "content": "处置完成。",
            }),
        ])
        policy = dict(self.safe_policy, allowed_tools=["write_file"])
        report = AUDIT.audit_content(trace, policy)
        self.assertTrue(any(
            finding["rule_id"] == "ATR-006" for finding in report["findings"]
        ))

    def test_markdown_contains_required_sections_and_finding_fields(self):
        report = AUDIT.audit_content(
            fixture("unauthorized_tool.jsonl"), self.safe_policy
        )
        markdown = AUDIT.render_markdown(report)
        for heading in (
            "## Risk Summary", "## Event Timeline",
            "## Risk Findings", "## Pending Evidence",
        ):
            self.assertIn(heading, markdown)
        for field in (
            "Rule ID", "Severity", "Event ID",
            "Evidence", "Reason", "Recommendation",
        ):
            self.assertIn(field, markdown)

    def test_pasted_log_is_supported_without_execution(self):
        pasted = "\n".join([
            "USER: Inspect the trace.",
            "PLAN: Read the supplied data.",
            'TOOL_CALL: name=read_file args={"path":"x"}',
            "TOOL_RESULT: ok",
            "FINAL: Evidence reviewed.",
        ])
        report = AUDIT.audit_content(pasted, self.safe_policy)
        self.assertEqual("pasted", report["summary"]["input_format"])
        self.assertEqual(5, report["summary"]["recognized_events"])

    def test_aggregated_json_reconstructs_calls_and_results(self):
        source = json.dumps({
            "user_input": "Inspect.",
            "model_plan": "Read only.",
            "tool_calls": [{
                "event_id": "call-1", "call_id": "c-1",
                "tool_name": "read_file", "arguments": {"path": "x"},
            }],
            "tool_results": [{
                "event_id": "result-1", "call_id": "c-1",
                "status": "success", "result": "ok",
            }],
            "final_answer": "One result.",
        })
        report = AUDIT.audit_content(source, self.safe_policy)
        self.assertEqual("NO_FINDINGS", report["status"])
        self.assertEqual(5, report["summary"]["recognized_events"])


if __name__ == "__main__":
    unittest.main()
