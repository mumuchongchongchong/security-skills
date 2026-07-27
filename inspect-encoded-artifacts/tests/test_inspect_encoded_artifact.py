from __future__ import annotations

import base64
import contextlib
import gzip
import io
import json
import sys
import unittest
import urllib.parse
import zlib
from pathlib import Path


SKILL_DIR = Path(__file__).resolve().parents[1]
SCRIPT_DIR = SKILL_DIR / "scripts"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(SCRIPT_DIR))

import inspect_encoded_artifact as artifact  # noqa: E402


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES_DIR / name).read_bytes()


def inspect_text(
    value: str,
    limits: artifact.Limits | None = None,
    decoders: tuple[artifact.DecoderFunction, ...] | None = None,
) -> dict[str, object]:
    return artifact.inspect_bytes(
        value.encode("utf-8"),
        limits=limits,
        decoders=decoders,
    )


def decoder_names(report: dict[str, object]) -> list[str]:
    records = report["transformation_chain"]
    assert isinstance(records, list)
    return [record["decoder"] for record in records]


class InspectEncodedArtifactTests(unittest.TestCase):
    def test_plain_text_is_not_misdecoded(self) -> None:
        report = artifact.inspect_bytes(
            fixture_bytes("plain_text.txt")
        )
        self.assertEqual(report["decode_status"], "NO_ENCODING_FOUND")
        self.assertEqual(report["transformation_chain"], [])

    def test_single_layer_base64(self) -> None:
        report = artifact.inspect_bytes(
            fixture_bytes("base64_text.txt")
        )
        self.assertEqual(report["decode_status"], "DECODED")
        self.assertIn("base64", decoder_names(report))
        previews = json.dumps(report["redacted_previews"])
        self.assertIn("Hello, Security!", previews)

    def test_base64url(self) -> None:
        report = inspect_text("SGVsbG8g5Li-")
        self.assertEqual(report["decode_status"], "DECODED")
        self.assertIn("base64url", decoder_names(report))
        self.assertIn("Hello", json.dumps(report["redacted_previews"]))

    def test_url_percent_encoding(self) -> None:
        report = inspect_text("Hello%2C%20Security%21")
        self.assertEqual(report["decode_status"], "DECODED")
        self.assertIn("url_percent", decoder_names(report))

    def test_hex_encoding(self) -> None:
        report = inspect_text("48656c6c6f2c20536563757269747921")
        self.assertEqual(report["decode_status"], "DECODED")
        self.assertIn("hex", decoder_names(report))

    def test_byte_escape_encoding(self) -> None:
        report = inspect_text(r"Hello\x2c\x20Security\x21")
        self.assertEqual(report["decode_status"], "DECODED")
        self.assertIn("byte_escape", decoder_names(report))

    def test_unicode_escape_encoding(self) -> None:
        report = inspect_text(r"Hello\u002c\u0020Security\u0021")
        self.assertEqual(report["decode_status"], "DECODED")
        self.assertIn("unicode_escape", decoder_names(report))

    def test_html_entity_encoding(self) -> None:
        report = inspect_text("Hello &amp; Security")
        self.assertEqual(report["decode_status"], "DECODED")
        self.assertIn("html_entity", decoder_names(report))

    def test_two_layer_nested_url_and_base64(self) -> None:
        report = artifact.inspect_bytes(
            fixture_bytes("nested_url_base64.txt")
        )
        names = decoder_names(report)
        self.assertEqual(report["decode_status"], "DECODED")
        self.assertIn("url_percent", names)
        self.assertIn("base64", names)
        self.assertGreaterEqual(
            max(
                record["layer"]
                for record in report["transformation_chain"]
            ),
            2,
        )

    def test_jwt_is_parsed_without_signature_claim(self) -> None:
        report = artifact.inspect_bytes(
            fixture_bytes("sample_jwt.txt")
        )
        jwt_records = [
            record
            for record in report["transformation_chain"]
            if record["decoder"] == "jwt_header_payload"
        ]
        self.assertEqual(len(jwt_records), 1)
        self.assertIn(
            "signature_not_verified",
            jwt_records[0]["warnings"],
        )
        rendered = artifact.render_json(report)
        self.assertIn("signature_not_verified", rendered)
        self.assertNotIn("synthetic-token-value", rendered)
        self.assertNotIn("synthetic-password", rendered)
        finding_types = {
            finding["type"] for finding in report["sensitive_findings"]
        }
        self.assertIn("jwt", finding_types)
        self.assertIn("email", finding_types)
        self.assertIn("token", finding_types)
        self.assertIn("password", finding_types)

    def test_base64_then_gzip(self) -> None:
        report = artifact.inspect_bytes(
            fixture_bytes("gzip_base64.txt")
        )
        names = decoder_names(report)
        self.assertEqual(report["decode_status"], "DECODED")
        self.assertIn("base64", names)
        self.assertIn("gzip", names)
        self.assertIn(
            "Hello compressed security!",
            json.dumps(report["redacted_previews"]),
        )

    def test_base64_then_zlib(self) -> None:
        compressed = zlib.compress(b"Hello zlib security!")
        encoded = base64.b64encode(compressed).decode("ascii")
        report = inspect_text(encoded)
        self.assertEqual(report["decode_status"], "DECODED")
        self.assertIn("zlib", decoder_names(report))

    def test_pe_file_header_is_reported_only(self) -> None:
        report = artifact.inspect_bytes(
            fixture_bytes("pe_header_hex.txt")
        )
        signatures = {
            item["signature"] for item in report["file_signatures"]
        }
        self.assertIn("MZ", signatures)
        self.assertIn("MZ/PE", json.dumps(report["final_content_types"]))
        self.assertIn(
            "preview suppressed",
            json.dumps(report["redacted_previews"]),
        )

    def test_suspicious_powershell_is_a_risk_signal(self) -> None:
        report = artifact.inspect_bytes(
            fixture_bytes("suspicious_command_base64.txt")
        )
        indicators = {
            signal["indicator"] for signal in report["risk_signals"]
        }
        self.assertEqual(
            report["risk_status"],
            "HIGH_RISK_INDICATORS",
        )
        self.assertIn("powershell", indicators)
        self.assertIn("invoke_expression", indicators)
        self.assertTrue(
            all(
                signal["assessment"] == "risk_signal_only"
                for signal in report["risk_signals"]
            )
        )

    def test_encoded_prompt_injection_is_reported_not_obeyed(self) -> None:
        report = artifact.inspect_bytes(
            fixture_bytes("prompt_injection_base64.txt")
        )
        indicators = {
            signal["indicator"] for signal in report["risk_signals"]
        }
        self.assertIn("ignore_previous_instructions", indicators)
        self.assertIn("reveal_system_prompt", indicators)
        self.assertIn("call_this_tool", indicators)
        self.assertIn("bypass_policy", indicators)
        self.assertEqual(report["decode_status"], "DECODED")
        self.assertEqual(
            report["risk_status"],
            "HIGH_RISK_INDICATORS",
        )

    def test_tokens_and_passwords_are_redacted(self) -> None:
        sample = (
            "Authorization: Bearer synthetic-token-12345\n"
            "api_key=synthetic-api-key-12345\n"
            "password=synthetic-password"
        )
        report = inspect_text(sample)
        rendered = artifact.render_json(report)
        self.assertNotIn("synthetic-token-12345", rendered)
        self.assertNotIn("synthetic-api-key-12345", rendered)
        self.assertNotIn("synthetic-password", rendered)
        finding_types = {
            finding["type"] for finding in report["sensitive_findings"]
        }
        self.assertIn("authorization_header", finding_types)
        self.assertIn("bearer_token", finding_types)
        self.assertIn("api_key", finding_types)
        self.assertIn("password", finding_types)

    def test_url_token_is_redacted_in_indicators(self) -> None:
        sample = (
            "https://example.invalid/download?"
            "token=synthetic-url-token-value"
        )
        report = inspect_text(sample)
        rendered = artifact.render_json(report)
        self.assertNotIn("synthetic-url-token-value", rendered)
        self.assertIn("[REDACTED:token:", rendered)

    def test_private_key_header_is_redacted(self) -> None:
        sample = "-----BEGIN SYNTHETIC PRIVATE KEY-----"
        report = inspect_text(sample)
        rendered = artifact.render_json(report)
        self.assertNotIn(sample, rendered)
        finding_types = {
            finding["type"] for finding in report["sensitive_findings"]
        }
        self.assertIn("private_key_header", finding_types)

    def test_invalid_base64_is_not_decoded(self) -> None:
        report = artifact.inspect_bytes(
            fixture_bytes("malformed_encoding.txt")
        )
        self.assertEqual(report["decode_status"], "NO_ENCODING_FOUND")
        self.assertNotIn("base64", decoder_names(report))

    def test_base64_like_word_is_low_candidate_only(self) -> None:
        report = artifact.inspect_bytes(
            fixture_bytes("fake_base64.txt")
        )
        self.assertEqual(report["decode_status"], "NO_ENCODING_FOUND")
        records = report["transformation_chain"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["confidence"], "low")
        self.assertTrue(records[0]["candidate"])
        self.assertIn(
            "low_confidence_candidate_not_recursed",
            records[0]["warnings"],
        )

    def test_maximum_recursion_depth(self) -> None:
        value = b"synthetic terminal text"
        for _ in range(5):
            value = base64.b64encode(value)
        limits = artifact.Limits(max_depth=2)
        report = artifact.inspect_bytes(value, limits=limits)
        self.assertEqual(report["decode_status"], "LIMIT_REACHED")
        names = {
            item["name"] for item in report["limits"]["triggered"]
        }
        self.assertIn("max_depth", names)
        self.assertLessEqual(
            max(
                record["layer"]
                for record in report["transformation_chain"]
            ),
            2,
        )

    def test_maximum_output_size(self) -> None:
        encoded = base64.b64encode(b"A" * 128)
        limits = artifact.Limits(max_output_bytes=32)
        report = artifact.inspect_bytes(encoded, limits=limits)
        self.assertEqual(report["decode_status"], "LIMIT_REACHED")
        names = {
            item["name"] for item in report["limits"]["triggered"]
        }
        self.assertIn("max_output_bytes", names)

    def test_decompression_ratio_limit(self) -> None:
        compressed = gzip.compress(b"A" * 4096, mtime=0)
        encoded = base64.b64encode(compressed)
        limits = artifact.Limits(max_decompression_ratio=2)
        report = artifact.inspect_bytes(encoded, limits=limits)
        self.assertEqual(report["decode_status"], "LIMIT_REACHED")
        names = {
            item["name"] for item in report["limits"]["triggered"]
        }
        self.assertIn("max_decompression_ratio", names)

    def test_hash_cycle_stops_chain(self) -> None:
        def same_bytes(
            data: bytes,
            _limits: artifact.Limits,
        ) -> list[artifact.DecodeCandidate]:
            return [
                artifact.DecodeCandidate(
                    decoder="synthetic_cycle_decoder",
                    output=data,
                    confidence="high",
                )
            ]

        report = inspect_text(
            "cycle source",
            decoders=(same_bytes,),
        )
        self.assertEqual(len(report["transformation_chain"]), 1)
        self.assertIn(
            "hash_cycle_detected_chain_stopped",
            report["transformation_chain"][0]["warnings"],
        )

    def test_json_field_paths_are_preserved_and_sensitive_fields_masked(
        self,
    ) -> None:
        sample = {
            "event": {
                "payload": "SGVsbG8sIFNlY3VyaXR5IQ==",
                "password": "synthetic-json-password",
            }
        }
        raw = json.dumps(sample).encode("utf-8")
        report = artifact.inspect_bytes(raw, input_kind="json")
        paths = {
            record["source_field"]
            for record in report["transformation_chain"]
        }
        self.assertIn("$.event.payload", paths)
        secret_paths = {
            finding["source_field"]
            for finding in report["sensitive_findings"]
        }
        self.assertIn("$.event.password", secret_paths)
        self.assertNotIn(
            "synthetic-json-password",
            artifact.render_json(report),
        )

    def test_jsonl_field_paths_are_preserved(self) -> None:
        raw = (
            b'{"payload":"SGVsbG8sIFNlY3VyaXR5IQ=="}\n'
            b'{"message":"plain synthetic event"}\n'
        )
        report = artifact.inspect_bytes(raw, input_kind="jsonl")
        paths = {
            record["source_field"]
            for record in report["transformation_chain"]
        }
        self.assertIn("$[line:1].payload", paths)
        self.assertEqual(report["input_summary"]["fields_inspected"], 2)

    def test_markdown_and_json_outputs_are_stable(self) -> None:
        report = artifact.inspect_bytes(
            fixture_bytes("base64_text.txt")
        )
        markdown_one = artifact.render_markdown(report)
        markdown_two = artifact.render_markdown(report)
        json_one = artifact.render_json(report)
        json_two = artifact.render_json(report)
        self.assertEqual(markdown_one, markdown_two)
        self.assertEqual(json_one, json_two)
        self.assertEqual(json.loads(json_one)["schema_version"], "1.0")
        for section in range(1, 12):
            self.assertIn(f"## {section}.", markdown_one)

    def test_binary_preview_escapes_control_bytes(self) -> None:
        preview = artifact.redacted_preview(b"MZ\x00\x01\x02", 100)
        self.assertIn(r"\x00", preview)
        self.assertNotIn("\x00", preview)

    def test_max_input_bytes(self) -> None:
        limits = artifact.Limits(max_input_bytes=8)
        report = artifact.inspect_bytes(b"A" * 9, limits=limits)
        self.assertEqual(report["decode_status"], "LIMIT_REACHED")
        self.assertTrue(report["input_summary"]["truncated"])
        self.assertIsNone(report["input_summary"]["input_sha256"])

    def test_partial_jsonl_reports_inconclusive(self) -> None:
        raw = b'{"message":"synthetic"}\n{broken-json}\n'
        report = artifact.inspect_bytes(raw, input_kind="jsonl")
        self.assertEqual(report["decode_status"], "PARTIAL")
        self.assertEqual(report["risk_status"], "INCONCLUSIVE")
        self.assertTrue(report["incomplete_analysis"])

    def test_cli_text_json_output(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = artifact.main(
                [
                    "--text",
                    "SGVsbG8sIFNlY3VyaXR5IQ==",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["decode_status"], "DECODED")

    def test_limits_cannot_be_disabled_or_raised(self) -> None:
        with self.assertRaises(ValueError):
            artifact.Limits(max_depth=0)
        with self.assertRaises(ValueError):
            artifact.Limits(
                max_output_bytes=artifact.DEFAULT_MAX_OUTPUT_BYTES + 1
            )

    def test_nested_url_fixture_is_synthetic(self) -> None:
        expected = urllib.parse.quote(
            base64.b64encode(b"Hello, nested!").decode("ascii"),
            safe="",
        )
        self.assertEqual(
            fixture_bytes("nested_url_base64.txt").decode().strip(),
            expected,
        )


if __name__ == "__main__":
    unittest.main()
