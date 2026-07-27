#!/usr/bin/env python3
"""Offline, bounded inspection of encoded artifacts.

Decoded content is treated only as untrusted data. This module never executes,
imports, opens, downloads, or writes decoded content.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import html
import ipaddress
import json
import re
import sys
import urllib.parse
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence


SCHEMA_VERSION = "1.0"
DEFAULT_MAX_DEPTH = 4
DEFAULT_MAX_INPUT_BYTES = 1024 * 1024
DEFAULT_MAX_OUTPUT_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_CANDIDATES = 100
DEFAULT_MAX_PREVIEW_CHARS = 1000
DEFAULT_MAX_DECOMPRESSION_RATIO = 100

DECODE_STATUSES = {
    "DECODED",
    "PARTIAL",
    "NO_ENCODING_FOUND",
    "LIMIT_REACHED",
    "ERROR",
}
RISK_STATUSES = {
    "NO_HIGH_RISK_INDICATORS",
    "REVIEW",
    "HIGH_RISK_INDICATORS",
    "INCONCLUSIVE",
}
NO_RISK_CAVEAT = (
    "NO_HIGH_RISK_INDICATORS means only that the current rules found no "
    "high-risk signal; it does not mean the content is safe."
)

ASCII_WHITESPACE_RE = re.compile(r"[\t\n\r ]+")
BASE64_STANDARD_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
BASE64_URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
HEX_RE = re.compile(r"^(?:0x)?[0-9A-Fa-f]+$")
BYTE_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9A-Fa-f]{4})")
HTML_ENTITY_RE = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
JWT_FULL_RE = re.compile(
    r"^[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*$"
)
JWT_SEARCH_RE = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{0,})(?![A-Za-z0-9_-])"
)
SENSITIVE_FIELD_RE = re.compile(
    r"(?:api[_-]?key|access[_-]?key|authorization|bearer|cookie|email|"
    r"pass(?:word|wd)?|secret|session|token)",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
IPV4_CANDIDATE_RE = re.compile(
    r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"
)
HASH_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
)

PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]{0,48}PRIVATE KEY-----.*?"
    r"-----END [A-Z0-9 ]{0,48}PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
PRIVATE_KEY_HEADER_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]{0,48}PRIVATE KEY-----",
    re.IGNORECASE,
)
AUTHORIZATION_RE = re.compile(
    r"(?im)\bAuthorization\s*:\s*([^\r\n]{1,4096})"
)
BEARER_RE = re.compile(
    r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{8,4096})"
)
COOKIE_RE = re.compile(
    r"(?im)\b(?:Cookie|Set-Cookie)\s*:\s*([^\r\n]{1,4096})"
)
PASSWORD_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"']?([^\"'\s,;}{]{3,4096})"
)
API_KEY_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?key|secret[_-]?key)\s*[:=]\s*"
    r"[\"']?([A-Za-z0-9._~+/=-]{8,4096})"
)
TOKEN_VALUE_RE = re.compile(
    r"(?i)\b(?:access[_-]?token|refresh[_-]?token|session[_-]?id|token|secret)"
    r"\s*[:=]\s*[\"']?([^\"'\s,;&}{]{4,4096})"
)
AWS_ACCESS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b")
GOOGLE_API_KEY_RE = re.compile(r"\b(AIza[0-9A-Za-z_-]{30,40})\b")
GITHUB_TOKEN_RE = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,255})\b")
SLACK_TOKEN_RE = re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,255})\b")
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63})(?![A-Za-z0-9._%+-])"
)

POWERSHELL_RE = re.compile(r"\bpowershell(?:\.exe)?\b", re.IGNORECASE)
POWERSHELL_ENC_RE = re.compile(r"(?<![A-Za-z0-9])-(?:enc|encodedcommand)\b", re.IGNORECASE)
FROM_BASE64_RE = re.compile(r"\bFromBase64String\b", re.IGNORECASE)
INVOKE_EXPRESSION_RE = re.compile(r"\b(?:Invoke-Expression|IEX)\b", re.IGNORECASE)
CMD_EXE_RE = re.compile(r"\bcmd\.exe\b", re.IGNORECASE)
CERTUTIL_RE = re.compile(r"\bcertutil(?:\.exe)?\b", re.IGNORECASE)
BITSADMIN_RE = re.compile(r"\bbitsadmin(?:\.exe)?\b", re.IGNORECASE)
RUNDLL32_RE = re.compile(r"\brundll32(?:\.exe)?\b", re.IGNORECASE)
REGSVR32_RE = re.compile(r"\bregsvr32(?:\.exe)?\b", re.IGNORECASE)
BIN_SHELL_RE = re.compile(r"/bin/(?:ba)?sh\b", re.IGNORECASE)
CURL_RE = re.compile(r"\bcurl\b", re.IGNORECASE)
WGET_RE = re.compile(r"\bwget\b", re.IGNORECASE)
CHMOD_RE = re.compile(r"\bchmod\b", re.IGNORECASE)
NOHUP_RE = re.compile(r"\bnohup\b", re.IGNORECASE)
DYNAMIC_EVAL_RE = re.compile(r"\beval\s*\(", re.IGNORECASE)
DYNAMIC_EXEC_RE = re.compile(r"\bexec\s*\(", re.IGNORECASE)
RUNTIME_EXEC_RE = re.compile(r"\bRuntime\s*\.\s*exec\b", re.IGNORECASE)
PROCESS_BUILDER_RE = re.compile(r"\bProcessBuilder\b", re.IGNORECASE)
DOWNLOAD_EXEC_CHAIN_RE = re.compile(
    r"(?:curl|wget|certutil|bitsadmin)[^\r\n]{0,300}"
    r"(?:&&|\|\||[|;])[^\r\n]{0,120}"
    r"(?:powershell|cmd(?:\.exe)?|/bin/(?:ba)?sh|chmod|rundll32)",
    re.IGNORECASE,
)
IGNORE_INSTRUCTIONS_RE = re.compile(
    r"\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions?\b",
    re.IGNORECASE,
)
REVEAL_PROMPT_RE = re.compile(
    r"\b(?:reveal|show|print|expose)\s+(?:the\s+)?(?:system|developer)\s+prompt\b",
    re.IGNORECASE,
)
CALL_TOOL_RE = re.compile(
    r"\b(?:call|invoke|use|run)\s+(?:this|the|a)\s+tool\b",
    re.IGNORECASE,
)
BYPASS_POLICY_RE = re.compile(
    r"\b(?:bypass|evade|disable|override)\s+(?:the\s+)?(?:policy|policies|guardrails?|safety)\b",
    re.IGNORECASE,
)
OVERRIDE_CONTROL_RE = re.compile(
    r"\b(?:override|replace)\s+(?:the\s+)?(?:system|developer)\s+(?:message|instructions?|prompt)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Limits:
    max_depth: int = DEFAULT_MAX_DEPTH
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    max_candidates: int = DEFAULT_MAX_CANDIDATES
    max_preview_chars: int = DEFAULT_MAX_PREVIEW_CHARS
    max_decompression_ratio: int = DEFAULT_MAX_DECOMPRESSION_RATIO

    def __post_init__(self) -> None:
        values = self.as_dict()
        defaults = {
            "max_depth": DEFAULT_MAX_DEPTH,
            "max_input_bytes": DEFAULT_MAX_INPUT_BYTES,
            "max_output_bytes": DEFAULT_MAX_OUTPUT_BYTES,
            "max_candidates": DEFAULT_MAX_CANDIDATES,
            "max_preview_chars": DEFAULT_MAX_PREVIEW_CHARS,
            "max_decompression_ratio": DEFAULT_MAX_DECOMPRESSION_RATIO,
        }
        for name, value in values.items():
            if value < 1 or value > defaults[name]:
                raise ValueError(
                    f"{name} must be between 1 and {defaults[name]}"
                )

    def as_dict(self) -> dict[str, int]:
        return {
            "max_depth": self.max_depth,
            "max_input_bytes": self.max_input_bytes,
            "max_output_bytes": self.max_output_bytes,
            "max_candidates": self.max_candidates,
            "max_preview_chars": self.max_preview_chars,
            "max_decompression_ratio": self.max_decompression_ratio,
        }


@dataclass
class DecodeCandidate:
    decoder: str
    output: bytes | None
    confidence: str
    warnings: list[str] = field(default_factory=list)
    limit_name: str | None = None
    output_size_hint: int | None = None


@dataclass(frozen=True)
class SourceValue:
    source_field: str
    data: bytes
    sensitive_type: str | None = None


@dataclass(frozen=True)
class Node:
    source_field: str
    data: bytes
    layer: int
    seen_hashes: frozenset[str]
    chain_id: str
    confidence: str
    sensitive_type: str | None


@dataclass(frozen=True)
class SecretRule:
    secret_type: str
    pattern: re.Pattern[str]
    value_group: int


@dataclass(frozen=True)
class RiskRule:
    category: str
    indicator: str
    severity: str
    pattern: re.Pattern[str]


class DecompressionLimitError(Exception):
    def __init__(self, limit_name: str, observed: int) -> None:
        super().__init__(limit_name)
        self.limit_name = limit_name
        self.observed = observed


DecoderFunction = Callable[[bytes, Limits], list[DecodeCandidate]]


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule("private_key", PRIVATE_KEY_BLOCK_RE, 0),
    SecretRule("private_key_header", PRIVATE_KEY_HEADER_RE, 0),
    SecretRule("authorization_header", AUTHORIZATION_RE, 1),
    SecretRule("bearer_token", BEARER_RE, 1),
    SecretRule("cookie", COOKIE_RE, 1),
    SecretRule("password", PASSWORD_RE, 1),
    SecretRule("api_key", API_KEY_RE, 1),
    SecretRule("token", TOKEN_VALUE_RE, 1),
    SecretRule("aws_access_key", AWS_ACCESS_KEY_RE, 1),
    SecretRule("google_api_key", GOOGLE_API_KEY_RE, 1),
    SecretRule("github_token", GITHUB_TOKEN_RE, 1),
    SecretRule("slack_token", SLACK_TOKEN_RE, 1),
    SecretRule("jwt", JWT_SEARCH_RE, 1),
    SecretRule("email", EMAIL_RE, 1),
)

RISK_RULES: tuple[RiskRule, ...] = (
    RiskRule("powershell", "powershell", "high", POWERSHELL_RE),
    RiskRule("powershell", "encoded_command_flag", "medium", POWERSHELL_ENC_RE),
    RiskRule("powershell", "from_base64_string", "medium", FROM_BASE64_RE),
    RiskRule("powershell", "invoke_expression", "high", INVOKE_EXPRESSION_RE),
    RiskRule("windows_command", "cmd.exe", "medium", CMD_EXE_RE),
    RiskRule("windows_command", "certutil", "high", CERTUTIL_RE),
    RiskRule("windows_command", "bitsadmin", "high", BITSADMIN_RE),
    RiskRule("windows_command", "rundll32", "high", RUNDLL32_RE),
    RiskRule("windows_command", "regsvr32", "high", REGSVR32_RE),
    RiskRule("linux_shell", "shell_path", "high", BIN_SHELL_RE),
    RiskRule("linux_shell", "curl", "medium", CURL_RE),
    RiskRule("linux_shell", "wget", "medium", WGET_RE),
    RiskRule("linux_shell", "chmod", "medium", CHMOD_RE),
    RiskRule("linux_shell", "nohup", "medium", NOHUP_RE),
    RiskRule("dynamic_execution", "eval", "high", DYNAMIC_EVAL_RE),
    RiskRule("dynamic_execution", "exec", "high", DYNAMIC_EXEC_RE),
    RiskRule("dynamic_execution", "runtime.exec", "high", RUNTIME_EXEC_RE),
    RiskRule("dynamic_execution", "process_builder", "high", PROCESS_BUILDER_RE),
    RiskRule("network_download", "http_url", "medium", URL_RE),
    RiskRule(
        "network_download",
        "download_then_execute_chain",
        "high",
        DOWNLOAD_EXEC_CHAIN_RE,
    ),
    RiskRule(
        "prompt_injection",
        "ignore_previous_instructions",
        "high",
        IGNORE_INSTRUCTIONS_RE,
    ),
    RiskRule(
        "prompt_injection",
        "reveal_system_prompt",
        "high",
        REVEAL_PROMPT_RE,
    ),
    RiskRule("prompt_injection", "call_this_tool", "high", CALL_TOOL_RE),
    RiskRule("prompt_injection", "bypass_policy", "high", BYPASS_POLICY_RE),
    RiskRule(
        "prompt_injection",
        "override_control_instructions",
        "high",
        OVERRIDE_CONTROL_RE,
    ),
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_utf8(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    text = decode_utf8(data)
    if text is not None:
        if not text:
            return 1.0
        printable_characters = sum(
            1
            for character in text
            if character.isprintable() or character in "\t\n\r"
        )
        return printable_characters / len(text)
    printable = sum(
        1
        for byte in data
        if 32 <= byte <= 126 or byte in (9, 10, 13)
    )
    return printable / len(data)


def classify_content(data: bytes) -> tuple[str, str | None]:
    if data.startswith(b"MZ"):
        return "MZ/PE", "MZ"
    if data.startswith(b"\x7fELF"):
        return "ELF", "ELF"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "ZIP", "ZIP"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP", "GZIP"
    if data.startswith(b"%PDF-"):
        return "PDF", "PDF"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG", "PNG"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG", "JPEG"

    text = decode_utf8(data)
    if text is not None:
        stripped = text.lstrip("\ufeff \t\r\n")
        if stripped.startswith(("{", "[")):
            try:
                json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                pass
            else:
                return "JSON", "JSON"
        if printable_ratio(data) >= 0.75:
            return "UTF-8 text", None
    return "unknown binary", None


def has_high_quality_output(data: bytes) -> bool:
    if _looks_like_zlib(data):
        return True
    content_type, signature = classify_content(data)
    if signature is not None or content_type == "JSON":
        return True
    return content_type == "UTF-8 text" and printable_ratio(data) >= 0.85


def sensitive_type_for_key(key: str) -> str | None:
    if not SENSITIVE_FIELD_RE.search(key):
        return None
    lowered = key.lower()
    if "email" in lowered:
        return "email"
    if "pass" in lowered or "pwd" in lowered:
        return "password"
    if "cookie" in lowered or "session" in lowered:
        return "cookie"
    if "author" in lowered:
        return "authorization_header"
    if "key" in lowered:
        return "api_key"
    return "token"


def masked_value(secret_type: str, value: str) -> str:
    digest = sha256_hex(value.encode("utf-8", errors="replace"))[:12]
    return f"[REDACTED:{secret_type}:{digest}]"


def _redact_json_value(value: Any, key: str | None = None) -> Any:
    if key is not None:
        secret_type = sensitive_type_for_key(key)
        if secret_type is not None and value is not None:
            serialized = (
                value
                if isinstance(value, str)
                else json.dumps(value, ensure_ascii=False, sort_keys=True)
            )
            return masked_value(secret_type, serialized)
    if isinstance(value, dict):
        return {
            str(child_key): _redact_json_value(child_value, str(child_key))
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_json_value(item) for item in value]
    return value


def redact_text(text: str) -> str:
    candidate = text
    stripped = text.lstrip("\ufeff \t\r\n")
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            pass
        else:
            candidate = json.dumps(
                _redact_json_value(parsed),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )

    for rule in SECRET_RULES:
        def replace(match: re.Match[str], current_rule: SecretRule = rule) -> str:
            value = match.group(current_rule.value_group)
            replacement = masked_value(current_rule.secret_type, value)
            start, end = match.span(current_rule.value_group)
            relative_start = start - match.start()
            relative_end = end - match.start()
            whole = match.group(0)
            return whole[:relative_start] + replacement + whole[relative_end:]

        candidate = rule.pattern.sub(replace, candidate)
    return candidate


def escape_control_text(text: str) -> str:
    escaped: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character == "\n":
            escaped.append("\\n")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\t":
            escaped.append("\\t")
        elif codepoint < 32 or codepoint == 127:
            escaped.append(f"\\x{codepoint:02x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def redacted_preview(data: bytes, max_chars: int) -> str:
    text = decode_utf8(data)
    if text is not None and printable_ratio(data) >= 0.65:
        preview = escape_control_text(redact_text(text))
    else:
        parts: list[str] = []
        for byte in data:
            if 32 <= byte <= 126:
                parts.append(chr(byte))
            elif byte == 9:
                parts.append("\\t")
            elif byte == 10:
                parts.append("\\n")
            elif byte == 13:
                parts.append("\\r")
            else:
                parts.append(f"\\x{byte:02x}")
            if sum(len(part) for part in parts) >= max_chars + 20:
                break
        preview = redact_text("".join(parts))
    if len(preview) > max_chars:
        return preview[:max_chars] + "…[truncated]"
    return preview


def report_preview(data: bytes, max_chars: int) -> str:
    content_type, _signature = classify_content(data)
    if content_type in {"MZ/PE", "ELF"}:
        return (
            f"[{content_type} preview suppressed; review file type and "
            "SHA-256 only]"
        )
    return redacted_preview(data, max_chars)


def _secret_finding(
    secret_type: str,
    value: str,
    layer: int,
    source_field: str,
) -> dict[str, Any]:
    return {
        "type": secret_type,
        "layer": layer,
        "source_field": source_field,
        "masked_value": masked_value(secret_type, value),
        "sha256": sha256_hex(value.encode("utf-8", errors="replace")),
    }


def _walk_json_secrets(
    value: Any,
    layer: int,
    path: str,
) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}"
            secret_type = sensitive_type_for_key(key_text)
            if secret_type is not None and child is not None:
                serialized = (
                    child
                    if isinstance(child, str)
                    else json.dumps(child, ensure_ascii=False, sort_keys=True)
                )
                yield _secret_finding(
                    secret_type,
                    serialized,
                    layer,
                    child_path,
                )
            yield from _walk_json_secrets(child, layer, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_json_secrets(
                child,
                layer,
                f"{path}[{index}]",
            )


def find_secrets(
    data: bytes,
    layer: int,
    source_field: str,
    field_secret_type: str | None = None,
) -> list[dict[str, Any]]:
    text = decode_utf8(data)
    if text is None:
        return []

    findings: list[dict[str, Any]] = []
    if field_secret_type is not None:
        findings.append(
            _secret_finding(
                field_secret_type,
                text,
                layer,
                source_field,
            )
        )

    stripped = text.lstrip("\ufeff \t\r\n")
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            pass
        else:
            findings.extend(_walk_json_secrets(parsed, layer, source_field))

    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            findings.append(
                _secret_finding(
                    rule.secret_type,
                    match.group(rule.value_group),
                    layer,
                    source_field,
                )
            )
    return findings


def detect_risk_signals(
    data: bytes,
    layer: int,
    source_field: str,
    confidence: str,
) -> list[dict[str, Any]]:
    text = decode_utf8(data)
    if text is None:
        return []
    signals: list[dict[str, Any]] = []
    for rule in RISK_RULES:
        for match in rule.pattern.finditer(text):
            evidence = escape_control_text(redact_text(match.group(0)))
            signals.append(
                {
                    "category": rule.category,
                    "indicator": rule.indicator,
                    "severity": rule.severity,
                    "layer": layer,
                    "source_field": source_field,
                    "confidence": confidence,
                    "redacted_evidence": evidence[:160],
                    "assessment": "risk_signal_only",
                }
            )

    for match in IPV4_CANDIDATE_RE.finditer(text):
        value = match.group(0)
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.is_global:
            signals.append(
                {
                    "category": "network_download",
                    "indicator": "public_ip_address",
                    "severity": "medium",
                    "layer": layer,
                    "source_field": source_field,
                    "confidence": confidence,
                    "redacted_evidence": value,
                    "assessment": "risk_signal_only",
                }
            )
    return signals


def extract_indicators(data: bytes) -> dict[str, list[dict[str, Any]]]:
    text = decode_utf8(data)
    results: dict[str, list[dict[str, Any]]] = {
        "urls": [],
        "domains": [],
        "ips": [],
        "hashes": [],
    }
    if text is None:
        return results

    urls: set[str] = set()
    domains: set[str] = set()
    ips: set[str] = set()
    hashes: set[tuple[str, str]] = set()

    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(".,);]}")
        urls.add(redact_text(url))
        try:
            hostname = urllib.parse.urlsplit(url).hostname
        except ValueError:
            hostname = None
        if hostname:
            domains.add(hostname.lower())

    for match in DOMAIN_RE.finditer(text):
        domains.add(match.group(0).lower())

    for match in IPV4_CANDIDATE_RE.finditer(text):
        value = match.group(0)
        try:
            normalized = str(ipaddress.ip_address(value))
        except ValueError:
            continue
        ips.add(normalized)

    for match in HASH_RE.finditer(text):
        value = match.group(0).lower()
        algorithm = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}[len(value)]
        hashes.add((algorithm, value))

    results["urls"] = [{"value": value} for value in sorted(urls)]
    results["domains"] = [{"value": value} for value in sorted(domains)]
    results["ips"] = [{"value": value} for value in sorted(ips)]
    results["hashes"] = [
        {"algorithm": algorithm, "value": value}
        for algorithm, value in sorted(hashes)
    ]
    return results


def _candidate_with_size_check(
    decoder: str,
    output: bytes,
    limits: Limits,
    confidence: str = "high",
    warnings: list[str] | None = None,
) -> DecodeCandidate:
    if len(output) > limits.max_output_bytes:
        return DecodeCandidate(
            decoder=decoder,
            output=None,
            confidence=confidence,
            warnings=["max_output_bytes_exceeded"],
            limit_name="max_output_bytes",
            output_size_hint=len(output),
        )
    return DecodeCandidate(
        decoder=decoder,
        output=output,
        confidence=confidence,
        warnings=list(warnings or []),
    )


def decode_jwt(data: bytes, limits: Limits) -> list[DecodeCandidate]:
    text = decode_utf8(data)
    if text is None:
        return []
    token = text.strip()
    if not JWT_FULL_RE.fullmatch(token):
        return []
    header_segment, payload_segment, _signature_segment = token.split(".", 2)

    def decode_segment(segment: str) -> bytes:
        if len(segment) % 4 == 1:
            raise ValueError("invalid Base64URL length")
        padded = segment + "=" * ((4 - len(segment) % 4) % 4)
        translated = padded.replace("-", "+").replace("_", "/")
        return base64.b64decode(translated, validate=True)

    try:
        header_bytes = decode_segment(header_segment)
        payload_bytes = decode_segment(payload_segment)
        header = json.loads(header_bytes.decode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ):
        return []
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return []
    output = json.dumps(
        {
            "header": header,
            "payload": payload,
            "signature_not_verified": True,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return [
        _candidate_with_size_check(
            "jwt_header_payload",
            output,
            limits,
            confidence="high",
            warnings=["signature_not_verified", "source_jwt_treated_as_sensitive"],
        )
    ]


def decode_base64_standard(
    data: bytes,
    limits: Limits,
) -> list[DecodeCandidate]:
    text = decode_utf8(data)
    if text is None:
        return []
    normalized = ASCII_WHITESPACE_RE.sub("", text.strip())
    if len(normalized) < 8 or len(normalized) % 4 != 0:
        return []
    if not BASE64_STANDARD_RE.fullmatch(normalized):
        return []
    if "=" in normalized[:-2]:
        return []
    estimated = (len(normalized) // 4) * 3
    if normalized.endswith("=="):
        estimated -= 2
    elif normalized.endswith("="):
        estimated -= 1
    if estimated > limits.max_output_bytes:
        return [
            DecodeCandidate(
                "base64",
                None,
                "high",
                ["max_output_bytes_exceeded"],
                "max_output_bytes",
                estimated,
            )
        ]
    try:
        output = base64.b64decode(normalized, validate=True)
    except binascii.Error:
        return []
    confidence = "high" if has_high_quality_output(output) else "low"
    return [
        DecodeCandidate(
            decoder="base64",
            output=output,
            confidence=confidence,
        )
    ]


def decode_base64_url(data: bytes, limits: Limits) -> list[DecodeCandidate]:
    text = decode_utf8(data)
    if text is None:
        return []
    normalized = ASCII_WHITESPACE_RE.sub("", text.strip())
    if len(normalized) < 6 or not BASE64_URL_RE.fullmatch(normalized):
        return []
    unpadded = normalized.rstrip("=")
    if len(unpadded) % 4 == 1:
        return []
    is_distinct_url_form = (
        "-" in unpadded or "_" in unpadded or len(normalized) % 4 != 0
    )
    if not is_distinct_url_form:
        return []
    padded = unpadded + "=" * ((4 - len(unpadded) % 4) % 4)
    translated = padded.replace("-", "+").replace("_", "/")
    estimated = (len(padded) // 4) * 3 - padded.count("=")
    if estimated > limits.max_output_bytes:
        return [
            DecodeCandidate(
                "base64url",
                None,
                "high",
                ["max_output_bytes_exceeded"],
                "max_output_bytes",
                estimated,
            )
        ]
    try:
        output = base64.b64decode(translated, validate=True)
    except binascii.Error:
        return []
    confidence = "high" if has_high_quality_output(output) else "low"
    return [DecodeCandidate("base64url", output, confidence)]


def decode_url_percent(data: bytes, limits: Limits) -> list[DecodeCandidate]:
    text = decode_utf8(data)
    if text is None or not PERCENT_ESCAPE_RE.search(text):
        return []
    try:
        output = urllib.parse.unquote_to_bytes(text)
    except (UnicodeEncodeError, ValueError):
        return []
    if output == data:
        return []
    return [
        _candidate_with_size_check(
            "url_percent",
            output,
            limits,
            confidence="high",
        )
    ]


def decode_hex(data: bytes, limits: Limits) -> list[DecodeCandidate]:
    text = decode_utf8(data)
    if text is None:
        return []
    normalized = ASCII_WHITESPACE_RE.sub("", text.strip())
    if not HEX_RE.fullmatch(normalized):
        return []
    if normalized.lower().startswith("0x"):
        normalized = normalized[2:]
    if len(normalized) < 8 or len(normalized) % 2 != 0:
        return []
    estimated = len(normalized) // 2
    if estimated > limits.max_output_bytes:
        return [
            DecodeCandidate(
                "hex",
                None,
                "high",
                ["max_output_bytes_exceeded"],
                "max_output_bytes",
                estimated,
            )
        ]
    try:
        output = bytes.fromhex(normalized)
    except ValueError:
        return []
    confidence = "high" if has_high_quality_output(output) else "low"
    return [DecodeCandidate("hex", output, confidence)]


def _replace_byte_escapes(text: str) -> bytes:
    output = bytearray()
    cursor = 0
    for match in BYTE_ESCAPE_RE.finditer(text):
        output.extend(text[cursor:match.start()].encode("utf-8"))
        output.append(int(match.group(1), 16))
        cursor = match.end()
    output.extend(text[cursor:].encode("utf-8"))
    return bytes(output)


def decode_byte_escapes(data: bytes, limits: Limits) -> list[DecodeCandidate]:
    text = decode_utf8(data)
    if text is None or not BYTE_ESCAPE_RE.search(text):
        return []
    output = _replace_byte_escapes(text)
    return [
        _candidate_with_size_check(
            "byte_escape",
            output,
            limits,
            confidence="high",
        )
    ]


def _unicode_escape_replacement(match: re.Match[str]) -> str:
    return chr(int(match.group(1), 16))


def decode_unicode_escapes(
    data: bytes,
    limits: Limits,
) -> list[DecodeCandidate]:
    text = decode_utf8(data)
    if text is None or not UNICODE_ESCAPE_RE.search(text):
        return []
    replaced = UNICODE_ESCAPE_RE.sub(_unicode_escape_replacement, text)
    try:
        output = replaced.encode("utf-16", "surrogatepass").decode(
            "utf-16"
        ).encode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return []
    return [
        _candidate_with_size_check(
            "unicode_escape",
            output,
            limits,
            confidence="high",
        )
    ]


def decode_html_entities(
    data: bytes,
    limits: Limits,
) -> list[DecodeCandidate]:
    text = decode_utf8(data)
    if text is None or not HTML_ENTITY_RE.search(text):
        return []
    decoded = html.unescape(text)
    if decoded == text:
        return []
    output = decoded.encode("utf-8")
    return [
        _candidate_with_size_check(
            "html_entity",
            output,
            limits,
            confidence="high",
        )
    ]


def _bounded_decompress(
    data: bytes,
    limits: Limits,
    wbits: int,
) -> bytes:
    ratio_cap = max(1, len(data) * limits.max_decompression_ratio)
    output_cap = min(limits.max_output_bytes, ratio_cap)
    active_limit = (
        "max_output_bytes"
        if limits.max_output_bytes <= ratio_cap
        else "max_decompression_ratio"
    )
    decompressor = zlib.decompressobj(wbits)
    try:
        output = bytearray(decompressor.decompress(data, output_cap + 1))
    except zlib.error as error:
        raise ValueError("invalid compressed stream") from error
    if len(output) > output_cap:
        raise DecompressionLimitError(active_limit, len(output))
    if not decompressor.eof:
        if decompressor.unconsumed_tail or len(output) >= output_cap:
            raise DecompressionLimitError(active_limit, output_cap + 1)
        raise ValueError("truncated compressed stream")
    remaining = output_cap - len(output)
    try:
        output.extend(decompressor.flush(remaining + 1))
    except zlib.error as error:
        raise ValueError("invalid compressed stream") from error
    if len(output) > output_cap:
        raise DecompressionLimitError(active_limit, len(output))
    return bytes(output)


def decode_gzip(data: bytes, limits: Limits) -> list[DecodeCandidate]:
    if not data.startswith(b"\x1f\x8b"):
        return []
    try:
        output = _bounded_decompress(data, limits, 16 + zlib.MAX_WBITS)
    except DecompressionLimitError as error:
        return [
            DecodeCandidate(
                "gzip",
                None,
                "high",
                [f"{error.limit_name}_exceeded"],
                error.limit_name,
                error.observed,
            )
        ]
    except ValueError:
        return [
            DecodeCandidate(
                "gzip",
                None,
                "low",
                ["invalid_or_truncated_gzip"],
            )
        ]
    return [DecodeCandidate("gzip", output, "high")]


def _looks_like_zlib(data: bytes) -> bool:
    if len(data) < 2:
        return False
    cmf, flags = data[0], data[1]
    return (cmf & 0x0F) == 8 and ((cmf << 8) + flags) % 31 == 0


def decode_zlib(data: bytes, limits: Limits) -> list[DecodeCandidate]:
    if not _looks_like_zlib(data):
        return []
    try:
        output = _bounded_decompress(data, limits, zlib.MAX_WBITS)
    except DecompressionLimitError as error:
        return [
            DecodeCandidate(
                "zlib",
                None,
                "high",
                [f"{error.limit_name}_exceeded"],
                error.limit_name,
                error.observed,
            )
        ]
    except ValueError:
        return [
            DecodeCandidate(
                "zlib",
                None,
                "low",
                ["invalid_or_truncated_zlib"],
            )
        ]
    return [DecodeCandidate("zlib", output, "high")]


DECODER_FUNCTIONS: tuple[DecoderFunction, ...] = (
    decode_jwt,
    decode_gzip,
    decode_zlib,
    decode_url_percent,
    decode_byte_escapes,
    decode_unicode_escapes,
    decode_html_entities,
    decode_base64_url,
    decode_base64_standard,
    decode_hex,
)


def looks_potentially_encoded(data: bytes) -> bool:
    if data.startswith(b"\x1f\x8b") or _looks_like_zlib(data):
        return True
    text = decode_utf8(data)
    if text is None:
        return False
    stripped = text.strip()
    normalized = ASCII_WHITESPACE_RE.sub("", stripped)
    return any(
        (
            JWT_FULL_RE.fullmatch(stripped) is not None,
            PERCENT_ESCAPE_RE.search(text) is not None,
            BYTE_ESCAPE_RE.search(text) is not None,
            UNICODE_ESCAPE_RE.search(text) is not None,
            HTML_ENTITY_RE.search(text) is not None,
            len(normalized) >= 8
            and len(normalized) % 4 == 0
            and BASE64_STANDARD_RE.fullmatch(normalized) is not None,
            len(normalized) >= 8
            and HEX_RE.fullmatch(normalized) is not None
            and len(normalized.removeprefix("0x")) % 2 == 0,
        )
    )


def _walk_json_strings(
    value: Any,
    path: str,
) -> Iterable[SourceValue]:
    if isinstance(value, str):
        key = path.rsplit(".", 1)[-1] if "." in path else ""
        yield SourceValue(
            source_field=path,
            data=value.encode("utf-8"),
            sensitive_type=sensitive_type_for_key(key),
        )
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_json_strings(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_json_strings(child, f"{path}[{index}]")


def prepare_sources(
    raw_input: bytes,
    input_kind: str,
) -> tuple[list[SourceValue], list[str], bool]:
    issues: list[str] = []
    fatal = False
    if input_kind == "json":
        try:
            parsed = json.loads(raw_input.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return [], ["JSON input could not be parsed"], True
        return list(_walk_json_strings(parsed, "$")), issues, fatal

    if input_kind == "jsonl":
        sources: list[SourceValue] = []
        valid_lines = 0
        text = decode_utf8(raw_input)
        if text is None:
            return [], ["JSONL input is not valid UTF-8"], True
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                issues.append(
                    f"JSONL line {line_number} could not be parsed"
                )
                continue
            valid_lines += 1
            sources.extend(
                _walk_json_strings(parsed, f"$[line:{line_number}]")
            )
        if valid_lines == 0 and issues:
            fatal = True
        return sources, issues, fatal

    text = decode_utf8(raw_input)
    if text is not None:
        stripped = text.lstrip("\ufeff \t\r\n")
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                pass
            else:
                return list(_walk_json_strings(parsed, "$")), issues, fatal
    field_name = "$" if text is not None else "$binary"
    return [SourceValue(field_name, raw_input)], issues, fatal


class ArtifactInspector:
    def __init__(
        self,
        limits: Limits | None = None,
        decoders: Sequence[DecoderFunction] | None = None,
    ) -> None:
        self.limits = limits or Limits()
        self.decoders = tuple(decoders or DECODER_FUNCTIONS)
        self.records: list[dict[str, Any]] = []
        self.risk_signals: list[dict[str, Any]] = []
        self.secret_findings: list[dict[str, Any]] = []
        self.file_signatures: list[dict[str, Any]] = []
        self.final_items: list[dict[str, Any]] = []
        self.indicators: dict[str, list[dict[str, Any]]] = {
            "urls": [],
            "domains": [],
            "ips": [],
            "hashes": [],
        }
        self.limits_triggered: list[dict[str, Any]] = []
        self.incomplete: list[str] = []
        self.accepted_transformations = 0
        self.candidate_count = 0
        self._risk_keys: set[tuple[Any, ...]] = set()
        self._secret_keys: set[tuple[Any, ...]] = set()
        self._signature_keys: set[tuple[Any, ...]] = set()
        self._indicator_keys: dict[str, set[tuple[Any, ...]]] = {
            key: set() for key in self.indicators
        }
        self._final_keys: set[tuple[Any, ...]] = set()
        self._limit_keys: set[tuple[Any, ...]] = set()

    def _add_limit(
        self,
        name: str,
        observed: int | str,
        source_field: str,
        layer: int,
    ) -> None:
        key = (name, str(observed), source_field, layer)
        if key in self._limit_keys:
            return
        self._limit_keys.add(key)
        self.limits_triggered.append(
            {
                "name": name,
                "limit": self.limits.as_dict()[name],
                "observed": observed,
                "source_field": source_field,
                "layer": layer,
            }
        )
        self.incomplete.append(
            f"{name} stopped analysis at layer {layer} for {source_field}"
        )

    def _observe(
        self,
        data: bytes,
        layer: int,
        source_field: str,
        confidence: str,
        field_secret_type: str | None = None,
    ) -> tuple[str, str | None]:
        content_type, signature = classify_content(data)
        digest = sha256_hex(data)
        if signature is not None:
            key = (signature, digest, layer, source_field)
            if key not in self._signature_keys:
                self._signature_keys.add(key)
                self.file_signatures.append(
                    {
                        "signature": signature,
                        "content_type": content_type,
                        "layer": layer,
                        "source_field": source_field,
                        "sha256": digest,
                    }
                )

        for signal in detect_risk_signals(
            data,
            layer,
            source_field,
            confidence,
        ):
            key = (
                signal["category"],
                signal["indicator"],
                signal["layer"],
                signal["source_field"],
                signal["redacted_evidence"],
            )
            if key not in self._risk_keys:
                self._risk_keys.add(key)
                self.risk_signals.append(signal)

        for finding in find_secrets(
            data,
            layer,
            source_field,
            field_secret_type,
        ):
            key = (
                finding["type"],
                finding["layer"],
                finding["source_field"],
                finding["sha256"],
            )
            if key not in self._secret_keys:
                self._secret_keys.add(key)
                self.secret_findings.append(finding)

        extracted = extract_indicators(data)
        for category, values in extracted.items():
            for value in values:
                key = tuple(sorted(value.items()))
                if key not in self._indicator_keys[category]:
                    self._indicator_keys[category].add(key)
                    self.indicators[category].append(value)
        return content_type, signature

    def _add_final(self, node: Node) -> None:
        content_type, _signature = classify_content(node.data)
        digest = sha256_hex(node.data)
        key = (node.source_field, node.layer, digest)
        if key in self._final_keys:
            return
        self._final_keys.add(key)
        preview = (
            masked_value(
                node.sensitive_type,
                decode_utf8(node.data) or sha256_hex(node.data),
            )
            if node.sensitive_type is not None
            else report_preview(
                node.data,
                self.limits.max_preview_chars,
            )
        )
        self.final_items.append(
            {
                "source_field": node.source_field,
                "layer": node.layer,
                "content_type": content_type,
                "sha256": digest,
                "redacted_preview": preview,
            }
        )

    def _decode_candidates(self, data: bytes) -> list[DecodeCandidate]:
        candidates: list[DecodeCandidate] = []
        for decoder in self.decoders:
            try:
                candidates.extend(decoder(data, self.limits))
            except (ValueError, TypeError, binascii.Error, zlib.error):
                continue
        return candidates

    def inspect_source(self, source: SourceValue, source_index: int) -> None:
        root_hash = sha256_hex(source.data)
        queue: list[Node] = [
            Node(
                source_field=source.source_field,
                data=source.data,
                layer=0,
                seen_hashes=frozenset({root_hash}),
                chain_id=f"source-{source_index}",
                confidence="input",
                sensitive_type=source.sensitive_type,
            )
        ]
        while queue:
            node = queue.pop(0)
            self._observe(
                node.data,
                node.layer,
                node.source_field,
                node.confidence,
                node.sensitive_type,
            )
            if node.layer >= self.limits.max_depth:
                if looks_potentially_encoded(node.data):
                    self._add_limit(
                        "max_depth",
                        node.layer + 1,
                        node.source_field,
                        node.layer,
                    )
                self._add_final(node)
                continue

            candidates = self._decode_candidates(node.data)
            accepted_child = False
            for candidate_index, candidate in enumerate(candidates, start=1):
                if self.candidate_count >= self.limits.max_candidates:
                    self._add_limit(
                        "max_candidates",
                        self.candidate_count + 1,
                        node.source_field,
                        node.layer + 1,
                    )
                    break
                self.candidate_count += 1
                output = candidate.output
                output_size = (
                    len(output)
                    if output is not None
                    else candidate.output_size_hint
                )
                output_hash = (
                    sha256_hex(output) if output is not None else None
                )
                warnings = list(candidate.warnings)
                cycle = output_hash is not None and output_hash in node.seen_hashes
                if cycle:
                    warnings.append("hash_cycle_detected_chain_stopped")
                if candidate.confidence == "low" and output is not None:
                    warnings.append("low_confidence_candidate_not_recursed")
                content_type = (
                    classify_content(output)[0]
                    if output is not None
                    else "not_available"
                )
                if output is None:
                    preview = ""
                elif node.sensitive_type is not None:
                    preview = masked_value(
                        node.sensitive_type,
                        decode_utf8(output) or sha256_hex(output),
                    )
                else:
                    preview = report_preview(
                        output,
                        self.limits.max_preview_chars,
                    )
                self.records.append(
                    {
                        "layer": node.layer + 1,
                        "source_field": node.source_field,
                        "decoder": candidate.decoder,
                        "input_size": len(node.data),
                        "output_size": output_size,
                        "input_sha256": sha256_hex(node.data),
                        "output_sha256": output_hash,
                        "confidence": candidate.confidence,
                        "content_type": content_type,
                        "redacted_preview": preview,
                        "warnings": warnings,
                        "candidate": candidate.confidence == "low",
                        "chain_id": (
                            f"{node.chain_id}.{candidate_index}"
                        ),
                    }
                )

                if candidate.limit_name is not None:
                    self._add_limit(
                        candidate.limit_name,
                        output_size if output_size is not None else "unknown",
                        node.source_field,
                        node.layer + 1,
                    )
                    continue
                if (
                    output is None
                    or candidate.confidence == "low"
                    or cycle
                ):
                    continue

                self.accepted_transformations += 1
                accepted_child = True
                queue.append(
                    Node(
                        source_field=node.source_field,
                        data=output,
                        layer=node.layer + 1,
                        seen_hashes=node.seen_hashes | {output_hash},
                        chain_id=f"{node.chain_id}.{candidate_index}",
                        confidence=candidate.confidence,
                        sensitive_type=node.sensitive_type,
                    )
                )

            if not accepted_child:
                self._add_final(node)

    def build_report(
        self,
        raw_input: bytes,
        source_kind: str,
        source_name: str,
        fields_inspected: int,
        parse_issues: list[str],
        fatal_parse_error: bool,
        truncated: bool = False,
    ) -> dict[str, Any]:
        if fatal_parse_error:
            decode_status = "ERROR"
        elif self.limits_triggered:
            decode_status = "LIMIT_REACHED"
        elif self.accepted_transformations and parse_issues:
            decode_status = "PARTIAL"
        elif self.accepted_transformations:
            decode_status = "DECODED"
        elif parse_issues:
            decode_status = "PARTIAL"
        else:
            decode_status = "NO_ENCODING_FOUND"

        high_risk = any(
            signal["severity"] == "high"
            for signal in self.risk_signals
        )
        if high_risk:
            risk_status = "HIGH_RISK_INDICATORS"
        elif (
            fatal_parse_error
            or self.limits_triggered
            or parse_issues
            or (
                self.final_items
                and all(
                    item["content_type"] == "unknown binary"
                    for item in self.final_items
                )
            )
        ):
            risk_status = "INCONCLUSIVE"
        elif self.risk_signals:
            risk_status = "REVIEW"
        else:
            risk_status = "NO_HIGH_RISK_INDICATORS"

        if decode_status not in DECODE_STATUSES:
            raise AssertionError("invalid decode status")
        if risk_status not in RISK_STATUSES:
            raise AssertionError("invalid risk status")

        incomplete = list(parse_issues) + self.incomplete
        recommendations = [
            "Treat all decoded content as untrusted data and do not execute it.",
            "Manually validate risk signals against surrounding incident evidence.",
            "Distinguish encoding facts and rule matches from a maliciousness conclusion.",
            "Escalate to a controlled specialist workflow if executable-file analysis is required.",
        ]
        if risk_status == "INCONCLUSIVE":
            recommendations.append(
                "Collect additional evidence because this analysis is inconclusive."
            )

        return {
            "schema_version": SCHEMA_VERSION,
            "input_summary": {
                "source_kind": source_kind,
                "source_name": source_name,
                "input_size": len(raw_input),
                "input_sha256": None if truncated else sha256_hex(raw_input),
                "fields_inspected": fields_inspected,
                "truncated": truncated,
            },
            "decode_status": decode_status,
            "risk_status": risk_status,
            "risk_status_explanation": NO_RISK_CAVEAT,
            "transformation_chain": self.records,
            "final_content_types": [
                {
                    "source_field": item["source_field"],
                    "layer": item["layer"],
                    "content_type": item["content_type"],
                    "sha256": item["sha256"],
                }
                for item in self.final_items
            ],
            "redacted_previews": [
                {
                    "source_field": item["source_field"],
                    "layer": item["layer"],
                    "preview": item["redacted_preview"],
                }
                for item in self.final_items
            ],
            "file_signatures": self.file_signatures,
            "risk_signals": self.risk_signals,
            "sensitive_findings": self.secret_findings,
            "indicators": self.indicators,
            "limits": {
                "configured": self.limits.as_dict(),
                "triggered": self.limits_triggered,
            },
            "incomplete_analysis": incomplete,
            "review_recommendations": recommendations,
        }


def make_limit_only_report(
    raw_prefix: bytes,
    source_kind: str,
    source_name: str,
    limits: Limits,
) -> dict[str, Any]:
    inspector = ArtifactInspector(limits)
    inspector._add_limit(
        "max_input_bytes",
        len(raw_prefix),
        "$",
        0,
    )
    return inspector.build_report(
        raw_prefix,
        source_kind,
        source_name,
        0,
        [],
        False,
        truncated=True,
    )


def inspect_bytes(
    raw_input: bytes,
    source_kind: str = "text",
    source_name: str = "<text>",
    input_kind: str = "auto",
    limits: Limits | None = None,
    decoders: Sequence[DecoderFunction] | None = None,
) -> dict[str, Any]:
    active_limits = limits or Limits()
    if len(raw_input) > active_limits.max_input_bytes:
        return make_limit_only_report(
            raw_input[: active_limits.max_input_bytes + 1],
            source_kind,
            source_name,
            active_limits,
        )

    sources, parse_issues, fatal = prepare_sources(
        raw_input,
        input_kind,
    )
    inspector = ArtifactInspector(active_limits, decoders)
    if not fatal:
        for index, source in enumerate(sources, start=1):
            inspector.inspect_source(source, index)
    return inspector.build_report(
        raw_input,
        source_kind,
        source_name,
        len(sources),
        parse_issues,
        fatal,
    )


def _markdown_escape(value: Any) -> str:
    text = str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "\\`")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def _markdown_list(items: list[str], empty_text: str) -> list[str]:
    if not items:
        return [f"- {empty_text}"]
    return [f"- {_markdown_escape(item)}" for item in items]


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["input_summary"]
    lines = [
        "# Encoded Artifact Inspection Report",
        "",
        "## 1. Input summary",
        "",
        f"- Source kind: `{_markdown_escape(summary['source_kind'])}`",
        f"- Source name: `{_markdown_escape(summary['source_name'])}`",
        f"- Input size: `{summary['input_size']}` bytes",
        f"- Input SHA-256: `{summary['input_sha256'] or 'not_computed_due_to_limit'}`",
        f"- String fields inspected: `{summary['fields_inspected']}`",
        "",
        "## 2. Decode status",
        "",
        f"- Status: `{report['decode_status']}`",
        "",
        "## 3. Transformation chain",
        "",
    ]
    records = report["transformation_chain"]
    if records:
        lines.extend(
            [
                "| Layer | Source field | Decoder | Input bytes | Output bytes | Confidence | Content type | Redacted preview | Warnings |",
                "|---:|---|---|---:|---:|---|---|---|---|",
            ]
        )
        for record in records:
            lines.append(
                "| {layer} | {source} | {decoder} | {input_size} | {output_size} | "
                "{confidence} | {content_type} | {preview} | {warnings} |".format(
                    layer=record["layer"],
                    source=_markdown_escape(record["source_field"]),
                    decoder=_markdown_escape(record["decoder"]),
                    input_size=record["input_size"],
                    output_size=(
                        record["output_size"]
                        if record["output_size"] is not None
                        else "n/a"
                    ),
                    confidence=record["confidence"],
                    content_type=_markdown_escape(record["content_type"]),
                    preview=_markdown_escape(record["redacted_preview"]),
                    warnings=_markdown_escape(
                        ", ".join(record["warnings"]) or "none"
                    ),
                )
            )
        lines.extend(["", "Layer hashes:"])
        for record in records:
            lines.append(
                "- Layer {layer} `{decoder}`: input `{input_hash}`, output `{output_hash}`".format(
                    layer=record["layer"],
                    decoder=_markdown_escape(record["decoder"]),
                    input_hash=record["input_sha256"],
                    output_hash=record["output_sha256"] or "not_available",
                )
            )
    else:
        lines.append("- No deterministic transformation accepted.")

    lines.extend(["", "## 4. Final content type", ""])
    if report["final_content_types"]:
        for item in report["final_content_types"]:
            lines.append(
                f"- `{_markdown_escape(item['source_field'])}` layer "
                f"`{item['layer']}`: `{_markdown_escape(item['content_type'])}`, "
                f"SHA-256 `{item['sha256']}`"
            )
    else:
        lines.append("- Not available.")

    lines.extend(["", "## 5. Redacted content preview", ""])
    if report["redacted_previews"]:
        for item in report["redacted_previews"]:
            lines.append(
                f"- `{_markdown_escape(item['source_field'])}` layer `{item['layer']}`:"
            )
            preview_lines = str(item["preview"]).splitlines() or [""]
            lines.extend(
                f"    {_markdown_escape(preview_line)}"
                for preview_line in preview_lines
            )
    else:
        lines.append("- Not available.")

    lines.extend(["", "## 6. File signatures", ""])
    if report["file_signatures"]:
        for item in report["file_signatures"]:
            lines.append(
                f"- `{item['signature']}` at layer `{item['layer']}` in "
                f"`{_markdown_escape(item['source_field'])}`; SHA-256 `{item['sha256']}`"
            )
    else:
        lines.append("- No known file signature found.")

    lines.extend(
        [
            "",
            "## 7. Risk signals",
            "",
            f"- Status: `{report['risk_status']}`",
            f"- {report['risk_status_explanation']}",
        ]
    )
    if report["risk_signals"]:
        for signal in report["risk_signals"]:
            lines.append(
                f"- `{signal['category']}/{signal['indicator']}` "
                f"({signal['severity']}) at layer `{signal['layer']}` in "
                f"`{_markdown_escape(signal['source_field'])}`: "
                f"`{_markdown_escape(signal['redacted_evidence'])}` — risk signal only"
            )
    else:
        lines.append("- No risk-signal rule matched.")

    lines.extend(["", "### Sensitive findings", ""])
    if report["sensitive_findings"]:
        for finding in report["sensitive_findings"]:
            lines.append(
                f"- `{finding['type']}` at layer `{finding['layer']}` in "
                f"`{_markdown_escape(finding['source_field'])}`: "
                f"`{_markdown_escape(finding['masked_value'])}`, "
                f"SHA-256 `{finding['sha256']}`"
            )
    else:
        lines.append("- No sensitive-data rule matched.")

    lines.extend(["", "## 8. Extracted URLs, domains, IPs, and hashes", ""])
    for category in ("urls", "domains", "ips", "hashes"):
        values = report["indicators"][category]
        rendered = [
            (
                f"{value['algorithm']}:{value['value']}"
                if "algorithm" in value
                else value["value"]
            )
            for value in values
        ]
        lines.append(
            f"- {category}: "
            + (
                ", ".join(f"`{_markdown_escape(value)}`" for value in rendered)
                if rendered
                else "none"
            )
        )

    lines.extend(["", "## 9. Safety limits", ""])
    configured = report["limits"]["configured"]
    lines.append(
        "- Configured: "
        + ", ".join(
            f"`{name}={value}`" for name, value in configured.items()
        )
    )
    triggered = report["limits"]["triggered"]
    if triggered:
        for item in triggered:
            lines.append(
                f"- Triggered `{item['name']}` at layer `{item['layer']}` in "
                f"`{_markdown_escape(item['source_field'])}` "
                f"(limit `{item['limit']}`, observed `{item['observed']}`)."
            )
    else:
        lines.append("- Triggered: none.")

    lines.extend(["", "## 10. Incomplete analysis", ""])
    lines.extend(
        _markdown_list(
            report["incomplete_analysis"],
            "No incomplete analysis recorded.",
        )
    )

    lines.extend(["", "## 11. Human review recommendations", ""])
    lines.extend(
        _markdown_list(
            report["review_recommendations"],
            "No additional recommendation.",
        )
    )
    return "\n".join(lines) + "\n"


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(
        report,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def _limited_integer(name: str, maximum: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError(
                f"{name} must be an integer"
            ) from error
        if parsed < 1 or parsed > maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between 1 and {maximum}"
            )
        return parsed

    return parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Offline static inspection of encoded artifacts. Decoded content "
            "is never executed or written to disk."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="Explicit text to inspect")
    source.add_argument("--input", help="One explicit file to inspect")
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Report format written to standard output",
    )
    parser.add_argument(
        "--max-depth",
        type=_limited_integer("max_depth", DEFAULT_MAX_DEPTH),
        default=DEFAULT_MAX_DEPTH,
    )
    parser.add_argument(
        "--max-input-bytes",
        type=_limited_integer(
            "max_input_bytes",
            DEFAULT_MAX_INPUT_BYTES,
        ),
        default=DEFAULT_MAX_INPUT_BYTES,
    )
    parser.add_argument(
        "--max-output-bytes",
        type=_limited_integer(
            "max_output_bytes",
            DEFAULT_MAX_OUTPUT_BYTES,
        ),
        default=DEFAULT_MAX_OUTPUT_BYTES,
    )
    parser.add_argument(
        "--max-candidates",
        type=_limited_integer(
            "max_candidates",
            DEFAULT_MAX_CANDIDATES,
        ),
        default=DEFAULT_MAX_CANDIDATES,
    )
    parser.add_argument(
        "--max-preview-chars",
        type=_limited_integer(
            "max_preview_chars",
            DEFAULT_MAX_PREVIEW_CHARS,
        ),
        default=DEFAULT_MAX_PREVIEW_CHARS,
    )
    parser.add_argument(
        "--max-decompression-ratio",
        type=_limited_integer(
            "max_decompression_ratio",
            DEFAULT_MAX_DECOMPRESSION_RATIO,
        ),
        default=DEFAULT_MAX_DECOMPRESSION_RATIO,
    )
    return parser


def _input_kind_for_path(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".jsonl":
        return "jsonl"
    return "auto"


def _error_report(
    source_kind: str,
    source_name: str,
    limits: Limits,
    message: str,
) -> dict[str, Any]:
    inspector = ArtifactInspector(limits)
    return inspector.build_report(
        b"",
        source_kind,
        source_name,
        0,
        [message],
        True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        limits = Limits(
            max_depth=args.max_depth,
            max_input_bytes=args.max_input_bytes,
            max_output_bytes=args.max_output_bytes,
            max_candidates=args.max_candidates,
            max_preview_chars=args.max_preview_chars,
            max_decompression_ratio=args.max_decompression_ratio,
        )
    except ValueError as error:
        parser.error(str(error))

    if args.text is not None:
        raw_input = args.text.encode("utf-8")
        report = inspect_bytes(
            raw_input,
            source_kind="text",
            source_name="<text>",
            input_kind="auto",
            limits=limits,
        )
    else:
        path = Path(args.input)
        source_name = path.name or "<input>"
        try:
            with path.open("rb") as input_file:
                raw_input = input_file.read(limits.max_input_bytes + 1)
        except (OSError, ValueError) as error:
            report = _error_report(
                "file",
                source_name,
                limits,
                f"Input file could not be read ({type(error).__name__})",
            )
        else:
            report = inspect_bytes(
                raw_input,
                source_kind="file",
                source_name=source_name,
                input_kind=_input_kind_for_path(path),
                limits=limits,
            )

    output = (
        render_json(report)
        if args.format == "json"
        else render_markdown(report)
    )
    sys.stdout.write(output)
    return 2 if report["decode_status"] == "ERROR" else 0


if __name__ == "__main__":
    raise SystemExit(main())
