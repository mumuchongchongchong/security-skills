#!/usr/bin/env python3
"""Offline agent-trace auditor. This module never executes trace content."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DEFAULT_MAX_REPEATED_CALLS = 3
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
HIGH_RISK_VERBS = {
    "delete", "remove", "write", "edit", "update", "create", "send", "post",
    "publish", "execute", "exec", "run", "shell", "command", "deploy",
    "transfer", "upload",
}

INJECTION_PATTERNS = (
    (
        "prompt_override",
        re.compile(
            r"\b(?:ignore|disregard|override|forget)\b.{0,80}"
            r"\b(?:previous|prior|system|developer|original)\b.{0,30}\binstructions?\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "authority_impersonation",
        re.compile(
            r"\b(?:system|developer|administrator)\s+(?:message|instruction)\b"
            r".{0,80}\b(?:follow|obey|override|must)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "secret_exfiltration_instruction",
        re.compile(
            r"\b(?:reveal|exfiltrate|send|print|return)\b.{0,60}"
            r"\b(?:password|token|api[_ -]?key|cookie|secret)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "command_execution_instruction",
        re.compile(
            r"\b(?:execute|run|launch)\b.{0,30}\b(?:command|shell|powershell|bash|cmd)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "prompt_override_zh",
        re.compile(r"(?:忽略|无视|覆盖).{0,40}(?:之前|先前|系统|开发者).{0,20}(?:指令|提示)"),
    ),
    (
        "dangerous_instruction_zh",
        re.compile(r"(?:执行以下命令|泄露.{0,20}(?:密钥|密码|令牌)|不要遵守.{0,20}(?:指令|规则))"),
    ),
)

SECRET_PATTERNS = (
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b", re.I)),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)
KEY_VALUE_SECRET_RE = re.compile(
    r"(?P<label>password|passwd|pwd|access[_ -]?token|refresh[_ -]?token|"
    r"api[_ -]?key|client[_ -]?secret|cookie|session[_ -]?id)"
    r"\s*[:=]\s*[\"']?(?P<secret>[^\s\"',;}{]{4,})",
    re.IGNORECASE,
)
SECRET_FIELD_RE = re.compile(
    r"^(?:password|passwd|pwd|token|access_token|refresh_token|api_key|apikey|"
    r"client_secret|secret|cookie|set_cookie|session_id|sessionid|private_key)$",
    re.IGNORECASE,
)
CERTAINTY_PATTERNS = (
    re.compile(r"已确认|已经确认|处置完成|已处置|已完成|问题已解决|确认无风险"),
    re.compile(r"(?<!not )(?<!un)\b(?:confirmed|verified|resolved)\b", re.I),
    re.compile(r"\b(?:successfully\s+)?completed\b", re.I),
    re.compile(r"\bno\s+(?:issues?|risks?)\s+(?:found|detected)\b", re.I),
)


def _safe_key(key: Any) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_\-]", "_", str(key))[:48]
    return cleaned or "field"


def _mask_secret(value: str) -> str:
    value = str(value)
    if value.lower().startswith("bearer "):
        return "Bearer ***"
    if value.startswith("sk-"):
        return "sk-***" + (value[-2:] if len(value) > 5 else "")
    for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "xox"):
        if value.startswith(prefix):
            return prefix + "***" + (value[-2:] if len(value) > len(prefix) + 2 else "")
    if len(value) >= 10:
        return value[:2] + "***" + value[-2:]
    return "***"


def sanitize_text(value: Any, limit: int | None = None) -> str:
    """Redact recognizable credentials before untrusted text reaches a report."""
    text = str(value)
    text = KEY_VALUE_SECRET_RE.sub(lambda m: f"{m.group('label')}=***", text)
    for kind, pattern in SECRET_PATTERNS:
        if kind == "private_key":
            text = pattern.sub("[MASKED PRIVATE KEY MARKER]", text)
        else:
            text = pattern.sub(lambda match: _mask_secret(match.group(0)), text)
    text = text.replace("\x00", "\\0")
    if limit is not None and len(text) > limit:
        return text[: max(0, limit - 1)] + "…"
    return text


def _redact_structure(value: Any) -> Any:
    """Mask sensitive fields before creating previews from structured values."""
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            redacted[key] = (
                "***"
                if SECRET_FIELD_RE.match(str(key)) and item not in (None, "")
                else _redact_structure(item)
            )
        return redacted
    if isinstance(value, list):
        return [_redact_structure(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def _safe_preview(value: Any, limit: int = 180) -> str:
    return sanitize_text(_flatten_text(_redact_structure(value)), limit)


def _safe_identifier(value: Any, fallback: str) -> str:
    if value is None or value == "":
        return fallback
    return sanitize_text(value, 100)


def _decode_jsonish(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if stripped.startswith(("{", "[")):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
    return value


def _flatten_text(value: Any) -> str:
    parts: list[str] = []

    def visit(node: Any) -> None:
        if isinstance(node, str):
            parts.append(node)
        elif isinstance(node, list):
            for item in node:
                visit(item)
        elif isinstance(node, dict):
            preferred = ("text", "content", "output_text", "value", "summary", "message")
            used = False
            for key in preferred:
                if key in node:
                    visit(node[key])
                    used = True
            if not used:
                for item in node.values():
                    if isinstance(item, (str, list, dict)):
                        visit(item)

    visit(value)
    return " ".join(part for part in parts if part).strip()


def _extract_container(data: Any) -> list[Any]:
    if isinstance(data, list):
        return list(data)
    if not isinstance(data, dict):
        return [{"type": "unknown", "content": data}]

    event_markers = {
        "type", "event_type", "kind", "role", "tool_name", "call_id", "tool_call_id",
    }
    if event_markers.intersection(data):
        return [data]
    for key in ("events", "messages", "trace", "items"):
        if isinstance(data.get(key), list):
            return list(data[key])
    if "input" in data and "output" in data:
        events: list[Any] = []
        source_input = data["input"]
        events.extend(source_input if isinstance(source_input, list) else [
            {"type": "user_input", "content": source_input}
        ])
        source_output = data["output"]
        events.extend(source_output if isinstance(source_output, list) else [
            {"type": "final_answer", "content": source_output}
        ])
        return events

    aggregate_keys = {
        "user_input", "prompt", "model_plan", "plan", "reasoning", "tool_calls",
        "calls", "tool_results", "results", "final_answer", "answer", "final",
    }
    if aggregate_keys.intersection(data):
        events = []
        for key in ("user_input", "prompt"):
            if key in data:
                events.append({"type": "user_input", "content": data[key]})
                break
        for key in ("model_plan", "plan", "reasoning"):
            if key in data:
                events.append({"type": "model_plan", "content": data[key]})
                break
        for key in ("tool_calls", "calls"):
            if key in data:
                values = data[key] if isinstance(data[key], list) else [data[key]]
                for value in values:
                    event = dict(value) if isinstance(value, dict) else {"content": value}
                    event.setdefault("type", "tool_call")
                    events.append(event)
                break
        for key in ("tool_results", "results"):
            if key in data:
                values = data[key] if isinstance(data[key], list) else [data[key]]
                for value in values:
                    event = dict(value) if isinstance(value, dict) else {"content": value}
                    event.setdefault("type", "tool_result")
                    events.append(event)
                break
        for key in ("final_answer", "answer", "final"):
            if key in data:
                events.append({"type": "final_answer", "content": data[key]})
                break
        return events
    return [data]


PASTED_LINE_RE = re.compile(
    r"^\s*(?:\[(?P<bracket>[A-Za-z_]+|用户|计划|工具调用|工具返回|最终|审批)\]"
    r"|(?P<plain>[A-Za-z_]+|用户|计划|工具调用|工具返回|最终|审批)\s*:)"
    r"\s*(?P<payload>.*)$"
)
PASTED_TYPE_MAP = {
    "user": "user_input", "user_input": "user_input", "用户": "user_input",
    "plan": "model_plan", "model_plan": "model_plan", "计划": "model_plan",
    "tool_call": "tool_call", "工具调用": "tool_call",
    "tool_result": "tool_result", "工具返回": "tool_result",
    "final": "final_answer", "final_answer": "final_answer", "最终": "final_answer",
    "approval": "approval", "审批": "approval",
}


def _parse_pasted(text: str) -> list[dict[str, Any]]:
    events = []
    for line in text.splitlines():
        match = PASTED_LINE_RE.match(line)
        if not match:
            continue
        label = (match.group("bracket") or match.group("plain")).lower()
        event_type = PASTED_TYPE_MAP.get(label)
        if not event_type:
            continue
        payload = match.group("payload")
        event: dict[str, Any] = {"type": event_type, "content": payload}
        if event_type == "tool_call":
            name_match = re.search(r"(?:tool|name)\s*=\s*([^\s,]+)", payload)
            args_match = re.search(r"(?:args|arguments)\s*=\s*(.+)$", payload)
            if name_match:
                event["tool_name"] = name_match.group(1)
            if args_match:
                event["arguments"] = _decode_jsonish(args_match.group(1))
        events.append(event)
    return events


def parse_trace(text: str) -> tuple[list[Any], str, list[dict[str, str]]]:
    issues: list[dict[str, str]] = []
    if not text.strip():
        return [], "empty", [{
            "issue": "empty_input",
            "impact": "No events are available for reconstruction.",
        }]
    try:
        return _extract_container(json.loads(text)), "json", issues
    except json.JSONDecodeError:
        pass

    parsed_lines: list[Any] = []
    invalid_lines = 0
    nonempty_lines = [line for line in text.splitlines() if line.strip()]
    for line in nonempty_lines:
        try:
            parsed_lines.extend(_extract_container(json.loads(line)))
        except json.JSONDecodeError:
            invalid_lines += 1
    if parsed_lines:
        if invalid_lines:
            issues.append({
                "issue": "malformed_jsonl_lines",
                "impact": f"{invalid_lines} non-empty line(s) could not be parsed and were omitted.",
            })
        return parsed_lines, "jsonl", issues

    pasted = _parse_pasted(text)
    if pasted:
        if len(pasted) < len(nonempty_lines):
            issues.append({
                "issue": "unrecognized_pasted_lines",
                "impact": "Some pasted lines did not have a recognized stage prefix.",
            })
        return pasted, "pasted", issues
    return [{"type": "unknown"}], "unknown", [{
        "issue": "unrecognized_log_structure",
        "impact": "The input is neither recognized JSON/JSONL nor a prefixed pasted trace.",
    }]


def _expand_nested_calls(events: Iterable[Any]) -> list[Any]:
    expanded = []
    for item in events:
        if not isinstance(item, dict):
            expanded.append(item)
            continue
        calls = item.get("tool_calls")
        if isinstance(calls, list):
            if item.get("content"):
                expanded.append({
                    "type": "model_plan",
                    "content": item["content"],
                    "timestamp": item.get("timestamp"),
                    "_stage_inferred": True,
                })
            for call in calls:
                call = call if isinstance(call, dict) else {"content": call}
                function = call.get("function") if isinstance(call.get("function"), dict) else {}
                expanded.append({
                    "type": "tool_call",
                    "event_id": call.get("id"),
                    "call_id": call.get("id"),
                    "tool_name": function.get("name") or call.get("name"),
                    "arguments": function.get("arguments") or call.get("arguments"),
                    "timestamp": item.get("timestamp"),
                    "_stage_inferred": True,
                })
            continue
        function_call = item.get("function_call")
        if isinstance(function_call, dict):
            if item.get("content"):
                expanded.append({
                    "type": "model_plan",
                    "content": item["content"],
                    "timestamp": item.get("timestamp"),
                    "_stage_inferred": True,
                })
            expanded.append({
                "type": "tool_call",
                "call_id": function_call.get("id"),
                "tool_name": function_call.get("name"),
                "arguments": function_call.get("arguments"),
                "timestamp": item.get("timestamp"),
                "_stage_inferred": True,
            })
            continue
        expanded.append(item)
    return expanded


def _first(event: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in event and event[key] is not None:
            return event[key]
    return None


def _classify_stage(event: dict[str, Any]) -> tuple[str, bool]:
    kind = str(_first(event, ("type", "event_type", "kind", "action")) or "").lower()
    kind = kind.replace("-", "_").replace(".", "_")
    role = str(event.get("role") or "").lower()
    inferred = bool(event.get("_stage_inferred"))
    if "approval" in kind or kind in {"authorization", "human_review", "consent"}:
        return "approval", inferred
    if kind in {"function_call_output", "tool_result", "tool_response", "tool_output"} or (
        "tool" in kind and any(word in kind for word in ("result", "output", "response"))
    ):
        return "tool_result", inferred
    if kind in {"function_call", "tool_call", "tool_use"} or (
        "tool" in kind and any(word in kind for word in ("call", "use", "request"))
    ):
        return "tool_call", inferred
    if kind in {"final", "final_answer", "answer", "response_output_text"} or "final" in kind:
        return "final_answer", inferred
    if kind in {"reasoning", "analysis", "model_plan", "planning", "plan"} or any(
        word in kind for word in ("reasoning", "planning")
    ):
        return "model_plan", inferred
    if kind in {"user", "user_input", "input", "request", "prompt"}:
        return "user_input", inferred
    if role == "user":
        return "user_input", True
    if role == "tool":
        return "tool_result", True
    if role == "assistant":
        return "final_answer", True
    return "unknown", False


def _extract_tool_name(event: dict[str, Any]) -> str | None:
    value = _first(event, ("tool_name", "name"))
    if value is None:
        tool = event.get("tool")
        value = tool.get("name") if isinstance(tool, dict) else tool
    if value is None and isinstance(event.get("function"), dict):
        value = event["function"].get("name")
    return _safe_identifier(value, "") or None


def _extract_arguments(event: dict[str, Any]) -> Any:
    value = _first(event, ("arguments", "args", "parameters"))
    if value is None and isinstance(event.get("function"), dict):
        value = event["function"].get("arguments")
    if value is None and "input" in event:
        value = event["input"]
    return _decode_jsonish(value)


def _extract_result(event: dict[str, Any]) -> Any:
    if event.get("error") not in (None, "", False):
        return event["error"]
    return _first(event, ("output", "result", "response", "content", "data", "error"))


def _result_status(event: dict[str, Any], result: Any) -> str:
    if event.get("error") not in (None, "", False) or event.get("success") is False:
        return "failed"
    if event.get("success") is True:
        return "success"
    status = str(event.get("status") or "").lower()
    if status in {"error", "failed", "failure", "denied", "timeout", "cancelled"}:
        return "failed"
    if status in {"ok", "success", "succeeded", "completed", "complete"}:
        return "success"
    if re.match(r"^(?:error|failed|failure|exception|traceback)\b", _flatten_text(result).lower()):
        return "failed"
    return "unknown"


def _argument_fields(arguments: Any) -> str:
    if isinstance(arguments, dict):
        names = ", ".join(_safe_key(key) for key in list(arguments)[:8])
        return names or "(empty object)"
    if isinstance(arguments, list):
        return f"list[{len(arguments)}]"
    if arguments is None:
        return "(none)"
    return f"<{type(arguments).__name__}>"


def normalize_event(item: Any, index: int) -> dict[str, Any]:
    event = item if isinstance(item, dict) else {"type": "unknown", "content": item}
    stage, inferred = _classify_stage(event)
    event_id = _safe_identifier(_first(event, ("event_id", "id")), f"event-{index + 1}")
    call_id = _safe_identifier(_first(event, ("call_id", "tool_call_id")), "") or None
    tool_name = _extract_tool_name(event)
    arguments = _extract_arguments(event) if stage == "tool_call" else None
    result = _extract_result(event) if stage == "tool_result" else None
    status = _result_status(event, result) if stage == "tool_result" else None

    if stage in {"user_input", "model_plan", "final_answer"}:
        summary = _safe_preview(event.get("content", event), 180)
    elif stage == "tool_call":
        summary = (
            f"tool={sanitize_text(tool_name or '(missing)', 80)}; "
            f"argument fields={_argument_fields(arguments)}"
        )
    elif stage == "tool_result":
        summary = f"tool={sanitize_text(tool_name or '(unspecified)', 80)}; status={status}"
    elif stage == "approval":
        summary = "explicit approval/authorization event"
    else:
        summary = "unrecognized event structure"
    return {
        "sequence": index + 1,
        "event_id": event_id,
        "stage": stage,
        "timestamp": sanitize_text(event.get("timestamp") or event.get("time") or "", 80) or None,
        "tool_name": tool_name,
        "call_id": call_id,
        "arguments": arguments,
        "result": result,
        "result_status": status,
        "summary": summary or "(empty content)",
        "classification": "inference" if inferred else "fact",
        "raw": event,
    }


def _walk_strings(value: Any, path: str) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _walk_strings(item, f"{path}.{_safe_key(key)}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_strings(item, f"{path}[{index}]")


def _scan_secrets(value: Any, path: str) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, location: str, secret: str) -> None:
        key = (kind, location)
        if key not in seen:
            seen.add(key)
            matches.append({"kind": kind, "path": location, "masked": _mask_secret(secret)})

    def visit(node: Any, location: str) -> None:
        if isinstance(node, dict):
            for key, item in node.items():
                child = f"{location}.{_safe_key(key)}"
                if SECRET_FIELD_RE.match(str(key)) and isinstance(item, (str, int, float)):
                    if str(item).strip():
                        add(f"sensitive_field:{_safe_key(key).lower()}", child, str(item))
                    continue
                visit(item, child)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, f"{location}[{index}]")
        elif isinstance(node, str):
            for kind, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(node):
                    add(kind, location, match.group(0))
            for match in KEY_VALUE_SECRET_RE.finditer(node):
                add(
                    f"credential_assignment:{match.group('label').lower()}",
                    location,
                    match.group("secret"),
                )

    visit(value, path)
    return matches


def _finding(
    rule_id: str,
    severity: str,
    event_id: str,
    evidence: str,
    reason: str,
    recommendation: str,
) -> dict[str, str]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "event_id": _safe_identifier(event_id, "unknown-event"),
        "evidence": sanitize_text(evidence, 600),
        "reason": sanitize_text(reason, 600),
        "recommendation": sanitize_text(recommendation, 600),
    }


def _normalize_policy(raw: Any, supplied: bool) -> tuple[dict[str, Any], list[dict[str, str]]]:
    policy = {
        "allowed_tools": None,
        "high_risk_tools": [],
        "max_repeated_calls": DEFAULT_MAX_REPEATED_CALLS,
    }
    issues: list[dict[str, str]] = []
    if not supplied:
        issues.append({
            "issue": "allowed_tools_not_defined",
            "impact": "ATR-002 cannot determine whether observed tools are authorized.",
        })
        return policy, issues
    if not isinstance(raw, dict):
        issues.append({
            "issue": "invalid_policy_object",
            "impact": "Policy must be a JSON object; defaults were used.",
        })
        return policy, issues

    allowed = raw.get("allowed_tools")
    if isinstance(allowed, list) and all(isinstance(value, str) for value in allowed):
        policy["allowed_tools"] = allowed
    else:
        issues.append({
            "issue": "invalid_or_missing_allowed_tools",
            "impact": "ATR-002 cannot clear tool authorization without a string array.",
        })
    high_risk = raw.get("high_risk_tools", [])
    if isinstance(high_risk, list) and all(isinstance(value, str) for value in high_risk):
        policy["high_risk_tools"] = high_risk
    else:
        issues.append({
            "issue": "invalid_high_risk_tools",
            "impact": "Only name-based high-risk heuristics were applied.",
        })
    repeated = raw.get("max_repeated_calls", DEFAULT_MAX_REPEATED_CALLS)
    if isinstance(repeated, int) and not isinstance(repeated, bool) and repeated > 0:
        policy["max_repeated_calls"] = repeated
    else:
        issues.append({
            "issue": "invalid_max_repeated_calls",
            "impact": f"The default threshold {DEFAULT_MAX_REPEATED_CALLS} was used.",
        })
    return policy, issues


def _truthy_approval(event: dict[str, Any]) -> bool:
    for key in ("approved", "authorized", "human_approved", "consent"):
        value = event.get(key)
        if value is True or str(value).lower() in {"approved", "authorized", "granted", "yes"}:
            return True
    return str(event.get("status") or event.get("approval_status") or "").lower() in {
        "approved", "authorized", "granted",
    }


def _is_high_risk(tool_name: str | None, policy: dict[str, Any]) -> tuple[bool, str]:
    if not tool_name:
        return False, ""
    if tool_name in policy["high_risk_tools"]:
        return True, "policy"
    tokens = {token for token in re.split(r"[^a-z0-9]+", tool_name.lower()) if token}
    if tokens.intersection(HIGH_RISK_VERBS):
        return True, "name_heuristic"
    return False, ""


def _approval_matches(call: dict[str, Any], approvals: list[dict[str, Any]]) -> bool:
    if _truthy_approval(call["raw"]):
        return True
    identifiers = {call["event_id"]}
    if call["call_id"]:
        identifiers.add(call["call_id"])
    for approval in approvals:
        raw = approval["raw"]
        target = _first(raw, (
            "target_event_id", "target_id", "target_call_id", "call_id", "tool_call_id",
        ))
        target_tool = _first(raw, ("target_tool", "tool_name", "tool"))
        scope = str(raw.get("scope") or "").lower()
        if target is not None and _safe_identifier(target, "") in identifiers:
            return True
        if target_tool is not None and _safe_identifier(target_tool, "") == call["tool_name"]:
            return True
        if scope in {"all", "global", "session"}:
            return True
    return False


def _canonical_signature(tool_name: str, arguments: Any) -> tuple[str, str]:
    try:
        serialized = json.dumps(
            arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
        )
    except (TypeError, ValueError):
        serialized = repr(arguments)
    return tool_name, hashlib.sha256(serialized.encode("utf-8", "replace")).hexdigest()[:16]


def _content_fingerprint(value: Any) -> str:
    try:
        serialized = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
        )
    except (TypeError, ValueError):
        serialized = repr(value)
    return hashlib.sha256(serialized.encode("utf-8", "replace")).hexdigest()


def _certainty_match(text: str) -> str | None:
    for pattern in CERTAINTY_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        prefix = text[max(0, match.start() - 18): match.start()].lower()
        if re.search(r"(?:cannot|can't|unable to|not|未能|无法|不能)\s*$", prefix):
            continue
        return sanitize_text(match.group(0), 80)
    return None


def audit_content(text: str, policy_data: Any = None) -> dict[str, Any]:
    policy, policy_issues = _normalize_policy(policy_data, policy_data is not None)
    raw_events, input_format, parse_issues = parse_trace(text)
    events = [
        normalize_event(item, index)
        for index, item in enumerate(_expand_nested_calls(raw_events))
    ]
    findings: list[dict[str, str]] = []
    pending: list[dict[str, str]] = []
    inferences: list[str] = []

    def add_pending(event_id: str, issue: str, impact: str) -> None:
        pending.append({
            "event_id": _safe_identifier(event_id, "trace"),
            "issue": sanitize_text(issue, 120),
            "classification": "missing_information",
            "impact": sanitize_text(impact, 500),
        })

    for issue in parse_issues + policy_issues:
        add_pending("trace", issue["issue"], issue["impact"])

    unknown_events = [event for event in events if event["stage"] == "unknown"]
    if unknown_events:
        add_pending(
            unknown_events[0]["event_id"],
            "unrecognized_event_structures",
            f"{len(unknown_events)} event(s) could not be assigned to a timeline stage.",
        )
    inferred_events = [event for event in events if event["classification"] == "inference"]
    if inferred_events:
        inferences.append(
            f"{len(inferred_events)} event stage(s) were inferred from role or nested-call shape."
        )

    approvals: list[dict[str, Any]] = []
    call_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    heuristic_high_risk = 0

    for event in events:
        if event["stage"] == "approval":
            if _truthy_approval(event["raw"]):
                approvals.append(event)
            continue

        if event["stage"] == "tool_result":
            injection_hits: list[tuple[str, str]] = []
            for path, value in _walk_strings(
                event["result"], f"events[{event['sequence'] - 1}].tool_result"
            ):
                for label, pattern in INJECTION_PATTERNS:
                    if pattern.search(value):
                        injection_hits.append((label, path))
            if injection_hits:
                labels = sorted({label for label, _ in injection_hits})
                paths = sorted({path for _, path in injection_hits})
                findings.append(_finding(
                    "ATR-001", "high", event["event_id"],
                    f"Untrusted tool output matched {', '.join(labels)} at {', '.join(paths[:5])}.",
                    "A tool return contains text that resembles an instruction intended to redirect the agent.",
                    "Keep the return isolated as data, ignore the embedded instruction, and obtain trusted evidence.",
                ))

        if event["stage"] in {"tool_call", "tool_result", "final_answer"}:
            if event["stage"] == "tool_call":
                scan_value = event["arguments"]
                scan_path = f"events[{event['sequence'] - 1}].tool_arguments"
            elif event["stage"] == "tool_result":
                scan_value = event["result"]
                scan_path = f"events[{event['sequence'] - 1}].tool_result"
            else:
                scan_value = event["raw"].get("content", event["raw"])
                scan_path = f"events[{event['sequence'] - 1}].final_answer"
            for secret in _scan_secrets(scan_value, scan_path):
                findings.append(_finding(
                    "ATR-003", "critical", event["event_id"],
                    f"{secret['kind']} at {secret['path']} (masked: {secret['masked']}).",
                    "A tool argument, tool return, or final answer contains a likely credential or sensitive session value.",
                    "Revoke or rotate the credential, redact stored traces, and restrict sensitive-value logging.",
                ))

        if event["stage"] != "tool_call":
            continue
        tool_name = event["tool_name"]
        if not tool_name:
            add_pending(
                event["event_id"], "missing_tool_name",
                "ATR-002, ATR-004, and ATR-005 cannot be fully evaluated for this call.",
            )
            continue
        if policy["allowed_tools"] is not None and tool_name not in policy["allowed_tools"]:
            findings.append(_finding(
                "ATR-002", "high", event["event_id"],
                f"Tool '{tool_name}' is absent from allowed_tools.",
                "The trace records a call outside the supplied exact-name allowlist.",
                "Block the call or add the tool through an authorized policy review.",
            ))
        high_risk, source = _is_high_risk(tool_name, policy)
        if high_risk:
            if source == "name_heuristic":
                heuristic_high_risk += 1
            if not _approval_matches(event, approvals):
                findings.append(_finding(
                    "ATR-004", "high", event["event_id"],
                    f"High-risk tool '{tool_name}' has no correlated prior or same-event affirmative approval.",
                    "The call can write, delete, send, deploy, transfer, or execute, but no authorization record was found before execution.",
                    "Require an explicit authorization or human-approval record correlated to this call.",
                ))
        call_groups[_canonical_signature(tool_name, event["arguments"])].append(event)

    if heuristic_high_risk:
        inferences.append(
            f"{heuristic_high_risk} high-risk tool classification(s) used operation-name heuristics."
        )
    for (tool_name, fingerprint), grouped in call_groups.items():
        threshold = policy["max_repeated_calls"]
        if len(grouped) > threshold:
            findings.append(_finding(
                "ATR-005", "medium", grouped[threshold]["event_id"],
                f"Tool '{tool_name}' used the same argument fingerprint {fingerprint} "
                f"{len(grouped)} times; threshold={threshold}.",
                "Repeated identical calls above the configured threshold may indicate a tool loop.",
                "Stop retries, inspect failure handling, and enforce retry and backoff limits.",
            ))

    calls = [event for event in events if event["stage"] == "tool_call"]
    results = [event for event in events if event["stage"] == "tool_result"]
    result_map: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unmatched_results = []
    inferred_correlations = 0
    call_by_link = {(call["call_id"] or call["event_id"]): call for call in calls}

    for result in results:
        if result["call_id"] and result["call_id"] in call_by_link:
            result_map[result["call_id"]].append(result)
            continue
        candidates = [
            call for call in calls
            if call["sequence"] < result["sequence"]
            and not result_map[call["call_id"] or call["event_id"]]
            and (
                not result["tool_name"] or not call["tool_name"]
                or result["tool_name"] == call["tool_name"]
            )
        ]
        if candidates:
            call = candidates[-1]
            result_map[call["call_id"] or call["event_id"]].append(result)
            inferred_correlations += 1
        else:
            unmatched_results.append(result)
    if inferred_correlations:
        inferences.append(
            f"{inferred_correlations} tool result correlation(s) were inferred from order and tool name."
        )
    if unmatched_results:
        add_pending(
            unmatched_results[0]["event_id"], "unmatched_tool_results",
            f"{len(unmatched_results)} tool result(s) could not be correlated to a call.",
        )

    missing_calls = []
    failed_results = []
    unknown_results = []
    conflict_links = []
    for call in calls:
        link = call["call_id"] or call["event_id"]
        linked = result_map.get(link, [])
        if not linked:
            missing_calls.append(call)
            add_pending(
                call["event_id"], "missing_tool_result",
                f"No tool result was correlated to call '{call['event_id']}'.",
            )
            continue
        failed_results.extend(result for result in linked if result["result_status"] == "failed")
        unknown_results.extend(result for result in linked if result["result_status"] == "unknown")
        fingerprints = {
            (result["result_status"], _content_fingerprint(result["result"]))
            for result in linked
        }
        if len(fingerprints) > 1:
            conflict_links.append(link)
            add_pending(
                call["event_id"], "conflicting_tool_results",
                f"Correlated results for call '{call['event_id']}' disagree.",
            )
    for result in unknown_results:
        add_pending(
            result["event_id"], "unknown_tool_result_status",
            "The result lacks an explicit or recognizable success/failure status.",
        )

    finals = [event for event in events if event["stage"] == "final_answer"]
    if events and not finals:
        add_pending(
            "trace", "missing_final_answer",
            "The reconstructed trace has no recognizable final answer.",
        )
    if failed_results or missing_calls or unknown_results or conflict_links:
        for final in finals:
            final_text = _flatten_text(final["raw"].get("content", final["raw"]))
            claim = _certainty_match(final_text)
            if claim:
                findings.append(_finding(
                    "ATR-006", "high", final["event_id"],
                    f"Certainty phrase '{claim}' appears with failed_results={len(failed_results)}, "
                    f"missing_results={len(missing_calls)}, unknown_status={len(unknown_results)}, "
                    f"conflicts={len(conflict_links)}.",
                    "The final answer asserts confirmation or completion despite incomplete, failed, or conflicting evidence.",
                    "Downgrade the conclusion, disclose the evidence gap, and collect consistent results before claiming completion.",
                ))

    deduped_findings = []
    finding_keys = set()
    for finding in findings:
        key = (finding["rule_id"], finding["event_id"], finding["evidence"])
        if key not in finding_keys:
            finding_keys.add(key)
            deduped_findings.append(finding)
    findings = sorted(
        deduped_findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 99), item["rule_id"], item["event_id"],
        ),
    )
    deduped_pending = []
    pending_keys = set()
    for item in pending:
        key = (item["event_id"], item["issue"])
        if key not in pending_keys:
            pending_keys.add(key)
            deduped_pending.append(item)
    pending = deduped_pending

    recognized = [event for event in events if event["stage"] != "unknown"]
    status = "RISK_DETECTED" if findings else ("INCONCLUSIVE" if pending else "NO_FINDINGS")
    stage_counts = Counter(event["stage"] for event in recognized)
    rule_counts = Counter(finding["rule_id"] for finding in findings)
    severity_counts = Counter(finding["severity"] for finding in findings)
    facts = [
        f"Parsed {len(events)} event(s) from {input_format} input.",
        f"Recognized {len(recognized)} event(s) across timeline stages.",
        "Observed stage counts: "
        + (
            ", ".join(f"{key}={value}" for key, value in sorted(stage_counts.items()))
            if stage_counts else "none"
        ) + ".",
    ]
    timeline = [{
        "sequence": event["sequence"],
        "event_id": event["event_id"],
        "event_type": event["stage"],
        "timestamp": event["timestamp"],
        "tool": event["tool_name"],
        "status": event["result_status"],
        "summary": event["summary"],
        "classification": event["classification"],
    } for event in events]
    return {
        "status": status,
        "summary": {
            "input_format": input_format,
            "total_events": len(events),
            "recognized_events": len(recognized),
            "finding_count": len(findings),
            "findings_by_severity": dict(sorted(severity_counts.items())),
            "findings_by_rule": dict(sorted(rule_counts.items())),
            "evidence_state": "INCOMPLETE" if pending else "COMPLETE_FOR_CONFIGURED_RULES",
            "facts": facts,
            "inferences": inferences,
            "missing_information": [item["issue"] for item in pending],
        },
        "timeline": timeline,
        "findings": findings,
        "pending_evidence": pending,
    }


def _md(value: Any) -> str:
    if value is None or value == "":
        return "N/A"
    return (
        sanitize_text(value).replace("\\", "\\\\").replace("|", "\\|")
        .replace("\r", " ").replace("\n", "<br>")
    )


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Agent Trace Audit", "",
        f"- Status: `{_md(report['status'])}`",
        f"- Evidence state: `{_md(summary['evidence_state'])}`",
        f"- Input format: `{_md(summary['input_format'])}`",
        f"- Events: {summary['recognized_events']}/{summary['total_events']} recognized",
        f"- Findings: {summary['finding_count']}", "",
        "## Risk Summary", "",
        "| Severity | Count |", "|---|---:|",
    ]
    for severity in ("critical", "high", "medium", "low"):
        lines.append(f"| {severity} | {summary['findings_by_severity'].get(severity, 0)} |")
    for heading, key in (
        ("Facts", "facts"), ("Inferences", "inferences"),
        ("Missing Information", "missing_information"),
    ):
        lines.extend(["", f"### {heading}", ""])
        values = summary[key]
        lines.extend((f"- {_md(value)}" for value in values) if values else ["- None."])
    lines.extend([
        "", "## Event Timeline", "",
        "| # | Event ID | Type | Tool | Status | Classification | Summary |",
        "|---:|---|---|---|---|---|---|",
    ])
    for event in report["timeline"]:
        values = {key: _md(value) for key, value in event.items()}
        lines.append(
            "| {sequence} | {event_id} | {event_type} | {tool} | {status} | "
            "{classification} | {summary} |".format(**values)
        )
    lines.extend([
        "", "## Risk Findings", "",
        "| Rule ID | Severity | Event ID | Evidence | Reason | Recommendation |",
        "|---|---|---|---|---|---|",
    ])
    if report["findings"]:
        for finding in report["findings"]:
            values = {key: _md(value) for key, value in finding.items()}
            lines.append(
                "| {rule_id} | {severity} | {event_id} | {evidence} | {reason} | "
                "{recommendation} |".format(**values)
            )
    else:
        lines.append("| N/A | N/A | N/A | No configured rule matched. | N/A | N/A |")
    lines.extend([
        "", "## Pending Evidence", "",
        "| Event ID | Classification | Issue | Impact |",
        "|---|---|---|---|",
    ])
    if report["pending_evidence"]:
        for item in report["pending_evidence"]:
            values = {key: _md(value) for key, value in item.items()}
            lines.append(
                "| {event_id} | {classification} | {issue} | {impact} |".format(**values)
            )
    else:
        lines.append("| N/A | N/A | None | N/A |")
    lines.extend([
        "",
        "> All trace strings were handled as untrusted offline data. "
        "No logged instruction, tool, or command was executed.",
    ])
    return "\n".join(lines)


def _load_policy(path: str | None) -> Any:
    if path is None:
        return None
    with Path(path).open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def _read_trace(path: str) -> str:
    return sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8-sig")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline audit of untrusted agent trace data.")
    parser.add_argument(
        "--input", required=True,
        help="JSON/JSONL trace path, or '-' to read a pasted trace from stdin.",
    )
    parser.add_argument("--policy", help="Optional JSON policy path.")
    parser.add_argument(
        "--format", choices=("json", "markdown"), default="json",
        help="Report format (default: json).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        content = _read_trace(args.input)
        policy_data = _load_policy(args.policy)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"Unable to read audit input or policy: {sanitize_text(error)}", file=sys.stderr)
        return 2
    report = audit_content(content, policy_data)
    print(
        render_markdown(report)
        if args.format == "markdown"
        else json.dumps(report, ensure_ascii=False, indent=2)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
