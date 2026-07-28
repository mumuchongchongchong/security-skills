#!/usr/bin/env python3
"""Deterministic offline audit of an unpacked third-party Agent Skill.

Target content is read as untrusted data. It is never imported, executed,
installed, followed through symbolic links, or used to initiate network I/O.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = "1.0"
DEFAULT_MAX_FILES = 1000
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_PREVIEW_CHARS = 180

TEXT_SUFFIXES = {
    ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".py", ".ps1",
    ".sh", ".bat", ".cmd", ".js", ".mjs", ".cjs", ".ts",
}
EXECUTABLE_TEXT_SUFFIXES = {
    ".py", ".ps1", ".sh", ".bat", ".cmd", ".js", ".mjs", ".cjs", ".ts",
}
DEPENDENCY_FILENAMES = {
    "requirements.txt", "requirements-dev.txt", "pyproject.toml",
    "package.json", "package-lock.json",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CONFIDENCE_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
RISKY_REVIEW_CAPABILITIES = {
    "filesystem.delete", "process.spawn", "code.dynamic-exec",
    "network.connect", "network.download", "network.upload",
    "environment.read", "credentials.read", "system.persistence",
    "package.install",
}

URL_RE = re.compile(r"\bhttps?://[^\s\"'<>`]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
SENSITIVE_KEY_RE = re.compile(
    r"(?:api[_-]?key|access[_-]?token|auth(?:orization)?|cookie|credential|"
    r"pass(?:word|wd)?|private[_-]?key|secret|session|token)",
    re.IGNORECASE,
)
SENSITIVE_PATH_RE = re.compile(
    r"(?:^|[\\/])(?:\.aws|\.azure|\.config|\.codex|\.gnupg|\.kube|\.ssh|"
    r"appdata|credentials?|id_rsa|id_ed25519|shadow)(?:[\\/]|$)",
    re.IGNORECASE,
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?P<label>api[_-]?key|access[_-]?token|authorization|cookie|credential|"
    r"pass(?:word|wd)?|private[_-]?key|secret|session|token)"
    r"\s*[:=]\s*[\"']?(?P<value>[^\s\"',;}{\[]{4,})",
    re.IGNORECASE,
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]{0,48}PRIVATE KEY-----",
    re.IGNORECASE,
)
TOKEN_SHAPE_RE = re.compile(
    r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{12,}|"
    r"(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{16,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16})\b"
)
BASE64_BLOB_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/]{40,}={0,2}|"
    r"[A-Za-z0-9_-]{48,}={0,2})(?![A-Za-z0-9+/=_-])"
)
BROAD_TRIGGER_RE = re.compile(
    r"\b(?:any|all|every)\s+(?:task|request|question|conversation)s?\b|"
    r"\bwhenever\b|任何任务|所有请求|任意问题",
    re.IGNORECASE,
)
OVERRIDE_PATTERNS = (
    (
        "ignore-prior-instructions",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b.{0,80}"
            r"\b(?:previous|prior|system|developer|original)\b.{0,30}"
            r"\binstructions?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "authority-override",
        re.compile(
            r"\b(?:replace|override)\b.{0,40}"
            r"\b(?:system|developer)\b.{0,30}\b(?:prompt|message|instructions?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ignore-prior-instructions-zh",
        re.compile(r"(?:忽略|无视|覆盖).{0,40}(?:之前|先前|系统|开发者).{0,20}(?:指令|提示)"),
    ),
)
BYPASS_PATTERNS = (
    (
        "skip-approval",
        re.compile(
            r"\b(?:skip|bypass|avoid|disable)\b.{0,50}"
            r"\b(?:approval|confirmation|permission|safeguard|guardrail)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "act-without-confirmation",
        re.compile(
            r"\b(?:without|do not (?:ask|request))\b.{0,40}"
            r"\b(?:approval|confirmation|permission)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "skip-approval-zh",
        re.compile(r"(?:绕过|跳过|禁用).{0,30}(?:审批|确认|权限|安全限制)"),
    ),
)
NETWORK_DECLARATION_RE = re.compile(
    r"\b(?:require|use|access|connect|fetch|send|call|query|download|upload)"
    r"\w*\b.{0,40}\b(?:network|internet|https?|api|webhook|endpoint)\b|"
    r"\bnetwork\s+access\b|\bapi\s+(?:request|endpoint|integration)\b|"
    r"(?:需要联网|访问网络|连接网络|调用.{0,20}(?:接口|API)|"
    r"查询.{0,20}(?:接口|API)|发送.{0,20}(?:网络|端点)|下载|上传)",
    re.IGNORECASE,
)
OFFLINE_DECLARATION_RE = re.compile(
    r"\b(?:fully\s+)?offline\b|\bno\s+network\b|不访问网络|完全离线",
    re.IGNORECASE,
)
READONLY_DECLARATION_RE = re.compile(
    r"\bread[- ]?only\b|只读|不修改",
    re.IGNORECASE,
)
LOCAL_DECLARATION_RE = re.compile(
    r"\blocal[- ]?only\b|\bonly local\b|仅本地|纯本地",
    re.IGNORECASE,
)
TRAVERSAL_RE = re.compile(r"(?:^|[\"'\s(])\.\.[\\/]+")
UNPINNED_INSTALL_RE = re.compile(
    r"\b(?:pip(?:3)?\s+install|npm\s+install|yarn\s+add|pnpm\s+add)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Limits:
    max_files: int = DEFAULT_MAX_FILES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES

    def __post_init__(self) -> None:
        maxima = {
            "max_files": DEFAULT_MAX_FILES,
            "max_file_bytes": DEFAULT_MAX_FILE_BYTES,
            "max_total_bytes": DEFAULT_MAX_TOTAL_BYTES,
        }
        for name, maximum in maxima.items():
            value = getattr(self, name)
            if value < 1 or value > maximum:
                raise ValueError(f"{name} must be between 1 and {maximum}")

    def as_dict(self) -> dict[str, int]:
        return {
            "max_files": self.max_files,
            "max_file_bytes": self.max_file_bytes,
            "max_total_bytes": self.max_total_bytes,
        }


@dataclass(frozen=True)
class TextIndicator:
    name: str
    description: str
    pattern: re.Pattern[str]
    capabilities: tuple[str, ...] = ()
    rule_id: str | None = None
    severity: str = "MEDIUM"


SHELL_INDICATORS = (
    TextIndicator(
        "curl-download", "curl can retrieve external content",
        re.compile(r"\bcurl(?:\.exe)?\b", re.IGNORECASE),
        ("network.connect", "network.download"),
    ),
    TextIndicator(
        "wget-download", "wget can retrieve external content",
        re.compile(r"\bwget(?:\.exe)?\b", re.IGNORECASE),
        ("network.connect", "network.download"),
    ),
    TextIndicator(
        "invoke-webrequest", "PowerShell web request can retrieve content",
        re.compile(r"\bInvoke-WebRequest\b|\biwr\b", re.IGNORECASE),
        ("network.connect", "network.download"),
    ),
    TextIndicator(
        "invoke-expression", "PowerShell dynamic expression execution",
        re.compile(r"\bInvoke-Expression\b|\bIEX\b", re.IGNORECASE),
        ("code.dynamic-exec",), "ASC-007", "HIGH",
    ),
    TextIndicator(
        "start-process", "PowerShell process launch",
        re.compile(r"\bStart-Process\b", re.IGNORECASE),
        ("process.spawn",),
    ),
    TextIndicator(
        "powershell-encoded", "Encoded PowerShell command",
        re.compile(r"\bpowershell(?:\.exe)?\b[^\r\n]{0,120}-(?:enc|encodedcommand)\b", re.IGNORECASE),
        ("code.dynamic-exec",), "ASC-003", "HIGH",
    ),
    TextIndicator(
        "certutil-transfer", "certutil can retrieve or decode content",
        re.compile(r"\bcertutil(?:\.exe)?\b", re.IGNORECASE),
        ("network.download",),
    ),
    TextIndicator(
        "bitsadmin-transfer", "BITS transfer command",
        re.compile(r"\bbitsadmin(?:\.exe)?\b", re.IGNORECASE),
        ("network.connect", "network.download"),
    ),
    TextIndicator(
        "bash-command", "Shell command execution",
        re.compile(r"\bbash\b[^\r\n]{0,40}\s-c\b", re.IGNORECASE),
        ("process.spawn",),
    ),
    TextIndicator(
        "chmod-executable", "Marks content executable",
        re.compile(r"\bchmod\b[^\r\n]{0,40}\+x\b", re.IGNORECASE),
        ("filesystem.write",),
    ),
    TextIndicator(
        "recursive-delete", "Recursive filesystem deletion",
        re.compile(r"\brm\b[^\r\n]{0,40}-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-rf\b", re.IGNORECASE),
        ("filesystem.delete",), "ASC-008", "HIGH",
    ),
    TextIndicator(
        "scheduled-task", "Scheduled-task persistence",
        re.compile(r"\bschtasks(?:\.exe)?\b|\bcrontab\b", re.IGNORECASE),
        ("system.persistence",), "ASC-008", "HIGH",
    ),
    TextIndicator(
        "registry-run-key", "Registry Run-key persistence",
        re.compile(r"\\CurrentVersion\\Run(?:Once)?\b|\bHK(?:CU|LM)\\[^\r\n]{0,120}\\Run(?:Once)?\b", re.IGNORECASE),
        ("system.persistence",), "ASC-008", "HIGH",
    ),
    TextIndicator(
        "package-install", "External dependency installation",
        UNPINNED_INSTALL_RE,
        ("package.install",),
    ),
    TextIndicator(
        "javascript-fetch", "JavaScript network request",
        re.compile(r"\bfetch\s*\(|\baxios\.(?:get|post|put|request)\s*\(", re.IGNORECASE),
        ("network.connect",),
    ),
    TextIndicator(
        "javascript-process", "JavaScript child process launch",
        re.compile(r"\bchild_process\b|\b(?:exec|spawn|execFile)\s*\(", re.IGNORECASE),
        ("process.spawn",),
    ),
    TextIndicator(
        "javascript-eval", "JavaScript dynamic execution",
        re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(", re.IGNORECASE),
        ("code.dynamic-exec",), "ASC-007", "HIGH",
    ),
)
DOWNLOAD_EXEC_RE = re.compile(
    r"(?:curl|wget|Invoke-WebRequest|iwr|certutil|bitsadmin)"
    r"[^\r\n]{0,300}(?:&&|\|\||[|;])[^\r\n]{0,160}"
    r"(?:powershell|cmd(?:\.exe)?|bash|sh|python|Start-Process|chmod)",
    re.IGNORECASE,
)


MAGIC_SIGNATURES = (
    ("PE/MZ", b"MZ", {".exe", ".dll", ".sys", ".scr"}),
    ("ELF", b"\x7fELF", {"", ".so", ".elf"}),
    ("ZIP", b"PK\x03\x04", {".zip", ".jar", ".whl", ".docx", ".xlsx", ".pptx"}),
    ("PDF", b"%PDF-", {".pdf"}),
    ("PNG", b"\x89PNG\r\n\x1a\n", {".png"}),
    ("JPEG", b"\xff\xd8\xff", {".jpg", ".jpeg"}),
    ("gzip", b"\x1f\x8b", {".gz", ".tgz"}),
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _line_for_offset(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    start = text.rfind("\n", 0, offset)
    column = offset - start
    return line, column


def _byte_offset(text: str, character_offset: int) -> int:
    return len(text[:character_offset].encode("utf-8", "replace"))


def _mask_value(value: str) -> str:
    if len(value) <= 4:
        return "***"
    return value[:1] + "***" + value[-1:]


def redact_text(value: Any) -> str:
    text = str(value)
    text = PRIVATE_KEY_RE.sub("[REDACTED:private-key-marker]", text)
    text = TOKEN_SHAPE_RE.sub("[REDACTED:token]", text)
    text = SECRET_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group('label')}=[REDACTED:{_mask_value(match.group('value'))}]",
        text,
    )
    return text


def safe_preview(value: Any, limit: int = MAX_PREVIEW_CHARS) -> str:
    text = redact_text(value)
    escaped: list[str] = []
    for char in text:
        code = ord(char)
        category = unicodedata.category(char)
        unsafe = (
            0x202A <= code <= 0x202E
            or 0x2066 <= code <= 0x2069
            or code in {0x200B, 0x200C, 0x200D, 0xFEFF}
            or (category == "Cc" and char not in "\t\n\r")
        )
        if unsafe:
            name = unicodedata.name(char, "CONTROL")
            escaped.append(f"<U+{code:04X} {name}>")
        elif char in "\r\n\t":
            escaped.append(" ")
        else:
            escaped.append(char)
    normalized = re.sub(r"\s+", " ", "".join(escaped)).strip()
    if len(normalized) > limit:
        return normalized[: max(0, limit - 1)] + "…"
    return normalized


def evidence(
    relative_path: str,
    *,
    line: int | None = None,
    column: int | None = None,
    byte_offset: int | None = None,
    snippet: str,
    detection: str,
    context: str,
) -> dict[str, Any]:
    return {
        "path": relative_path,
        "line": line,
        "column": column,
        "byte_offset": byte_offset,
        "snippet": safe_preview(snippet),
        "detection": detection,
        "context": context,
    }


def file_context(relative_path: str) -> str:
    parts = tuple(part.casefold() for part in Path(relative_path).parts)
    if "tests" in parts or "fixtures" in parts:
        return "test_fixture"
    if relative_path.casefold().startswith("references/") or relative_path.casefold().endswith(".md"):
        return "documentation"
    return "runtime"


def detect_magic(data: bytes) -> tuple[str | None, set[str] | None]:
    for name, signature, suffixes in MAGIC_SIGNATURES:
        if data.startswith(signature):
            return name, suffixes
    return None, None


def looks_textual(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(
        1 for char in decoded
        if char.isprintable() or char in "\t\n\r"
    )
    return printable / max(1, len(decoded)) >= 0.85


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)):
        values = [literal_string(item) for item in node.elts]
        if all(value is not None for value in values):
            return " ".join(value for value in values if value is not None)
    return None


class AuditState:
    def __init__(self, target_name: str, limits: Limits) -> None:
        self.target_name = safe_preview(target_name, 100)
        self.limits = limits
        self.files: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []
        self.endpoints: list[dict[str, Any]] = []
        self.capabilities: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.findings: list[dict[str, Any]] = []
        self.correlations: list[dict[str, Any]] = []
        self.execution_references: list[dict[str, Any]] = []
        self.limitations: list[dict[str, Any]] = []
        self.bytes_read = 0
        self.text_files_scanned = 0
        self.metadata_only_files = 0
        self.symlinks = 0
        self.files_scanned = 0
        self.skill_text: str | None = None
        self.skill_description = ""
        self.discovery_truncated = False
        self.entries_considered = 0

    def add_capability(self, name: str, item: dict[str, Any]) -> None:
        key = json.dumps(item, ensure_ascii=False, sort_keys=True)
        existing = {
            json.dumps(value, ensure_ascii=False, sort_keys=True)
            for value in self.capabilities[name]
        }
        if key not in existing:
            self.capabilities[name].append(item)

    def add_import(self, module: str, item: dict[str, Any]) -> None:
        record = {"module": safe_preview(module, 120), "evidence": item}
        key = json.dumps(record, ensure_ascii=False, sort_keys=True)
        if key not in {
            json.dumps(value, ensure_ascii=False, sort_keys=True)
            for value in self.imports
        }:
            self.imports.append(record)

    def add_endpoint(self, url: str, item: dict[str, Any]) -> None:
        redacted = redact_url(url)
        domain_match = DOMAIN_RE.search(redacted)
        record = {
            "url": safe_preview(redacted, 240),
            "domain": safe_preview(domain_match.group(0), 120) if domain_match else "unknown",
            "evidence": item,
        }
        key = json.dumps(record, ensure_ascii=False, sort_keys=True)
        if key not in {
            json.dumps(value, ensure_ascii=False, sort_keys=True)
            for value in self.endpoints
        }:
            self.endpoints.append(record)

    def add_finding(
        self,
        rule_id: str,
        title: str,
        severity: str,
        confidence: str,
        category: str,
        evidence_items: Iterable[dict[str, Any]],
        explanation: str,
        remediation: str,
    ) -> None:
        items = list(evidence_items)
        if not items:
            return
        candidate = {
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "evidence": items,
            "explanation": explanation,
            "remediation": remediation,
        }
        identity = (
            rule_id,
            tuple(
                (item["path"], item.get("line"), item.get("byte_offset"), item["detection"])
                for item in items
            ),
        )
        for current in self.findings:
            current_identity = (
                current["rule_id"],
                tuple(
                    (item["path"], item.get("line"), item.get("byte_offset"), item["detection"])
                    for item in current["evidence"]
                ),
            )
            if current_identity == identity:
                return
        self.findings.append(candidate)

    def add_limitation(
        self,
        kind: str,
        relative_path: str,
        detail: str,
    ) -> None:
        item = {
            "kind": kind,
            "path": relative_path,
            "detail": safe_preview(detail, 240),
        }
        if item not in self.limitations:
            self.limitations.append(item)


def redact_url(url: str) -> str:
    value = redact_text(url)
    value = re.sub(
        r"(?i)([?&](?:token|key|secret|password|signature|auth)=)[^&#\s]+",
        r"\1[REDACTED]",
        value,
    )
    value = re.sub(r"(?i)(https?://)[^/@\s]+@", r"\1[REDACTED]@", value)
    return value


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, state: AuditState, relative_path: str, context: str) -> None:
        self.state = state
        self.relative_path = relative_path
        self.context = context

    def ev(self, node: ast.AST, snippet: str, detection: str = "python-ast") -> dict[str, Any]:
        return evidence(
            self.relative_path,
            line=getattr(node, "lineno", None),
            column=(getattr(node, "col_offset", 0) + 1) if hasattr(node, "col_offset") else None,
            snippet=snippet,
            detection=detection,
            context=self.context,
        )

    def add_cap(self, name: str, node: ast.AST, snippet: str) -> None:
        self.state.add_capability(name, self.ev(node, snippet))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.record_import(alias.name, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        self.record_import(module, node)
        self.generic_visit(node)

    def record_import(self, module: str, node: ast.AST) -> None:
        if not module:
            return
        item = self.ev(node, f"import {module}", "python-import")
        self.state.add_import(module, item)
        root = module.split(".")[0]
        if root in {"socket", "urllib", "http", "requests"}:
            self.state.add_capability("network.connect", item)
        if root == "subprocess":
            self.state.add_capability("process.spawn", item)
        if root in {"ctypes", "importlib"}:
            self.state.add_capability("code.dynamic-exec", item)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        name = dotted_name(node.value)
        if name in {"os.environ", "environ"}:
            key = literal_string(node.slice)
            item = self.ev(node, "environment lookup")
            self.state.add_capability("environment.read", item)
            if key and SENSITIVE_KEY_RE.search(key):
                secret_item = self.ev(node, "credential-like environment key")
                self.state.add_capability("credentials.read", secret_item)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted_name(node.func)
        lower = name.casefold()
        item = self.ev(node, f"call {name or '<dynamic>'}")
        is_process_call = lower in {"os.system", "os.popen"} or lower.startswith("subprocess.")

        if lower in {"eval", "exec", "compile", "__import__"}:
            self.state.add_capability("code.dynamic-exec", item)
        if lower in {"pickle.loads", "marshal.loads"}:
            self.state.add_capability("code.dynamic-exec", item)
        if is_process_call:
            self.state.add_capability("process.spawn", item)
        if lower in {
            "os.remove", "os.unlink", "shutil.rmtree", "path.unlink", "path.rmdir",
        } or lower.endswith((".unlink", ".rmdir")):
            self.state.add_capability("filesystem.delete", item)
        if lower in {"open", "io.open"}:
            mode = literal_string(node.args[1]) if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == "mode":
                    mode = literal_string(keyword.value)
            if mode and any(flag in mode for flag in "wax+"):
                self.state.add_capability("filesystem.write", item)
            else:
                self.state.add_capability("filesystem.read", item)
        if lower.endswith((".read_text", ".read_bytes", ".open")):
            self.state.add_capability("filesystem.read", item)
        if lower.endswith((".write_text", ".write_bytes", ".touch", ".mkdir", ".rename", ".replace")):
            self.state.add_capability("filesystem.write", item)
        if lower in {"os.getenv", "os.environ.get"} or lower.endswith(".getenv"):
            self.state.add_capability("environment.read", item)
            key = literal_string(node.args[0]) if node.args else None
            if key and SENSITIVE_KEY_RE.search(key):
                secret_item = self.ev(node, "credential-like environment key")
                self.state.add_capability("credentials.read", secret_item)

        if lower.startswith("socket.") or lower.endswith((".connect", ".create_connection")):
            self.state.add_capability("network.connect", item)
        if lower.endswith((".send", ".sendall", ".sendto")):
            self.state.add_capability("network.connect", item)
            self.state.add_capability("network.upload", item)
        if lower.endswith((".recv", ".recvfrom")):
            self.state.add_capability("network.download", item)
        if lower in {
            "urllib.request.urlopen", "urllib.request.urlretrieve",
            "requests.get", "http.client.httpconnection",
        } or lower.endswith((".urlopen", ".urlretrieve")):
            self.state.add_capability("network.connect", item)
            self.state.add_capability("network.download", item)
        if lower in {"requests.post", "requests.put", "requests.patch"}:
            self.state.add_capability("network.connect", item)
            self.state.add_capability("network.upload", item)
        if lower == "urllib.request.request" or lower.endswith(".request"):
            has_data = any(keyword.arg == "data" for keyword in node.keywords)
            if has_data:
                self.state.add_capability("network.connect", item)
                self.state.add_capability("network.upload", item)
        if lower.startswith("winreg.") and any(
            token in lower for token in ("setvalue", "createkey")
        ):
            self.state.add_capability("system.persistence", item)

        literal_args = " ".join(
            value for value in (literal_string(arg) for arg in node.args)
            if value is not None
        )
        if literal_args:
            if is_process_call:
                for token in re.findall(r"[A-Za-z0-9_.\\/-]+", literal_args):
                    basename = Path(token).name
                    if "." not in basename:
                        continue
                    record = {
                        "basename": safe_preview(basename, 100),
                        "evidence": self.ev(node, f"process references file {basename}"),
                    }
                    if record not in self.state.execution_references:
                        self.state.execution_references.append(record)
            if SENSITIVE_PATH_RE.search(literal_args):
                self.state.add_capability(
                    "credentials.read",
                    self.ev(node, "sensitive-directory path category"),
                )
            if TRAVERSAL_RE.search(literal_args):
                traversal_item = self.ev(node, "parent-directory traversal")
                self.state.add_finding(
                    "ASC-009", "Path traversal or out-of-scope access",
                    "MEDIUM", "HIGH", "filesystem-boundary",
                    [traversal_item],
                    "Executable source contains a parent-directory path that may escape the Skill root.",
                    "Normalize against an approved root and reject paths that leave it.",
                )
            if re.search(r"\b(?:pip|pip3|npm|yarn|pnpm)\b.{0,40}\b(?:install|add)\b", literal_args, re.I):
                self.state.add_capability("package.install", item)
                if "==" not in literal_args and "@sha256:" not in literal_args:
                    self.state.add_finding(
                        "ASC-011", "Unpinned external dependency",
                        "MEDIUM", "HIGH", "dependency-integrity",
                        [self.ev(node, "package install without exact version")],
                        "An install invocation does not show an exact version or integrity identifier.",
                        "Pin the dependency and record a trusted source and integrity metadata.",
                    )
            if re.search(r"\b(?:schtasks|crontab)\b|CurrentVersion[\\/]Run", literal_args, re.I):
                self.state.add_capability("system.persistence", item)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and SENSITIVE_PATH_RE.search(node.value):
            self.state.add_capability(
                "credentials.read",
                self.ev(node, "sensitive-directory path literal"),
            )
        self.generic_visit(node)


def parse_frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    result: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return result
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in {"name", "description"}:
            result[key] = value.strip().strip("\"'")
    return {}


def _walk_directory(
    directory: Path,
    state: AuditState,
    entries: list[Path],
) -> None:
    try:
        children = sorted(directory.iterdir(), key=lambda item: item.name.casefold())
    except OSError as error:
        relative = "." if directory.name == state.target_name else safe_preview(directory.name)
        state.add_limitation("directory_unreadable", relative, type(error).__name__)
        return
    for child in children:
        if state.discovery_truncated:
            return
        try:
            is_link = child.is_symlink()
            is_directory = child.is_dir() if not is_link else False
        except OSError as error:
            state.add_limitation("entry_metadata_unreadable", safe_preview(child.name), type(error).__name__)
            continue
        if is_directory:
            _walk_directory(child, state, entries)
            continue
        state.entries_considered += 1
        if len(entries) >= state.limits.max_files:
            state.discovery_truncated = True
            state.add_limitation(
                "max_files_reached", ".",
                f"Stopped after {state.limits.max_files} entries; at least one entry remains unscanned.",
            )
            return
        entries.append(child)


def link_target_description(path: Path) -> str:
    try:
        target = path.readlink()
    except OSError:
        return "unreadable-link-target"
    if target.is_absolute():
        return "<absolute-target-redacted>"
    return safe_preview(target.as_posix(), 160)


def scan_unicode(
    state: AuditState,
    text: str,
    relative_path: str,
    context: str,
) -> None:
    for offset, char in enumerate(text):
        code = ord(char)
        category = unicodedata.category(char)
        hidden = (
            0x202A <= code <= 0x202E
            or 0x2066 <= code <= 0x2069
            or code in {0x200B, 0x200C, 0x200D}
            or (code == 0xFEFF and offset != 0)
            or (category == "Cc" and char not in "\t\n\r")
        )
        if not hidden:
            continue
        line, column = _line_for_offset(text, offset)
        code_name = unicodedata.name(char, "CONTROL")
        item = evidence(
            relative_path,
            line=line,
            column=column,
            byte_offset=_byte_offset(text, offset),
            snippet=f"U+{code:04X} {code_name}",
            detection="unicode-codepoint-scan",
            context=context,
        )
        severity = "HIGH" if 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069 else "MEDIUM"
        state.add_finding(
            "ASC-002", "Hidden Unicode control character",
            severity, "HIGH", "unicode-obfuscation", [item],
            "A hidden or direction-changing Unicode code point can conceal or reorder reviewed text.",
            "Remove the code point or document a narrowly reviewed need.",
        )


def scan_instruction_text(
    state: AuditState,
    text: str,
    relative_path: str,
    context: str,
) -> None:
    for name, pattern in OVERRIDE_PATTERNS:
        for match in pattern.finditer(text):
            line, column = _line_for_offset(text, match.start())
            item = evidence(
                relative_path, line=line, column=column,
                byte_offset=_byte_offset(text, match.start()),
                snippet=f"matched instruction override category: {name}",
                detection=f"instruction-pattern:{name}", context=context,
            )
            state.add_finding(
                "ASC-001", "Instruction hierarchy override",
                "HIGH", "HIGH", "prompt-injection", [item],
                "Untrusted Skill content contains language that attempts to replace or ignore higher-priority instructions.",
                "Remove the override and keep target content explicitly scoped as data.",
            )
    for name, pattern in BYPASS_PATTERNS:
        for match in pattern.finditer(text):
            line, column = _line_for_offset(text, match.start())
            item = evidence(
                relative_path, line=line, column=column,
                byte_offset=_byte_offset(text, match.start()),
                snippet=f"matched approval bypass category: {name}",
                detection=f"approval-bypass-pattern:{name}", context=context,
            )
            state.add_finding(
                "ASC-013", "Approval or safety bypass request",
                "HIGH", "HIGH", "authorization-bypass", [item],
                "Untrusted Skill content requests bypassing an approval, permission, or safety boundary.",
                "Remove the bypass request and require explicit authorization.",
            )


def scan_endpoints(
    state: AuditState,
    text: str,
    relative_path: str,
    context: str,
) -> None:
    for match in URL_RE.finditer(text):
        line, column = _line_for_offset(text, match.start())
        state.add_endpoint(
            match.group(0).rstrip(".,);]"),
            evidence(
                relative_path, line=line, column=column,
                byte_offset=_byte_offset(text, match.start()),
                snippet="external URL",
                detection="url-pattern", context=context,
            ),
        )


def scan_encoding(
    state: AuditState,
    text: str,
    relative_path: str,
    context: str,
) -> None:
    for match in BASE64_BLOB_RE.finditer(text):
        candidate = match.group(0)
        if len(set(candidate)) < 8:
            continue
        line, column = _line_for_offset(text, match.start())
        item = evidence(
            relative_path, line=line, column=column,
            byte_offset=_byte_offset(text, match.start()),
            snippet=f"structured encoded candidate length={len(candidate)}",
            detection="bounded-encoding-indicator", context=context,
        )
        state.add_finding(
            "ASC-003", "Suspected encoded or obfuscated content",
            "MEDIUM", "LOW", "obfuscation", [item],
            "A long structured encoding candidate may conceal content, but encoding alone is not malicious.",
            "Review the transformation and, if needed, inspect it with a bounded offline decoder.",
        )


def scan_dependencies(
    state: AuditState,
    text: str,
    relative_path: str,
    context: str,
) -> None:
    name = Path(relative_path).name.casefold()
    if name.startswith("requirements") and name.endswith(".txt"):
        for line_number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-", "git+", "http:")):
                continue
            state.add_capability(
                "package.install",
                evidence(
                    relative_path, line=line_number, snippet="dependency declaration",
                    detection="dependency-manifest", context=context,
                ),
            )
            if "==" not in stripped or "--hash=" not in stripped:
                state.add_finding(
                    "ASC-011", "Dependency lacks exact version or integrity metadata",
                    "MEDIUM", "HIGH", "dependency-integrity",
                    [evidence(
                        relative_path, line=line_number,
                        snippet="dependency without complete pin and hash",
                        detection="dependency-pin-check", context=context,
                    )],
                    "A dependency declaration lacks an exact version or integrity hash.",
                    "Pin the exact version and include trusted integrity metadata.",
                )
    elif name in DEPENDENCY_FILENAMES and UNPINNED_INSTALL_RE.search(text):
        match = UNPINNED_INSTALL_RE.search(text)
        assert match is not None
        line, column = _line_for_offset(text, match.start())
        state.add_capability(
            "package.install",
            evidence(
                relative_path, line=line, column=column,
                snippet="package install command",
                detection="package-install-pattern", context=context,
            ),
        )


def scan_executable_patterns(
    state: AuditState,
    text: str,
    relative_path: str,
    context: str,
) -> None:
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        for indicator in SHELL_INDICATORS:
            match = indicator.pattern.search(line)
            if not match:
                continue
            item = evidence(
                relative_path, line=line_number, column=match.start() + 1,
                snippet=f"matched executable indicator: {indicator.name}",
                detection=f"executable-pattern:{indicator.name}", context=context,
            )
            for capability in indicator.capabilities:
                state.add_capability(capability, item)
            if indicator.rule_id:
                state.add_finding(
                    indicator.rule_id,
                    indicator.description,
                    indicator.severity,
                    "HIGH",
                    "executable-behavior",
                    [item],
                    f"Executable content matched the named {indicator.name} behavior indicator.",
                    "Remove the behavior or document and constrain it for explicit review.",
                )
        if UNPINNED_INSTALL_RE.search(line) and "==" not in line and "@sha256:" not in line:
            state.add_finding(
                "ASC-011", "Unpinned external dependency installation",
                "MEDIUM", "HIGH", "dependency-integrity",
                [evidence(
                    relative_path, line=line_number,
                    snippet="install command without exact version",
                    detection="unpinned-install-pattern", context=context,
                )],
                "An executable install command lacks an exact version or integrity identifier.",
                "Pin the exact dependency and verify its source and integrity.",
            )
        if TRAVERSAL_RE.search(line):
            match = TRAVERSAL_RE.search(line)
            assert match is not None
            state.add_finding(
                "ASC-009", "Path traversal or out-of-scope access",
                "MEDIUM", "MEDIUM", "filesystem-boundary",
                [evidence(
                    relative_path, line=line_number, column=match.start() + 1,
                    snippet="parent-directory traversal indicator",
                    detection="path-traversal-pattern", context=context,
                )],
                "Executable text contains a parent-directory traversal indicator.",
                "Resolve against an approved root and reject out-of-scope paths.",
            )
        if DOWNLOAD_EXEC_RE.search(line):
            match = DOWNLOAD_EXEC_RE.search(line)
            assert match is not None
            item = evidence(
                relative_path, line=line_number, column=match.start() + 1,
                snippet="download followed by execution on one command line",
                detection="download-execute-chain-pattern", context=context,
            )
            state.add_capability("network.download", item)
            state.add_capability("process.spawn", item)


def scan_text_file(
    state: AuditState,
    text: str,
    relative_path: str,
) -> None:
    context = file_context(relative_path)
    scan_unicode(state, text, relative_path, context)
    scan_instruction_text(state, text, relative_path, context)
    scan_endpoints(state, text, relative_path, context)
    scan_encoding(state, text, relative_path, context)
    scan_dependencies(state, text, relative_path, context)
    suffix = Path(relative_path).suffix.casefold()
    if suffix in EXECUTABLE_TEXT_SUFFIXES:
        scan_executable_patterns(state, text, relative_path, context)
    if suffix == ".py":
        try:
            tree = ast.parse(text, filename=relative_path)
        except (SyntaxError, ValueError) as error:
            line = getattr(error, "lineno", None)
            state.add_limitation(
                "python_parse_error", relative_path,
                f"{type(error).__name__} at line {line or 'unknown'}; regex coverage retained.",
            )
        else:
            PythonAnalyzer(state, relative_path, context).visit(tree)


def scan_entry(state: AuditState, root: Path, path: Path) -> None:
    relative_path = path.relative_to(root).as_posix()
    context = file_context(relative_path)
    try:
        metadata = path.lstat()
    except OSError as error:
        state.add_limitation("metadata_unreadable", relative_path, type(error).__name__)
        return
    if stat.S_ISLNK(metadata.st_mode):
        state.symlinks += 1
        state.files.append({
            "path": relative_path,
            "size": metadata.st_size,
            "sha256": None,
            "inferred_type": "symbolic-link",
            "header_type": None,
            "extension_matches_header": None,
            "is_symlink": True,
            "link_target": link_target_description(path),
            "context": context,
            "scan_status": "metadata-only",
        })
        item = evidence(
            relative_path, byte_offset=0, snippet="symbolic link not followed",
            detection="filesystem-lstat", context=context,
        )
        state.add_finding(
            "ASC-009", "Symbolic link in Skill",
            "MEDIUM", "HIGH", "filesystem-boundary", [item],
            "The target contains a symbolic link; its destination was recorded but not followed.",
            "Replace the link with reviewed in-tree content or document and constrain it.",
        )
        return
    if not stat.S_ISREG(metadata.st_mode):
        state.add_limitation("unsupported_special_file", relative_path, "Non-regular file was not read.")
        return

    size = metadata.st_size
    entry = {
        "path": relative_path,
        "size": size,
        "sha256": None,
        "inferred_type": "unread",
        "header_type": None,
        "extension_matches_header": None,
        "is_symlink": False,
        "link_target": None,
        "context": context,
        "scan_status": "not-read",
    }
    state.files.append(entry)
    if size > state.limits.max_file_bytes:
        state.add_limitation(
            "max_file_bytes_reached", relative_path,
            f"File size {size} exceeds the configured per-file limit {state.limits.max_file_bytes}.",
        )
        return
    if state.bytes_read + size > state.limits.max_total_bytes:
        state.add_limitation(
            "max_total_bytes_reached", relative_path,
            f"Reading this file would exceed {state.limits.max_total_bytes} total bytes.",
        )
        return
    try:
        if path.is_symlink():
            state.add_limitation("symlink_race_detected", relative_path, "Entry changed to a symlink before read.")
            return
        with path.open("rb") as handle:
            data = handle.read(state.limits.max_file_bytes + 1)
    except OSError as error:
        state.add_limitation("file_unreadable", relative_path, type(error).__name__)
        return
    if len(data) > state.limits.max_file_bytes:
        state.add_limitation("max_file_bytes_reached", relative_path, "File grew beyond the read limit.")
        return
    state.bytes_read += len(data)
    state.files_scanned += 1
    entry["sha256"] = sha256_hex(data)
    entry["scan_status"] = "scanned"
    header_type, allowed_suffixes = detect_magic(data)
    suffix = path.suffix.casefold()
    entry["header_type"] = header_type
    entry["inferred_type"] = header_type or (
        f"text/{suffix.lstrip('.') or 'plain'}" if suffix in TEXT_SUFFIXES else
        ("text/unknown" if looks_textual(data) else "unknown-binary")
    )
    if header_type is not None and allowed_suffixes is not None:
        matches = suffix in allowed_suffixes
        entry["extension_matches_header"] = matches
        if not matches:
            item = evidence(
                relative_path, byte_offset=0,
                snippet=f"header={header_type}; extension={suffix or '<none>'}; sha256={entry['sha256']}",
                detection="magic-header-extension-check", context=context,
            )
            state.add_finding(
                "ASC-010", "File extension conflicts with file header",
                "HIGH", "HIGH", "file-disguise", [item],
                "The file signature does not match the extension expected by its name.",
                "Quarantine the file, verify provenance, and use a truthful extension after review.",
            )
    if suffix not in TEXT_SUFFIXES or header_type is not None:
        state.metadata_only_files += 1
        if header_type is None and not looks_textual(data):
            state.add_limitation(
                "unknown_binary", relative_path,
                "Unrecognized binary content was hashed but not semantically parsed.",
            )
        return
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        state.add_limitation(
            "text_decode_error", relative_path,
            f"UTF-8 decoding failed at byte {error.start}.",
        )
        return
    state.text_files_scanned += 1
    if relative_path.casefold() == "skill.md":
        state.skill_text = text
        frontmatter = parse_frontmatter(text)
        state.skill_description = frontmatter.get("description", "")
        if not frontmatter.get("name") or not state.skill_description:
            state.add_limitation(
                "skill_frontmatter_unrecognized", relative_path,
                "Required name/description frontmatter could not be parsed.",
            )
    scan_text_file(state, text, relative_path)


def _operational_evidence(
    state: AuditState,
    capability: str,
) -> list[dict[str, Any]]:
    return [
        item for item in state.capabilities.get(capability, [])
        if item["detection"] != "python-import"
    ]


def first_evidence(
    state: AuditState,
    capabilities: Iterable[str],
) -> dict[str, Any] | None:
    items: list[dict[str, Any]] = []
    for capability in capabilities:
        items.extend(_operational_evidence(state, capability))
    return sorted(
        items,
        key=lambda item: (
            item["path"], item.get("line") or 0, item.get("byte_offset") or 0,
            item["detection"],
        ),
    )[0] if items else None


def analyze_declarations(state: AuditState) -> dict[str, Any]:
    description = state.skill_description
    entire_skill = state.skill_text or ""
    network_declared = bool(NETWORK_DECLARATION_RE.search(description))
    offline_declared = bool(OFFLINE_DECLARATION_RE.search(entire_skill))
    readonly_declared = bool(READONLY_DECLARATION_RE.search(entire_skill))
    local_declared = bool(LOCAL_DECLARATION_RE.search(entire_skill))
    declared_capabilities = ["network.connect"] if network_declared else []
    observed = sorted(state.capabilities)
    mismatches: list[dict[str, Any]] = []

    if state.skill_text is None:
        item = evidence(
            "SKILL.md", byte_offset=0, snippet="required manifest missing",
            detection="required-file-check", context="manifest",
        )
        state.add_finding(
            "ASC-012", "Missing SKILL.md declaration",
            "HIGH", "HIGH", "declaration-gap", [item],
            "The directory has no SKILL.md from which purpose and permissions can be reviewed.",
            "Add a valid SKILL.md with a narrow purpose and explicit capability boundaries.",
        )
    elif description and BROAD_TRIGGER_RE.search(description):
        match = BROAD_TRIGGER_RE.search(description)
        assert match is not None
        item = evidence(
            "SKILL.md", line=2, snippet="overly broad trigger description",
            detection="frontmatter-trigger-scope", context="manifest",
        )
        state.add_finding(
            "ASC-001", "Overly broad trigger description",
            "MEDIUM", "MEDIUM", "trigger-scope", [item],
            "The trigger description may cause the Skill to activate for unrelated requests.",
            "Narrow the description to concrete audit tasks and target types.",
        )

    network_evidence = first_evidence(
        state, ("network.connect", "network.download", "network.upload")
    )
    if network_evidence and not network_declared:
        state.add_finding(
            "ASC-004", "Undeclared external communication capability",
            "HIGH", "HIGH", "network-boundary", [network_evidence],
            "Executable content has an operational network capability not declared in the Skill description.",
            "Remove the network behavior or declare exact endpoints, data classes, and approval boundaries.",
        )
        mismatches.append({
            "claim": "network use not declared",
            "observed": "network capability",
            "evidence": network_evidence,
        })
    if network_evidence and (offline_declared or local_declared):
        state.add_finding(
            "ASC-012", "Offline or local-only claim conflicts with network capability",
            "HIGH", "HIGH", "capability-mismatch", [network_evidence],
            "The manifest claims offline/local-only behavior while executable content can access a network.",
            "Remove the network behavior or correct the declaration and obtain renewed review.",
        )
        mismatches.append({
            "claim": "offline/local-only",
            "observed": "network capability",
            "evidence": network_evidence,
        })
    mutation_evidence = first_evidence(
        state, ("filesystem.write", "filesystem.delete", "system.persistence")
    )
    if mutation_evidence and readonly_declared:
        state.add_finding(
            "ASC-012", "Read-only claim conflicts with mutation capability",
            "HIGH", "HIGH", "capability-mismatch", [mutation_evidence],
            "The manifest claims read-only behavior while executable content can write, delete, or persist.",
            "Remove the mutation or correct the declaration and require explicit approval.",
        )
        mismatches.append({
            "claim": "read-only",
            "observed": "mutation capability",
            "evidence": mutation_evidence,
        })

    credential_item = first_evidence(state, ("credentials.read",))
    if credential_item:
        state.add_finding(
            "ASC-005", "Credential or sensitive-directory access",
            "HIGH", "HIGH", "sensitive-access", [credential_item],
            "Executable content can read a credential-like environment key or sensitive directory.",
            "Replace broad access with explicit least-privilege input and document handling.",
        )
    dynamic_item = first_evidence(state, ("code.dynamic-exec",))
    if dynamic_item:
        state.add_finding(
            "ASC-007", "Dynamic code execution or dangerous deserialization",
            "HIGH", "HIGH", "unexpected-code-execution", [dynamic_item],
            "Executable content can interpret code dynamically or deserialize unsafe data.",
            "Remove dynamic execution or constrain it to reviewed, integrity-verified content.",
        )
    delete_item = first_evidence(state, ("filesystem.delete",))
    if delete_item:
        state.add_finding(
            "ASC-008", "Filesystem deletion capability",
            "HIGH", "HIGH", "destructive-behavior", [delete_item],
            "Executable content can delete files or directories.",
            "Scope deletion to reviewed temporary paths and require explicit approval.",
        )
    persistence_item = first_evidence(state, ("system.persistence",))
    if persistence_item:
        state.add_finding(
            "ASC-008", "System persistence capability",
            "HIGH", "HIGH", "persistence", [persistence_item],
            "Executable content can create registry, startup, cron, or scheduled-task persistence.",
            "Remove persistence or require a separately authorized installation workflow.",
        )

    return {
        "declared_purpose": safe_preview(description, 600) if description else "Unavailable",
        "flags": {
            "network_declared": network_declared,
            "offline_declared": offline_declared,
            "read_only_declared": readonly_declared,
            "local_only_declared": local_declared,
        },
        "declared_capabilities": declared_capabilities,
        "observed_capabilities": observed,
        "mismatches": mismatches,
        "permission_boundaries": (
            ["Network use is declared; manually verify listed endpoints and data handling."]
            if network_declared else
            ["No network permission boundary was declared."]
        ),
    }


def correlate(state: AuditState) -> None:
    credential_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    upload_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    download_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    execute_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    persistence_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    write_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in _operational_evidence(state, "credentials.read"):
        credential_by_path[item["path"]].append(item)
    for item in _operational_evidence(state, "network.upload"):
        upload_by_path[item["path"]].append(item)
    for item in _operational_evidence(state, "network.download"):
        download_by_path[item["path"]].append(item)
    for capability in ("process.spawn", "code.dynamic-exec"):
        for item in _operational_evidence(state, capability):
            execute_by_path[item["path"]].append(item)
    for item in _operational_evidence(state, "system.persistence"):
        persistence_by_path[item["path"]].append(item)
    for capability in ("filesystem.write", "process.spawn", "code.dynamic-exec"):
        for item in _operational_evidence(state, capability):
            write_by_path[item["path"]].append(item)

    for path in sorted(set(credential_by_path) & set(upload_by_path)):
        items = [credential_by_path[path][0], upload_by_path[path][0]]
        correlation = {
            "id": "ASC-C01",
            "title": "Sensitive-source to external-send chain",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "signals": ["credentials.read", "network.upload"],
            "evidence": items,
            "explanation": "The same executable file reads credential-like data and can send data externally.",
        }
        state.correlations.append(correlation)
        state.add_finding(
            "ASC-006", "Potential credential exfiltration chain",
            "CRITICAL", "HIGH", "data-exfiltration", items,
            correlation["explanation"],
            "Block installation, remove the data flow, and rotate any credential exposed during testing.",
        )

    for path in sorted(set(download_by_path) & set(execute_by_path)):
        items = [download_by_path[path][0], execute_by_path[path][0]]
        correlation = {
            "id": "ASC-C02",
            "title": "Download followed by execution",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "signals": ["network.download", "process.spawn/code.dynamic-exec"],
            "evidence": items,
            "explanation": "The same executable file can download content and pass content to an execution mechanism.",
        }
        state.correlations.append(correlation)
        state.add_finding(
            "ASC-007", "Download-then-execute chain",
            "CRITICAL", "HIGH", "unexpected-code-execution", items,
            correlation["explanation"],
            "Block installation; remove the chain or require reviewed, pinned, integrity-verified artifacts.",
        )

    hidden_paths = {
        item["path"]
        for finding in state.findings
        if finding["rule_id"] in {"ASC-001", "ASC-002", "ASC-013"}
        for item in finding["evidence"]
    }
    for path in sorted(hidden_paths & set(persistence_by_path)):
        items = [
            next(
                item
                for finding in state.findings
                if finding["rule_id"] in {"ASC-001", "ASC-002", "ASC-013"}
                for item in finding["evidence"]
                if item["path"] == path
            ),
            persistence_by_path[path][0],
        ]
        state.correlations.append({
            "id": "ASC-C03",
            "title": "Concealed persistence",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "signals": ["hidden-instruction/control", "system.persistence"],
            "evidence": items,
            "explanation": "Concealment and persistence occur in the same target file.",
        })

    traversal_paths = {
        item["path"]
        for finding in state.findings
        if finding["rule_id"] == "ASC-009"
        for item in finding["evidence"]
        if item["detection"] != "filesystem-lstat"
    }
    for path in sorted(traversal_paths & set(write_by_path)):
        traversal_item = next(
            item
            for finding in state.findings
            if finding["rule_id"] == "ASC-009"
            for item in finding["evidence"]
            if item["path"] == path
        )
        state.correlations.append({
            "id": "ASC-C04",
            "title": "Out-of-scope write or execution",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "signals": ["path.traversal", "filesystem.write/process.spawn"],
            "evidence": [traversal_item, write_by_path[path][0]],
            "explanation": "Traversal and a mutation or execution capability occur in the same file.",
        })

    disguised_by_basename: dict[str, dict[str, Any]] = {}
    for finding in state.findings:
        if finding["rule_id"] != "ASC-010":
            continue
        for item in finding["evidence"]:
            disguised_by_basename[Path(item["path"]).name.casefold()] = item
    for reference in sorted(
        state.execution_references,
        key=lambda item: (item["basename"].casefold(), item["evidence"]["path"]),
    ):
        disguised = disguised_by_basename.get(reference["basename"].casefold())
        if not disguised:
            continue
        state.correlations.append({
            "id": "ASC-C05",
            "title": "Disguised binary referenced by execution logic",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "signals": ["file.header-mismatch", "process.spawn"],
            "evidence": [disguised, reference["evidence"]],
            "explanation": "Execution logic references a file whose binary signature conflicts with its extension.",
        })


def sorted_findings(state: AuditState) -> list[dict[str, Any]]:
    for finding in state.findings:
        finding["evidence"] = sorted(
            finding["evidence"],
            key=lambda item: (
                item["path"], item.get("line") or 0, item.get("byte_offset") or 0,
                item["detection"],
            ),
        )
    return sorted(
        state.findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 99),
            item["rule_id"],
            item["evidence"][0]["path"],
            item["evidence"][0].get("line") or 0,
        ),
    )


def determine_verdict(
    state: AuditState,
    findings: list[dict[str, Any]],
) -> tuple[str, list[str]]:
    blocking_ids = {"ASC-C01", "ASC-C02", "ASC-C03", "ASC-C04", "ASC-C05"}
    blockers = [
        correlation for correlation in state.correlations
        if correlation["id"] in blocking_ids
        and correlation["severity"] == "CRITICAL"
        and correlation["confidence"] == "HIGH"
    ]
    if blockers:
        return "BLOCK", [
            f"High-confidence blocking correlation: {item['id']} {item['title']}."
            for item in blockers
        ]
    if state.limitations:
        return "INCONCLUSIVE", [
            "The scan has material coverage limitations; ALLOW is prohibited."
        ]
    if findings:
        return "REVIEW", [
            "One or more deterministic risk indicators require human review."
        ]
    risky = sorted(RISKY_REVIEW_CAPABILITIES & set(state.capabilities))
    if risky:
        return "REVIEW", [
            "Observed risky capabilities require purpose and permission review: "
            + ", ".join(risky) + "."
        ]
    return "ALLOW", [
        "The complete supplied material produced no blocking rule or risky capability match.",
        "ALLOW is limited to this input and is not a guarantee of absolute safety.",
    ]


def audit_directory(target: Path | str, limits: Limits | None = None) -> dict[str, Any]:
    root = Path(target)
    limits = limits or Limits()
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise ValueError("target must be an existing, non-symlink directory")
    root = root.resolve()
    state = AuditState(root.name, limits)
    entries: list[Path] = []
    _walk_directory(root, state, entries)
    for path in entries:
        scan_entry(state, root, path)
    declaration = analyze_declarations(state)
    correlate(state)
    findings = sorted_findings(state)
    state.correlations = sorted(
        state.correlations,
        key=lambda item: (item["id"], item["evidence"][0]["path"]),
    )
    verdict, reasons = determine_verdict(state, findings)

    for name in state.capabilities:
        state.capabilities[name] = sorted(
            state.capabilities[name],
            key=lambda item: (
                item["path"], item.get("line") or 0, item.get("byte_offset") or 0,
                item["detection"],
            ),
        )
    coverage_status = "partial" if state.limitations else "complete"
    report = {
        "schema_version": SCHEMA_VERSION,
        "target": {
            "name": state.target_name,
            "relative_path": ".",
            "kind": "unpacked-skill-directory",
            "skill_md_present": state.skill_text is not None,
        },
        "coverage": {
            "status": coverage_status,
            "entries_considered": state.entries_considered,
            "files_inventory_count": len(state.files),
            "files_scanned": state.files_scanned,
            "text_files_scanned": state.text_files_scanned,
            "metadata_only_files": state.metadata_only_files,
            "symlinks_not_followed": state.symlinks,
            "bytes_read": state.bytes_read,
            "discovery_truncated": state.discovery_truncated,
            "limits": limits.as_dict(),
        },
        "capability_manifest": {
            "format": "skill-capability-manifest",
            "standards_claim": None,
            "files": sorted(state.files, key=lambda item: item["path"]),
            "python_imports": sorted(
                state.imports,
                key=lambda item: (
                    item["module"], item["evidence"]["path"],
                    item["evidence"].get("line") or 0,
                ),
            ),
            "external_endpoints": sorted(
                state.endpoints,
                key=lambda item: (
                    item["domain"], item["url"], item["evidence"]["path"],
                ),
            ),
            "capabilities": [
                {"name": name, "evidence": state.capabilities[name]}
                for name in sorted(state.capabilities)
            ],
        },
        "declaration_analysis": declaration,
        "findings": findings,
        "correlations": state.correlations,
        "scanner_verdict": verdict,
        "verdict_reasons": reasons,
        "limitations": sorted(
            state.limitations,
            key=lambda item: (item["path"], item["kind"], item["detail"]),
        ),
    }
    return report


def _md(value: Any) -> str:
    return safe_preview(value, 600).replace("\\", "\\\\").replace("|", "\\|")


def render_markdown(report: dict[str, Any]) -> str:
    verdict = report["scanner_verdict"]
    coverage = report["coverage"]
    declaration = report["declaration_analysis"]
    recommendation = {
        "ALLOW": "No blocking evidence was found in the fully scanned supplied material. This is not a guarantee of safety.",
        "REVIEW": "Do not install until a human reviewer resolves the listed capabilities and findings.",
        "BLOCK": "Do not install or use this Skill while the blocking correlation remains.",
        "INCONCLUSIVE": "Do not treat this result as approval. Re-run with complete readable material within limits.",
    }[verdict]
    lines = [
        "# Skill Supply Chain Audit", "",
        "## 1. Final Verdict", "",
        f"- Scanner verdict: `{_md(verdict)}`",
    ]
    lines.extend(f"- {_md(reason)}" for reason in report["verdict_reasons"])
    lines.extend([
        "", "## 2. Scan Coverage", "",
        f"- Status: `{_md(coverage['status'])}`",
        f"- Files scanned: {coverage['files_scanned']}/{coverage['files_inventory_count']}",
        f"- Text files scanned: {coverage['text_files_scanned']}",
        f"- Metadata-only files: {coverage['metadata_only_files']}",
        f"- Symlinks not followed: {coverage['symlinks_not_followed']}",
        f"- Bytes read: {coverage['bytes_read']}", "",
        "## 3. Declared Purpose", "",
        f"- {_md(declaration['declared_purpose'])}", "",
        "## 4. Observed Capability Manifest", "",
        "| Capability | Evidence count |", "|---|---:|",
    ])
    capabilities = report["capability_manifest"]["capabilities"]
    if capabilities:
        for capability in capabilities:
            lines.append(f"| `{_md(capability['name'])}` | {len(capability['evidence'])} |")
    else:
        lines.append("| None observed | 0 |")
    endpoints = report["capability_manifest"]["external_endpoints"]
    lines.extend(["", "### External endpoints", ""])
    if endpoints:
        lines.extend(
            f"- `{_md(item['domain'])}` — `{_md(item['url'])}` ({_md(item['evidence']['path'])})"
            for item in endpoints
        )
    else:
        lines.append("- None observed.")
    lines.extend([
        "", "## 5. Declared vs Observed", "",
        f"- Declared capabilities: {_md(', '.join(declaration['declared_capabilities']) or 'None')}",
        f"- Observed capabilities: {_md(', '.join(declaration['observed_capabilities']) or 'None')}",
        f"- Mismatches: {len(declaration['mismatches'])}", "",
        "## 6. Risk Findings", "",
        "| Rule | Severity | Confidence | Category | Evidence |",
        "|---|---|---|---|---|",
    ])
    if report["findings"]:
        for finding in report["findings"]:
            locations = ", ".join(
                f"{item['path']}:{item.get('line') or 'byte ' + str(item.get('byte_offset') or 0)}"
                for item in finding["evidence"]
            )
            lines.append(
                f"| {_md(finding['rule_id'])} | {_md(finding['severity'])} | "
                f"{_md(finding['confidence'])} | {_md(finding['category'])} | {_md(locations)} |"
            )
            lines.append(
                f"\n- **{_md(finding['rule_id'])} {_md(finding['title'])}:** "
                f"{_md(finding['explanation'])} Remediation: {_md(finding['remediation'])}"
            )
    else:
        lines.append("| None | N/A | N/A | N/A | No configured rule matched. |")
    lines.extend(["", "## 7. Dangerous Correlations", ""])
    if report["correlations"]:
        for item in report["correlations"]:
            lines.append(
                f"- `{_md(item['id'])}` {_md(item['title'])} "
                f"({_md(item['severity'])}/{_md(item['confidence'])}): "
                f"{_md(item['explanation'])}"
            )
    else:
        lines.append("- None established.")
    lines.extend([
        "", "## 8. Installation or Use Recommendation", "",
        f"- {_md(recommendation)}", "",
        "## 9. Limitations", "",
    ])
    if report["limitations"]:
        lines.extend(
            f"- `{_md(item['kind'])}` at `{_md(item['path'])}`: {_md(item['detail'])}"
            for item in report["limitations"]
        )
    else:
        lines.append("- No scanner coverage limitation was recorded.")
    lines.extend([
        "",
        "> All target content was handled as untrusted offline data. No target script, command, import, link target, or endpoint was executed or contacted.",
    ])
    return "\n".join(lines) + "\n"


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2) + "\n"


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _write_report(path: Path, content: str, target_root: Path) -> None:
    resolved = path.resolve(strict=False)
    if _is_within(resolved, target_root):
        raise ValueError("report output must be outside the target directory")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(content, encoding="utf-8", newline="\n")


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(
        description="Offline, read-only audit of an unpacked third-party Agent Skill."
    )
    parser.add_argument("target", help="Path to the unpacked Skill directory.")
    parser.add_argument("--json-out", type=Path, help="Write JSON outside the target.")
    parser.add_argument("--markdown-out", type=Path, help="Write Markdown outside the target.")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        limits = Limits(
            max_files=args.max_files,
            max_file_bytes=args.max_file_bytes,
            max_total_bytes=args.max_total_bytes,
        )
        target = Path(args.target)
        if not target.exists() or not target.is_dir() or target.is_symlink():
            raise ValueError("target must be an existing, non-symlink directory")
        target_root = target.resolve()
        report = audit_directory(target, limits)
        json_text = render_json(report)
        markdown_text = render_markdown(report)
        if args.json_out:
            _write_report(args.json_out, json_text, target_root)
        if args.markdown_out:
            _write_report(args.markdown_out, markdown_text, target_root)
        if not args.json_out and not args.markdown_out:
            sys.stdout.write(json_text)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Audit failed: {safe_preview(type(error).__name__)}", file=sys.stderr)
        return 3
    return {
        "ALLOW": 0,
        "REVIEW": 1,
        "INCONCLUSIVE": 1,
        "BLOCK": 2,
    }[report["scanner_verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
