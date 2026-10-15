"""Static analysis for Model Context Protocol (MCP) server manifests.

Scans MCP server tool definitions for prompt injection, hidden instructions,
rug-pull indicators, and other tool-poisoning attack patterns identified by
Palo Alto Unit 42, Invariant, Microsoft, and Simon Willison in 2025–2026.

Two operating modes:

1. **Scan a single manifest** — pass a parsed dict::

        from raucle.mcp_scanner import scan_manifest
        findings = scan_manifest(manifest_dict)

2. **Scan a manifest file or directory** — pass a path::

        findings = scan_manifest_file("server.json")
        findings = scan_manifest_dir("./mcp-servers/")

The scanner returns a list of :class:`Finding` objects.  Output can be
serialised as JSON or SARIF (for GitHub Advanced Security integration).

Detection categories
--------------------
- ``hidden_instruction`` — invisible/zero-width chars or special tags in tool
  descriptions (the classic ``<IMPORTANT>``, ``<SYSTEM>``, ``[INST]`` attacks)
- ``prompt_injection`` — direct injection phrases in tool descriptions
- ``credential_exposure`` — secrets baked into the manifest
- ``rug_pull_indicator`` — descriptions or names that change semantics
  post-approval ("ignore the above…", "now act as…")
- ``ssrf_target`` — tool URLs pointing at internal metadata services
- ``shell_pattern`` — tools that take raw shell commands
- ``ambiguous_authority`` — tools claiming to override others
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single security finding within an MCP manifest."""

    rule_id: str
    category: str
    severity: Severity
    tool: str
    field: str
    message: str
    evidence: str = ""
    location: str = ""  # filename or path:line

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.value,
            "tool": self.tool,
            "field": self.field,
            "message": self.message,
            "evidence": self.evidence,
            "location": self.location,
        }


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Hidden instruction tags / containers — these have no legitimate purpose in a
# tool description and are the standard tool-poisoning payload.
_HIDDEN_TAG_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("important_tag", re.compile(r"<\s*important\s*>", re.IGNORECASE)),
    ("system_tag", re.compile(r"<\s*system\s*>", re.IGNORECASE)),
    ("inst_tag", re.compile(r"\[\s*INST\s*\]", re.IGNORECASE)),
    ("im_start_tag", re.compile(r"<\|im_start\|>", re.IGNORECASE)),
    ("hidden_html_comment", re.compile(r"<!--\s*(?:ignore|override|instruction)", re.IGNORECASE)),
]

# Zero-width / invisible Unicode in descriptions
_INVISIBLE_CHARS = re.compile(r"[​-‏ - ﻿⁠-⁤]")

# Direct injection phrases
_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "override_instructions",
        re.compile(
            r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)"
        ),
    ),
    (
        "act_as",
        re.compile(r"(?i)\b(?:act|behave|respond)\s+as\s+(?:a\s+|an\s+)?(?:different|new)\b"),
    ),
    (
        "reveal_prompt",
        re.compile(r"(?i)reveal\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)"),
    ),
    (
        "jailbreak_keywords",
        re.compile(r"(?i)\b(?:jailbreak|DAN|do\s+anything\s+now|developer\s+mode)\b"),
    ),
    (
        "execute_silently",
        re.compile(
            r"(?i)(?:silently|without\s+(?:asking|telling|notifying))\s+(?:execute|run|perform)"
        ),
    ),
]

# Rug-pull indicators — manifest claims to mutate after approval
_RUGPULL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "post_approval_change",
        re.compile(
            r"(?i)(?:description|behaviour|behavior)\s+(?:will\s+)?(?:change|update|mutate)\s+(?:after|once)\b"
        ),
    ),
    ("dynamic_description", re.compile(r"(?i)description\s+is\s+dynamic")),
    ("override_other_tools", re.compile(r"(?i)override(?:s)?\s+(?:other|all)\s+tools?")),
]

# Credential / secret patterns (broader than DLP-001 — checks any string field)
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[A-Z0-9]{16}")),
    ("private_key", re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[a-z0-9._\-]{20,}")),
    (
        "api_key_assignment",
        # (?i) makes A-Z redundant beside a-z: one range covers both cases
        re.compile(r"(?i)(?:api[_-]?key|password)\s*[:=]\s*['\"]?[a-z0-9_\-]{16,}"),
    ),
]

# Cloud metadata / SSRF targets
_SSRF_TARGETS = re.compile(
    r"(?i)(?:"
    r"169\.254\.169\.254|"  # AWS/Azure
    r"metadata\.google\.internal|"
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|::1|"
    r"file://|gopher://|dict://"
    r")"
)

# Shell-exec indicators
_SHELL_HINTS = re.compile(
    r"(?i)\b(?:shell|bash|sh|exec|execute_command|run_command|system_call|popen)\b"
)


# ---------------------------------------------------------------------------
# Manifest field extraction
# ---------------------------------------------------------------------------


def _iter_tools(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract tool definitions from common MCP manifest shapes.

    Supports both the standard ``{"tools": [...]}`` shape and the
    ``{"capabilities": {"tools": {...}}}`` mapping form.
    """
    tools = manifest.get("tools")
    if isinstance(tools, list):
        return tools
    if isinstance(tools, dict):
        # name -> definition
        return [
            {"name": k, **(v if isinstance(v, dict) else {"description": str(v)})}
            for k, v in tools.items()
        ]

    capabilities = manifest.get("capabilities", {})
    if isinstance(capabilities, dict):
        cap_tools = capabilities.get("tools")
        if isinstance(cap_tools, list):
            return cap_tools
        if isinstance(cap_tools, dict):
            return [
                {"name": k, **(v if isinstance(v, dict) else {"description": str(v)})}
                for k, v in cap_tools.items()
            ]
    return []


def _stringify(value: Any) -> str:
    """Convert a manifest field value to a flat string for pattern matching."""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Per-tool scanning
# ---------------------------------------------------------------------------


def _collect_scannable_fields(tool: dict[str, Any]) -> list[tuple[str, str]]:
    """Collect (field_name, content) pairs from a tool definition for scanning."""
    scannable_fields: list[tuple[str, str]] = []
    for fld in ("description", "summary", "instructions"):
        v = tool.get(fld)
        if v is not None:
            scannable_fields.append((fld, _stringify(v)))

    params = tool.get("parameters") or tool.get("inputSchema") or {}
    if isinstance(params, dict):
        props = params.get("properties", {})
        if isinstance(props, dict):
            for pname, pval in props.items():
                if isinstance(pval, dict) and "description" in pval:
                    scannable_fields.append(
                        (f"parameters.{pname}.description", _stringify(pval["description"]))
                    )
    return scannable_fields


def _scan_tool(tool: dict[str, Any], location: str = "") -> list[Finding]:
    """Scan a single tool definition.  Returns a list of findings."""
    findings: list[Finding] = []
    name = str(tool.get("name", "<unnamed>"))

    # Fields to scrutinise — description and parameter descriptions are the
    # main injection surface.
    scannable_fields = _collect_scannable_fields(tool)

    for field_name, content in scannable_fields:
        findings.extend(_scan_text(name, field_name, content, location))

    # Tool name itself
    findings.extend(_scan_text(name, "name", name, location, name_field=True))

    # URL-like fields → SSRF check
    for url_field in ("url", "endpoint", "uri", "callback"):
        v = tool.get(url_field)
        if v and isinstance(v, str) and _SSRF_TARGETS.search(v):
            findings.append(
                Finding(
                    rule_id="MCP-SSRF-001",
                    category="ssrf_target",
                    severity=Severity.HIGH,
                    tool=name,
                    field=url_field,
                    message=f"Tool {url_field} targets internal/loopback address",
                    evidence=v[:120],
                    location=location,
                )
            )

    return findings


def _scan_text(
    tool_name: str,
    field_name: str,
    content: str,
    location: str,
    name_field: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []

    # Hidden Unicode
    invisible_count = len(_INVISIBLE_CHARS.findall(content))
    if invisible_count:
        findings.append(
            Finding(
                rule_id="MCP-HIDE-001",
                category="hidden_instruction",
                severity=Severity.CRITICAL,
                tool=tool_name,
                field=field_name,
                message=f"{invisible_count} invisible Unicode char(s) in {field_name}",
                evidence=f"{invisible_count} chars in [\\u200B-\\u200F, \\uFEFF, …]",
                location=location,
            )
        )

    # Hidden instruction tags
    for tag_name, pattern in _HIDDEN_TAG_PATTERNS:
        m = pattern.search(content)
        if m:
            findings.append(
                Finding(
                    rule_id=f"MCP-HIDE-{tag_name.upper()}",
                    category="hidden_instruction",
                    severity=Severity.CRITICAL,
                    tool=tool_name,
                    field=field_name,
                    message=f"Hidden-instruction tag {tag_name!r} found in {field_name}",
                    evidence=content[max(0, m.start() - 20) : m.end() + 60],
                    location=location,
                )
            )

    # Injection phrases
    for inj_name, pattern in _INJECTION_PATTERNS:
        m = pattern.search(content)
        if m:
            findings.append(
                Finding(
                    rule_id=f"MCP-INJ-{inj_name.upper()}",
                    category="prompt_injection",
                    severity=Severity.HIGH,
                    tool=tool_name,
                    field=field_name,
                    message=f"Injection phrase {inj_name!r} embedded in {field_name}",
                    evidence=content[max(0, m.start() - 20) : m.end() + 60],
                    location=location,
                )
            )

    # Rug-pull
    for rp_name, pattern in _RUGPULL_PATTERNS:
        m = pattern.search(content)
        if m:
            findings.append(
                Finding(
                    rule_id=f"MCP-RUG-{rp_name.upper()}",
                    category="rug_pull_indicator",
                    severity=Severity.CRITICAL,
                    tool=tool_name,
                    field=field_name,
                    message=f"Rug-pull indicator {rp_name!r} in {field_name}",
                    evidence=m.group(0)[:120],
                    location=location,
                )
            )

    # Secrets
    for sec_name, pattern in _SECRET_PATTERNS:
        m = pattern.search(content)
        if m:
            findings.append(
                Finding(
                    rule_id=f"MCP-SEC-{sec_name.upper()}",
                    category="credential_exposure",
                    severity=Severity.CRITICAL,
                    tool=tool_name,
                    field=field_name,
                    message=f"Possible credential ({sec_name!r}) embedded in {field_name}",
                    evidence=m.group(0)[:24] + "…",
                    location=location,
                )
            )

    # Shell-exec hints in tool name (not all bad — informational)
    if name_field and _SHELL_HINTS.search(content):
        findings.append(
            Finding(
                rule_id="MCP-SHELL-001",
                category="shell_pattern",
                severity=Severity.MEDIUM,
                tool=tool_name,
                field=field_name,
                message=f"Tool name suggests shell command execution: {content!r}",
                evidence=content,
                location=location,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_manifest(manifest: dict[str, Any], location: str = "") -> list[Finding]:
    """Scan a parsed MCP manifest dict.  Returns all findings across all tools."""
    findings: list[Finding] = []
    for tool in _iter_tools(manifest):
        if isinstance(tool, dict):
            findings.extend(_scan_tool(tool, location=location))
    return findings


def scan_manifest_file(path: str | Path) -> list[Finding]:
    """Load and scan a JSON manifest file."""
    path = Path(path)
    with open(path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    return scan_manifest(manifest, location=str(path))


def scan_manifest_dir(directory: str | Path) -> list[Finding]:
    """Scan every ``*.json`` file in *directory*.  Returns combined findings."""
    directory = Path(directory)
    findings: list[Finding] = []
    if not directory.is_dir():
        return findings
    for manifest_path in sorted(directory.glob("*.json")):
        try:
            findings.extend(scan_manifest_file(manifest_path))
        except (json.JSONDecodeError, OSError):
            continue
    return findings


# ---------------------------------------------------------------------------
# SARIF output (for GitHub Advanced Security)
# ---------------------------------------------------------------------------


def findings_to_sarif(findings: list[Finding], tool_version: str = "0.4.0") -> dict[str, Any]:
    """Convert findings to SARIF 2.1.0 format suitable for GitHub code scanning."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    sarif_severity_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    for f in findings:
        if f.rule_id not in rules_by_id:
            rules_by_id[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.category},
                "defaultConfiguration": {"level": sarif_severity_map[f.severity]},
            }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": sarif_severity_map[f.severity],
                "message": {"text": f"{f.message} (tool={f.tool}, field={f.field})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.location or "<inline>"},
                        },
                        "logicalLocations": [
                            {"name": f.tool, "kind": "function"},
                        ],
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "raucle",
                        "version": tool_version,
                        "informationUri": "https://github.com/epic28-ltd/raucle",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
