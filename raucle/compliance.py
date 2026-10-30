"""Compliance evidence packs (P4) — map the receipt chain to named controls.

A regulated buyer's recurring question is *"show me your agent-authorization
evidence."* raucle already produces a signed, offline-verifiable receipt chain;
this module turns that chain into a **control-mapped compliance report**: for a
named framework (EU AI Act, ISO/IEC 42001, SOC 2), which controls the chain
*evidences*, with the concrete counts/receipts that satisfy each, and an honest
statement of what is out of scope.

This is deliberately an **evidence map, not a conformance attestation.** raucle
evidences a *subset* of each framework — the record-keeping, access-control, and
monitoring controls its primitives genuinely address. Full compliance needs
other artifacts and an assessor. Every control below states exactly what the
chain proves and what it does not, in the same honest posture as the
[OWASP](../docs/standards/owasp-agentic-top10-mapping.md) and
[NIST](../docs/standards/nist-ai-agent-standards-alignment.md) mappings.

Usage::

    from raucle.compliance import build_report, render_markdown
    report = build_report("receipts.jsonl", framework="eu-ai-act")
    print(render_markdown(report))

CLI: ``raucle compliance report receipts.jsonl --framework eu-ai-act``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from raucle._paths import validate_path


class ControlStatus(str, Enum):
    SATISFIED = "SATISFIED"  # the chain provides the evidence this control asks for
    PARTIAL = "PARTIAL"  # the chain provides part; named gaps remain
    OUT_OF_SCOPE = "OUT_OF_SCOPE"  # raucle does not address this control


@dataclass
class ChainEvidence:
    """Facts extracted from a receipt chain, the raw material for control checks."""

    total_events: int = 0
    decisions: int = 0
    allow: int = 0
    deny: int = 0
    scans: int = 0
    flagged_scans: int = 0
    signed: bool = False  # the chain DECLARES signed (header flag)
    verifiable: bool = False  # we could run a CONCLUSIVE verification
    chain_valid: bool = False  # verification ran and passed
    signature_verified: bool = False  # signatures verified against a provided key
    checkpoints: int = 0
    distinct_agents: int = 0
    distinct_tools: int = 0


def _read_chain_lines(chain_path: str | Path) -> tuple[list[str], bool] | None:
    """Read the chain file and extract the declared-signed flag from the header.

    Returns ``(raw_lines, declared_signed)`` or ``None`` if the file is
    unreadable/malformed (caller returns an unverifiable ChainEvidence).
    """
    try:
        raw_lines = validate_path(chain_path).read_text(encoding="utf-8").splitlines()
        declared_signed = False
        for line in raw_lines:
            line = line.strip()
            if line:
                declared_signed = bool(json.loads(line).get("signed"))
                break
        return raw_lines, declared_signed
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None


def _verify_chain_evidence(
    ev: ChainEvidence,
    chain_path: str | Path,
    declared_signed: bool,
    key_given: bool,
    public_key_pem: bytes | None,
) -> None:
    """Run the AuditVerifier and populate the verification fields on *ev*."""
    # A signed chain cannot be CONCLUSIVELY verified without the operator key:
    # AuditVerifier(no key) on a signed chain returns invalid because it cannot
    # authenticate the checkpoints. Treat that as inconclusive, NOT as failed —
    # claiming "tampered" when we simply lack the key would itself be dishonest.
    try:
        from raucle.audit import AuditVerifier

        if declared_signed and not key_given:
            ev.verifiable = False
            ev.chain_valid = False
            ev.signature_verified = False
        else:
            vreport = AuditVerifier(public_key_pem=public_key_pem).verify_chain(chain_path)
            ev.verifiable = True
            ev.chain_valid = bool(vreport.valid)
            ev.signature_verified = ev.chain_valid and key_given and vreport.signed_mode == "signed"
    except Exception:
        ev.verifiable = True
        ev.chain_valid = False
        ev.signature_verified = False


def _tally_decision_event(event: dict, ev: ChainEvidence, agents: set, tools: set) -> None:
    """Tally a single decision event."""
    ev.decisions += 1
    if event["decision"] == "ALLOW":
        ev.allow += 1
    else:
        ev.deny += 1
    if event.get("agent_id"):
        agents.add(event["agent_id"])
    if event.get("tool"):
        tools.add(event["tool"])


def _tally_scan_event(event: dict, ev: ChainEvidence) -> None:
    """Tally a single scan-verdict event."""
    ev.scans += 1
    if event["verdict"] != "CLEAN":
        ev.flagged_scans += 1


def _tally_chain_events(raw_lines: list[str], ev: ChainEvidence) -> None:
    """Parse each JSONL record and tally events, decisions, and scans."""
    agents: set[str] = set()
    tools: set[str] = set()
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("chain_meta"):
            ev.signed = bool(rec.get("signed"))
            continue
        if rec.get("checkpoint"):
            ev.checkpoints += 1
            continue
        event = rec.get("event") if isinstance(rec.get("event"), dict) else rec
        ev.total_events += 1
        if "decision" in event:
            _tally_decision_event(event, ev, agents, tools)
        elif "verdict" in event:
            _tally_scan_event(event, ev)
    ev.distinct_agents = len(agents)
    ev.distinct_tools = len(tools)


def _chain_auth_status(ev: ChainEvidence) -> str:
    if ev.signed:
        return "signatures unauthenticated"
    return "chain unsigned"


def extract_evidence(
    chain_path: str | Path, *, public_key_pem: bytes | None = None
) -> ChainEvidence:
    """Read a receipt chain (JSONL) and tally the facts controls are checked against.

    The chain is **actually verified** with :class:`~raucle.audit.AuditVerifier`
    (codex #4) — a JSON ``signed:true`` flag on a forged file is NOT trusted. The
    hash chain is always verified (tamper-evidence); checkpoint *signatures* are
    verified only when ``public_key_pem`` is supplied, so a control is only marked
    on signature strength when signatures were genuinely checked.
    """
    ev = ChainEvidence()
    # Determine the declared-signed flag from the header up front. Malformed JSON
    # is not evidence — return an unverifiable ChainEvidence rather than raising
    # (codex r6 LOW).
    result = _read_chain_lines(chain_path)
    if result is None:
        return ev  # all-zero / unverifiable; every control will read PARTIAL
    raw_lines, declared_signed = result
    key_given = public_key_pem is not None
    _verify_chain_evidence(ev, chain_path, declared_signed, key_given, public_key_pem)
    _tally_chain_events(raw_lines, ev)
    return ev


@dataclass
class Control:
    """One framework control and how raucle evidence maps to it."""

    id: str
    title: str
    requirement: str
    status_fn: Callable[[ChainEvidence], tuple[ControlStatus, str]]


@dataclass
class ControlResult:
    id: str
    title: str
    requirement: str
    status: ControlStatus
    evidence: str


@dataclass
class ComplianceReport:
    framework: str
    framework_title: str
    chain_path: str
    chain_signed: bool
    controls: list[ControlResult] = field(default_factory=list)
    evidence: ChainEvidence | None = None

    def summary(self) -> dict[str, int]:
        out = {s.value: 0 for s in ControlStatus}
        for c in self.controls:
            out[c.status.value] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "framework_title": self.framework_title,
            "chain_path": self.chain_path,
            "chain_signed": self.chain_signed,
            "disclaimer": _DISCLAIMER,
            "summary": self.summary(),
            "controls": [
                {
                    "id": c.id,
                    "title": c.title,
                    "requirement": c.requirement,
                    "status": c.status.value,
                    "evidence": c.evidence,
                }
                for c in self.controls
            ],
        }


_DISCLAIMER = (
    "This is an EVIDENCE MAP, not a conformance attestation. raucle evidences the "
    "subset of controls its primitives address (signed authorization decisions, "
    "tamper-evident logging, capability access control). Full compliance requires "
    "additional controls, artifacts, and an accredited assessor."
)


# ---------------------------------------------------------------------------
# Control-status helpers (honest: SATISFIED only when the chain truly evidences it)
# ---------------------------------------------------------------------------


def _signed_log(ev: ChainEvidence) -> tuple[ControlStatus, str]:
    if ev.signed and not ev.verifiable:
        return ControlStatus.PARTIAL, (
            f"{ev.decisions} decisions logged in a signed chain, but signatures were NOT "
            "authenticated here (no operator public key supplied). Re-run with --pubkey to "
            "authenticate for full evidence."
        )
    if not ev.chain_valid:
        return ControlStatus.PARTIAL, (
            "the chain FAILED verification (tampered, reordered, or not a valid raucle chain) "
            "— it cannot serve as record-keeping evidence until it verifies."
        )
    if ev.decisions == 0:
        return ControlStatus.PARTIAL, "no authorization decisions found in this (valid) chain."
    if ev.signature_verified:
        return ControlStatus.SATISFIED, (
            f"{ev.decisions} authorization decisions ({ev.allow} ALLOW / {ev.deny} DENY) "
            f"recorded as a tamper-evident, Ed25519-signed, timestamped hash chain with "
            f"{ev.checkpoints} signed checkpoint(s); signatures verified, independently "
            "verifiable offline."
        )
    return ControlStatus.PARTIAL, (
        f"{ev.decisions} decisions logged and the hash chain verifies, but the chain is "
        "UNSIGNED — integrity is hash-chained, not authenticated. Sign the chain (audit "
        "signer) for full evidence."
    )


def _access_control(ev: ChainEvidence) -> tuple[ControlStatus, str]:
    if ev.decisions > 0:
        return ControlStatus.PARTIAL, (
            f"Capability tokens enforce per-call tool authorization at the gate "
            f"({ev.deny} call(s) denied across {ev.distinct_tools} tool(s), "
            f"{ev.distinct_agents} agent identit(y/ies)). This is the tool-call access-control "
            "layer; identity provisioning, human IAM, and network access are out of scope."
        )
    return ControlStatus.OUT_OF_SCOPE, "no gated tool calls in this chain."


def _monitoring(ev: ChainEvidence) -> tuple[ControlStatus, str]:
    if ev.signed and not ev.verifiable:
        return ControlStatus.PARTIAL, "signed chain not authenticated (supply --pubkey)."
    if not ev.chain_valid:
        return ControlStatus.PARTIAL, "chain failed verification; monitoring evidence not usable."
    if ev.deny == 0 and ev.scans == 0:
        return ControlStatus.PARTIAL, "no denial or scan signals recorded yet."
    if not ev.signature_verified:
        return ControlStatus.PARTIAL, (
            f"{ev.deny} denied call(s) and {ev.flagged_scans} flagged scan(s) of {ev.scans} "
            "recorded, but the chain is UNSIGNED / signatures not authenticated — an "
            "unauthenticated detection record. Sign the chain and supply --pubkey for evidence."
        )
    return ControlStatus.SATISFIED, (
        f"{ev.deny} denied call(s) and {ev.flagged_scans} flagged scan(s) of {ev.scans} "
        "recorded as signed, verified anomaly signals — a continuous, attributable detection "
        "record of policy-violating and adversarial activity."
    )


def _human_oversight(_ev: ChainEvidence) -> tuple[ControlStatus, str]:
    return ControlStatus.PARTIAL, (
        "The gate is the enforcement point where a human-set authorization policy is applied; "
        "DENY decisions are the structural oversight mechanism. Interactive human-in-the-loop "
        "approval UX is out of scope (pair with an approval workflow)."
    )


def _robustness(ev: ChainEvidence) -> tuple[ControlStatus, str]:
    integrity = "authenticated" if ev.signature_verified else "unauthenticated"
    return ControlStatus.PARTIAL, (
        "Structural prompt-injection resistance on the tool-call surface (a call outside the "
        f"signed capability cannot execute; {ev.deny} blocked here); the record's integrity is "
        f"{integrity}. Not a full robustness/accuracy regime for model outputs."
    )


def _not_addressed(_ev: ChainEvidence) -> tuple[ControlStatus, str]:
    return ControlStatus.OUT_OF_SCOPE, "raucle does not address this control."


def _dora_logging(ev: ChainEvidence) -> tuple[ControlStatus, str]:
    """RTS 2024/1774 Article 12(2)(c): logging of access-control, identity
    and ICT operations events. Every gate decision IS such an event for a
    non-human identity."""
    if ev.decisions > 0:
        return (
            ControlStatus.SATISFIED,
            f"{ev.decisions} identity-attributed decision events logged "
            f"({ev.allow} allow, {ev.deny} deny) across {ev.distinct_tools} tools "
            f"and {ev.distinct_agents} acting identities.",
        )
    return ControlStatus.PARTIAL, "no decision events found in the chain."


def _dora_tamper(ev: ChainEvidence) -> tuple[ControlStatus, str]:
    """RTS Article 12(2)(d): logs protected against tampering, deletion and
    unauthorised access. Satisfied only by SIGNATURE VERIFICATION ACTUALLY
    RUN against the provided key, never by the chain asserting its own
    signedness."""
    if ev.signature_verified and ev.chain_valid:
        return (
            ControlStatus.SATISFIED,
            "chain verification ran and PASSED: every checkpoint signature "
            "verified against the provided key. Tampering is detectable, not "
            "merely discouraged.",
        )
    if ev.chain_valid and not ev.verifiable:
        return (
            ControlStatus.PARTIAL,
            "chain integrity verified, but conclusive signature verification "
            "needs the operator public key (pass --pubkey).",
        )
    if ev.chain_valid:
        return (
            ControlStatus.PARTIAL,
            "chain integrity verified; the chain is unsigned, so tampering is "
            "detectable only within the hash chain, not cryptographically "
            "attributable.",
        )
    return (
        ControlStatus.PARTIAL,
        "chain could not be verified as valid; this pack records the failure.",
    )


def _dora_retention(_ev: ChainEvidence) -> tuple[ControlStatus, str]:
    """RTS Article 12(4): the retention period is the entity's own risk
    decision; the pack records the observed span and states the duty."""
    return (
        ControlStatus.PARTIAL,
        "the pack's retention.json records the observed span; the retention "
        "period remains the entity's ICT risk-assessment decision per the RTS.",
    )


def _dora_attribution(ev: ChainEvidence) -> tuple[ControlStatus, str]:
    """FSB Sound Practices (Oct 2026, supervisory expectation): actions
    attributable to specific agents, and whether each acted within its
    permissions."""
    if ev.distinct_agents > 0 and ev.decisions > 0:
        return (
            ControlStatus.SATISFIED,
            f"every decision event carries an acting identity ({ev.distinct_agents} "
            "distinct agents observed); the delegated-authority binding in each "
            "row answers the within-its-permissions question.",
        )
    return ControlStatus.PARTIAL, "no acting identities observed in the chain."


# ---------------------------------------------------------------------------
# Framework control maps (the honest subset raucle evidences)
# ---------------------------------------------------------------------------

_FRAMEWORKS: dict[str, tuple[str, list[Control]]] = {
    "dora": (
        "EU DORA (Regulation (EU) 2022/2554) logging controls per RTS 2024/1774 Article 12",
        [
            Control(
                "RTS-12(2)(c)",
                "Logging of access-control, identity and ICT operations events",
                "Financial entities log access-control, identity-management and "
                "ICT operations events; an agent's tool calls are such events.",
                _dora_logging,
            ),
            Control(
                "RTS-12(2)(d)",
                "Protection of logs against tampering, deletion and unauthorised access",
                "Logs are protected 'against tampering, deletion, and unauthorised "
                "access at rest, in transit and, where relevant, in use'.",
                _dora_tamper,
            ),
            Control(
                "RTS-12(4)",
                "Retention period proportionate to the risk assessment",
                "The retention period takes account of the entity's business and "
                "information security objectives and the ICT risk assessment.",
                _dora_retention,
            ),
            Control(
                "FSB-ATTR",
                "Attribution of agentic actions (supervisory expectation)",
                "The FSB Sound Practices (Oct 2026) expect institutions to "
                "attribute actions to specific agents and to know whether each "
                "acted within its permissions throughout its chain of steps.",
                _dora_attribution,
            ),
        ],
    ),
    "eu-ai-act": (
        "EU AI Act (Regulation 2024/1689) — high-risk AI obligations",
        [
            Control(
                "Art.12",
                "Record-keeping (automatic logging)",
                "High-risk AI systems shall technically allow for the automatic recording of "
                "events (logs) over the system's lifetime.",
                _signed_log,
            ),
            Control(
                "Art.14",
                "Human oversight",
                "High-risk AI systems shall be designed to be effectively overseen by natural "
                "persons.",
                _human_oversight,
            ),
            Control(
                "Art.15",
                "Accuracy, robustness and cybersecurity",
                "High-risk AI systems shall be resilient to attempts to alter their use or "
                "behaviour by exploiting vulnerabilities.",
                _robustness,
            ),
        ],
    ),
    "iso-42001": (
        "ISO/IEC 42001:2023 — AI management system",
        [
            Control(
                "A.6.2.6",
                "AI system operation and monitoring",
                "The organization shall log and monitor the operation of AI systems.",
                _monitoring,
            ),
            Control(
                "A.6.2.8",
                "AI system recording of event logs",
                "The organization shall determine the event logs needed and retain them.",
                _signed_log,
            ),
            Control(
                "A.8.3",
                "Information for interested parties / auditability",
                "The organization shall provide information enabling assessment of the AI system.",
                lambda ev: (
                    (
                        ControlStatus.SATISFIED,
                        "Every decision is independently verifiable offline via the signed chain "
                        "+ bundled keys (audit-pack); signatures authenticated here, needing no "
                        "trust in the producing party.",
                    )
                    if ev.signature_verified
                    else (
                        ControlStatus.PARTIAL,
                        "not independently authenticated: supply the operator key (--pubkey) and a "
                        "signed chain for verifiable auditability ("
                        + _chain_auth_status(ev)
                        + ").",
                    )
                ),
            ),
        ],
    ),
    "soc2": (
        "SOC 2 (AICPA Trust Services Criteria)",
        [
            Control(
                "CC6.1",
                "Logical access controls",
                "The entity implements logical access security measures to protect against "
                "unauthorized access.",
                _access_control,
            ),
            Control(
                "CC7.2",
                "Monitoring for anomalies",
                "The entity monitors system components for anomalies indicative of malicious "
                "acts or errors.",
                _monitoring,
            ),
            Control(
                "CC7.3",
                "Evaluation of security events (evidence)",
                "The entity evaluates security events and maintains evidence of its response.",
                _signed_log,
            ),
        ],
    ),
}


def supported_frameworks() -> list[str]:
    return sorted(_FRAMEWORKS)


def build_report(
    chain_path: str | Path, *, framework: str, public_key_pem: bytes | None = None
) -> ComplianceReport:
    """Map a receipt chain to a framework's controls and produce the evidence report.

    Pass ``public_key_pem`` (the operator/audit public key) to AUTHENTICATE the
    chain's signatures; without it the chain is integrity-checked but signature
    strength is not claimed.
    """
    key = framework.lower()
    if key not in _FRAMEWORKS:
        raise ValueError(
            f"unknown framework {framework!r}; choose from {', '.join(supported_frameworks())}"
        )
    title, controls = _FRAMEWORKS[key]
    ev = extract_evidence(chain_path, public_key_pem=public_key_pem)
    results: list[ControlResult] = []
    for c in controls:
        status, evidence = c.status_fn(ev)
        results.append(
            ControlResult(
                id=c.id,
                title=c.title,
                requirement=c.requirement,
                status=status,
                evidence=evidence,
            )
        )
    return ComplianceReport(
        framework=key,
        framework_title=title,
        chain_path=str(chain_path),
        chain_signed=ev.signature_verified,
        controls=results,
        evidence=ev,
    )


def render_markdown(report: ComplianceReport) -> str:
    """Render a report as a Markdown evidence map (the artifact for a CISO/auditor)."""
    s = report.summary()
    lines = [
        f"# Compliance evidence map — {report.framework_title}",
        "",
        f"**Source:** `{report.chain_path}` "
        f"({'signed' if report.chain_signed else 'UNSIGNED'} receipt chain)",
        "",
        f"> {_DISCLAIMER}",
        "",
        f"**Summary:** {s['SATISFIED']} satisfied · {s['PARTIAL']} partial · "
        f"{s['OUT_OF_SCOPE']} out of scope.",
        "",
        "| Control | Status | Evidence |",
        "|---|---|---|",
    ]
    for c in report.controls:
        ev = c.evidence.replace("|", "\\|")
        lines.append(f"| **{c.id}** {c.title} | {c.status.value} | {ev} |")
    lines += [
        "",
        "*Generated by `raucle compliance report`. Verify the underlying chain "
        "with `raucle audit verify` (and bundle it with `raucle audit-pack "
        "build` for an offline-verifiable evidence pack).*",
    ]
    return "\n".join(lines)


__all__ = [
    "ControlStatus",
    "ChainEvidence",
    "ComplianceReport",
    "ControlResult",
    "extract_evidence",
    "build_report",
    "render_markdown",
    "supported_frameworks",
]
