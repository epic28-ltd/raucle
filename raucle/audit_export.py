"""Audit-export artifact (E1) — a signed, reproducible attestation over a
provenance chain, its trusted keys, and the proofs in play.

The platform "magic moment": a CISO runs this against a chain and hands the
output to a regulator. The report does not *certify* safety — it attests that a
set of verdicts is **reproducible** from a set of inputs. Every status is
recomputable offline by re-running ``provenance verify`` and recomputing proof
hashes, and the manifest embeds the SHA-256 of every input so nothing is taken
on trust.

Two layers:
  - the authoritative **signed JSON manifest** (``build_report`` → ``sign_manifest``),
  - a human **HTML view** (``render_html``), printable to PDF.

This module adds NO new security primitive. It composes the shipped v0.17
surfaces: ``ProvenanceVerifier.verify_chain`` (the chain verdict),
``ProvenanceReceipt`` (the nodes), and ``ProofResult`` dicts (the proof
obligations). It runs nothing and mutates nothing.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from raucle._paths import validate_path

from . import __version__
from .prove import ProofResult
from .provenance import (
    CapabilityStatement,
    ProvenanceReceipt,
    ProvenanceVerifier,
    _canonical_json,
    _sha256_hex,
)

GREEN = "green"
AMBER = "amber"
RED = "red"

# Maps a ProofResult status to a node colour + the obligation it discharges.
_PROOF_STATUS = {
    "PROVEN": (GREEN, "policy completeness proven (rests on the prover-soundness axiom)"),
    "REFUTED": (RED, "policy REFUTED — a counterexample exists"),
    "UNDECIDED": (AMBER, "UNDECIDED — prover could not certify; not a failure, not a proof"),
}


_SHA256_PREFIX = "sha256:"  # named once (Sonar S1192)


def _proof_hash_ok(p: dict[str, Any]) -> bool:
    """A supplied proof dict is trusted only if its claimed ``hash`` equals the
    hash recomputed from its own body (the content-address binding). Without this
    a caller could assert ``status: PROVEN`` under a chosen hash and never run the
    prover. Recomputed via the real ProofResult so the canonical form matches."""
    claimed = p.get("hash")
    if not claimed:
        return False
    try:
        recomputed = ProofResult(
            status=str(p.get("status", "")),
            prover=p.get("prover", ""),
            prover_version=p.get("prover_version", ""),
            grammar_hash=p.get("grammar_hash", ""),
            policy_hash=p.get("policy_hash", ""),
            counterexample=p.get("counterexample"),
            notes=list(p.get("notes", [])),
            timeout_ms=int(p.get("timeout_ms", 0)),
        ).hash
    except (TypeError, ValueError):
        return False
    return recomputed == claimed


def _proof_verdict(p: dict[str, Any]) -> tuple[str, str]:
    """Colour + detail for a supplied proof, after content-address verification.
    A hash that does not match the recomputed body is untrusted → AMBER, never
    GREEN — even if it claims PROVEN."""
    if not _proof_hash_ok(p):
        return AMBER, "untrusted: claimed hash does not match the recomputed ProofResult hash"
    status_str = str(p.get("status", "")).upper()
    colour, detail = _PROOF_STATUS.get(status_str, (AMBER, f"unknown proof status {status_str!r}"))
    if status_str == "REFUTED" and p.get("counterexample"):
        # UTF-16 key ordering (§4.3.1): this detail is embedded in the signable
        # manifest body, so it must use the same canonical ordering as the rest
        # of the signed material rather than code-point sort_keys (codex R7).
        from ._canon import reorder_keys_utf16

        detail += "; counterexample: " + json.dumps(
            reorder_keys_utf16(p["counterexample"]), sort_keys=False
        )
    return colour, detail


@dataclass
class AuditNode:
    """One agent/tool node in the audited chain."""

    id: str
    label: str
    kind: str  # "tool" | "operation"
    status: str
    evidence: list[str] = field(default_factory=list)
    receipt_hashes: list[str] = field(default_factory=list)
    # When a capability for this tool cites a proof we were given, the joined
    # obligation is recorded inline: the green "discharged proof obligation with
    # a certificate hash" — the founding-myth magic moment.
    proof_certificate: str = ""
    proof_status: str = ""  # "" if none joined; else green|amber|red
    lean_theorem: str = ""


@dataclass
class ProofObligation:
    """A proof obligation surfaced from a supplied ProofResult."""

    name: str
    prover: str
    status: str  # green | amber | red
    certificate: str  # ProofResult.hash
    grammar_hash: str
    policy_hash: str
    detail: str


@dataclass
class AuditReport:
    generated_at: int
    tool_version: str
    chain_verdict: dict[str, Any]
    nodes: list[AuditNode]
    obligations: list[ProofObligation]
    summary: dict[str, Any]
    input_hashes: dict[str, Any]
    # Chain findings that could not be attributed to a single node (DAG-level
    # parent/taint issues, global parse failures). Shown in the banner.
    global_findings: list[str] = field(default_factory=list)

    def body(self) -> dict[str, Any]:
        """The canonical, signable manifest body (no signature)."""
        return {
            "kind": "raucle-audit-export/v1",
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "chain_verdict": self.chain_verdict,
            "nodes": [asdict(n) for n in self.nodes],
            "obligations": [asdict(o) for o in self.obligations],
            "global_findings": self.global_findings,
            "summary": self.summary,
            "input_hashes": self.input_hashes,
        }


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


_WORST = {RED: 2, AMBER: 1, GREEN: 0}


def _parse_finding(err: str) -> tuple[str | None, object, str]:
    """Attribute a verify_chain error to a node key, with linear string parsing
    (no regex — avoids ReDoS on the catch-all tail). Returns one of:
    ``("line", <int>, detail)``, ``("receipt", <hash>, detail)``, or
    ``(None, None, err)`` when the finding is not node-attributable."""
    head, sep, rest = err.partition(": ")
    if sep and head.startswith("line "):
        num = head[5:].strip()
        if num.isdigit():
            return "line", int(num), rest
    if sep and head.startswith("receipt "):
        h = head[len("receipt ") :].strip()
        if h.startswith(_SHA256_PREFIX):
            return "receipt", h, rest
    return None, None, err


def _load_receipts(chain_path: str | Path) -> list[tuple[int, ProvenanceReceipt]]:
    """Parse every receipt with its 1-based line number, so verify_chain's
    ``line N: ...`` findings can be attributed to the exact node. The verdict is
    authoritative; an unparseable line is skipped (it is already in the verdict)."""
    out: list[tuple[int, ProvenanceReceipt]] = []
    with open(chain_path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                jws = raw.get("jws") if isinstance(raw, dict) else None
                if jws:
                    out.append((line_no, ProvenanceReceipt.from_jws(jws)))
            except (ValueError, KeyError):
                continue
    return out


def _worse(a: str, b: str) -> str:
    return a if _WORST[a] >= _WORST[b] else b


def _group_receipt_nodes(
    numbered: list[tuple[int, ProvenanceReceipt]],
) -> tuple[dict[str, AuditNode], dict[int, AuditNode], dict[str, AuditNode], dict[str, str]]:
    """Group receipts by tool or operation into audit nodes.

    Returns ``(grouped, line_to_node, hash_to_node, node_tool)``.
    """
    grouped: dict[str, AuditNode] = {}
    line_to_node: dict[int, AuditNode] = {}
    hash_to_node: dict[str, AuditNode] = {}
    node_tool: dict[str, str] = {}
    for line_no, r in numbered:
        tool = getattr(r, "tool", "") or ""
        if tool:
            key, label, kind = f"{r.agent_id}/{tool}", f"{r.agent_id} → {tool}", "tool"
        else:
            key = f"{r.agent_id}/{r.operation.value}"
            label, kind = f"{r.agent_id} · {r.operation.value}", "operation"
        node = grouped.get(key)
        if node is None:
            node = AuditNode(id=key, label=label, kind=kind, status=GREEN)
            grouped[key] = node
            node_tool[key] = tool
        node.receipt_hashes.append(r.receipt_hash)
        line_to_node[line_no] = node
        hash_to_node[r.receipt_hash] = node
    return grouped, line_to_node, hash_to_node, node_tool


def _attribute_findings(
    verdict: Any,
    line_to_node: dict[int, AuditNode],
    hash_to_node: dict[str, AuditNode],
) -> list[str]:
    """Attribute verify_chain findings to their nodes; return global findings."""
    global_findings: list[str] = []
    for err in verdict.errors:
        kind, key, detail = _parse_finding(err)
        node = None
        if kind == "line":
            node = line_to_node.get(key)
        elif kind == "receipt":
            node = hash_to_node.get(key)
        if node is not None:
            node.status = RED
            node.evidence.append(detail)
        else:
            global_findings.append(err)
    return global_findings


def _build_proof_obligations(
    proofs: list[dict[str, Any]],
) -> tuple[list[ProofObligation], dict[str, tuple[str, str]]]:
    """Build proof obligations from supplied ProofResult dicts.

    Returns ``(obligations, proof_verdict_by_hash)``.
    """
    obligations: list[ProofObligation] = []
    proof_verdict_by_hash: dict[str, tuple[str, str]] = {}
    for p in proofs:
        colour, detail = _proof_verdict(p)
        obligations.append(
            ProofObligation(
                name=p.get("prover", "policy completeness"),
                prover=p.get("prover", ""),
                status=colour,
                certificate=p.get("hash", ""),
                grammar_hash=p.get("grammar_hash", ""),
                policy_hash=p.get("policy_hash", ""),
                detail=detail,
            )
        )
        # Only index trusted (hash-verified) proofs for the node join, so a
        # forged hash cannot be matched by a citing capability.
        if p.get("hash") and _proof_hash_ok(p):
            proof_verdict_by_hash[p["hash"]] = (colour, detail)
    return obligations, proof_verdict_by_hash


def _join_capabilities_to_proofs(
    grouped: dict[str, AuditNode],
    node_tool: dict[str, str],
    capabilities: list[dict[str, Any]],
    proof_verdict_by_hash: dict[str, tuple[str, str]],
) -> None:
    """Join tool nodes → capability tokens → the proofs they cite."""
    cap_by_tool = {c.get("tool"): c for c in capabilities if c.get("tool")}
    for key, node in grouped.items():
        tool = node_tool.get(key)
        cap = cap_by_tool.get(tool) if tool else None
        cited = cap.get("policy_proof_hash") if cap else None
        if not cited:
            continue
        node.proof_certificate = cited
        node.lean_theorem = "Theorem 3 (policy-proof composition)"
        verdict_pair = proof_verdict_by_hash.get(cited)
        if verdict_pair is None:
            node.proof_status = AMBER
            node.status = _worse(node.status, AMBER)
            node.evidence.append(
                f"capability cites proof {cited} but no trusted (hash-verified) "
                f"proof with that hash was supplied"
            )
            continue
        pstatus, pdetail = verdict_pair
        node.proof_status = pstatus
        node.status = _worse(node.status, pstatus)
        node.evidence.append(f"cited proof {cited}: {pdetail}")


def build_report(
    chain_path: str | Path,
    public_keys: dict[str, bytes],
    proofs: list[dict[str, Any]] | None = None,
    *,
    generated_at: int,
    tool_version: str = __version__,
    capabilities: list[dict[str, Any]] | None = None,
    capability_statements: dict[str, CapabilityStatement] | None = None,
) -> AuditReport:
    """Compute the audit report. ``generated_at`` is injected (not read from the
    clock) so the manifest is deterministic and testable.

    ``capability_statements`` ({key_id: CapabilityStatement}) are passed to the
    verifier so it ENFORCES each agent's allowed-tools/models — without them a
    chain calling a forbidden tool would verify clean and the node would show
    GREEN. ``capabilities`` (optional) is a list of capability tokens — each
    carrying ``tool`` and ``policy_proof_hash`` — used only to join a tool node
    to the proof it cites.
    """
    proofs = proofs or []
    capabilities = capabilities or []
    verifier = ProvenanceVerifier(
        public_keys=public_keys, capabilities=capability_statements or None
    )
    verdict = verifier.verify_chain(chain_path)
    numbered = _load_receipts(chain_path)
    tampered = set(verdict.tampered_receipts)

    # Nodes: group receipts by the tool they invoke, else by operation. Track
    # which line numbers and receipt hashes belong to each node for attribution.
    grouped, line_to_node, hash_to_node, node_tool = _group_receipt_nodes(numbered)

    # Tampered receipts → RED on the owning node.
    for h in tampered:
        node = hash_to_node.get(h)
        if node:
            node.status = RED
            node.evidence.append("receipt flagged as tampered (receipt_hash mismatch)")

    # Attribute every verify_chain finding to its node by line or receipt hash;
    # anything not attributable is a global (DAG/taint-level) finding.
    global_findings = _attribute_findings(verdict, line_to_node, hash_to_node)

    # Nodes with no attributed finding verified cleanly — say so explicitly,
    # even when the chain is INVALID elsewhere (precise, not blanket-amber).
    for node in grouped.values():
        if node.status == GREEN and not node.evidence:
            node.evidence.append("chain verified clean for this node's receipts")

    # Proof obligations from supplied ProofResult dicts.
    obligations, proof_verdict_by_hash = _build_proof_obligations(proofs)

    # Join: a tool node → the capability for that tool → the proof it cites.
    _join_capabilities_to_proofs(grouped, node_tool, capabilities, proof_verdict_by_hash)

    def _count(colour: str) -> int:
        return sum(1 for n in grouped.values() if n.status == colour) + sum(
            1 for o in obligations if o.status == colour
        )

    summary = {
        "chain_valid": verdict.valid,
        "receipt_count": verdict.receipt_count,
        "global_findings": len(global_findings),
        "green": _count(GREEN),
        "amber": _count(AMBER),
        "red": _count(RED),
    }

    input_hashes = {
        "chain_sha256": _SHA256_PREFIX + _sha256_hex(validate_path(chain_path).read_bytes()),
        "public_keys": {
            kid: _SHA256_PREFIX + _sha256_hex(pem) for kid, pem in sorted(public_keys.items())
        },
        # The enforced capability statements are an input that changes verdicts
        # (allowed-tools/models), so bind their content into the manifest too.
        "capability_statements": {
            kid: _SHA256_PREFIX + _sha256_hex(_canonical_json(stmt.to_dict()))
            for kid, stmt in sorted((capability_statements or {}).items())
        },
        "proofs": [p.get("hash", "") for p in proofs],
    }

    return AuditReport(
        generated_at=generated_at,
        tool_version=tool_version,
        chain_verdict=verdict.to_dict(),
        nodes=list(grouped.values()),
        obligations=obligations,
        summary=summary,
        input_hashes=input_hashes,
        global_findings=global_findings,
    )


# ---------------------------------------------------------------------------
# Sign / verify the manifest
# ---------------------------------------------------------------------------


def _require_crypto() -> Any:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def sign_manifest(report: AuditReport, audit_key_pem: bytes) -> dict[str, Any]:
    """Ed25519-sign the canonical manifest body with the org's audit key.

    The signature is over ``_canonical_json(body)`` — the same canonical form
    (and integer bound) the rest of the system uses, so the signed bytes are
    reproducible cross-implementation.
    """
    serialization, _, _ = _require_crypto()
    priv = serialization.load_pem_private_key(audit_key_pem, password=None)
    body = report.body()
    signed_bytes = _canonical_json(body)
    sig = priv.sign(signed_bytes)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "body": body,
        "signature": "ed25519:" + sig.hex(),
        "signer_key_id": _sha256_hex(pub_pem)[:16],
        "signer_public_key_pem": pub_pem.decode("ascii"),
    }


def signer_key_id(manifest: dict[str, Any]) -> str:
    """The signer identity DERIVED from the embedded public key — never the
    free-text ``signer_key_id`` field, which is unsigned and display-only."""
    pem = manifest["signer_public_key_pem"].encode("ascii")
    return _sha256_hex(pem)[:16]


def verify_manifest(manifest: dict[str, Any]) -> bool:
    """Re-verify a signed manifest offline. Two checks: (1) the signature is
    valid under the embedded public key over the canonical ``body`` bytes; and
    (2) the displayed ``signer_key_id`` actually equals the id derived from that
    public key — so a mutated identity label is rejected, not silently trusted.

    Note: this confirms internal consistency. WHICH key to trust is the caller's
    out-of-band pinning step (as with the provenance trusted-issuer set)."""
    serialization, _, _ = _require_crypto()
    try:
        pem = manifest["signer_public_key_pem"].encode("ascii")
        pub = serialization.load_pem_public_key(pem)
        sig_hex = manifest["signature"].split(":", 1)[1]
        pub.verify(bytes.fromhex(sig_hex), _canonical_json(manifest["body"]))
    except Exception:
        return False
    # The displayed key id must match the key that actually verified.
    expected_key_id = _sha256_hex(pem)[:16]
    return manifest.get("signer_key_id") == expected_key_id


# ---------------------------------------------------------------------------
# HTML render (dependency-free; print to PDF)
# ---------------------------------------------------------------------------

_BADGE = {GREEN: "✅ GREEN", AMBER: "⚠️ AMBER", RED: "⛔ RED"}


def _esc(s: str) -> str:
    import html

    return html.escape(str(s))


def _badge(status: str) -> str:
    """A fixed badge for a known status, else the escaped raw value — never raw
    HTML (a hand-crafted manifest with status '<script>...' must not inject)."""
    return _BADGE.get(status, _esc(status))


def render_html(manifest: dict[str, Any]) -> str:
    """Render the signed manifest as a self-contained HTML report (print → PDF)."""
    body = manifest["body"]
    s = body["summary"]
    rows = []
    for n in body["nodes"]:
        cert = ""
        if n.get("proof_certificate"):
            cert = (
                f"<br><small>proof <code>{_esc(n['proof_certificate'])}</code>"
                f" · {_esc(n.get('lean_theorem', ''))}</small>"
            )
        rows.append(
            f"<tr><td>{_esc(n['label'])}{cert}</td><td>{_badge(n['status'])}</td>"
            f"<td>{_esc('; '.join(n['evidence']))}</td></tr>"
        )
    obls = []
    for o in body["obligations"]:
        obls.append(
            f"<tr><td>{_esc(o['name'])}</td><td>{_badge(o['status'])}</td>"
            f"<td><code>{_esc(o['certificate'])}</code></td><td>{_esc(o['detail'])}</td></tr>"
        )
    pk = "".join(
        f"<li><code>{_esc(k)}</code>: <code>{_esc(v)}</code></li>"
        for k, v in body["input_hashes"]["public_keys"].items()
    )
    cs = "".join(
        f"<li><code>{_esc(k)}</code>: <code>{_esc(v)}</code></li>"
        for k, v in body["input_hashes"].get("capability_statements", {}).items()
    )
    gf = body.get("global_findings", [])
    global_block = (
        "<h2>Chain-level findings (not attributable to one node)</h2><ul>"
        + "".join(f"<li>{_esc(f)}</li>" for f in gf)
        + "</ul>"
        if gf
        else ""
    )
    node_rows = "".join(rows) or "<tr><td colspan=3>none</td></tr>"
    obl_rows = "".join(obls) or "<tr><td colspan=4>none supplied</td></tr>"
    g, a, rd = s["green"], s["amber"], s["red"]
    chain_state = "VALID" if s["chain_valid"] else "INVALID"
    signer = signer_key_id(manifest)  # derived from the embedded key, not the label
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>raucle audit export</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;max-width:900px;margin:2rem auto;color:#1a1a1a}}
 table{{border-collapse:collapse;width:100%;margin:1rem 0}}
 th,td{{border:1px solid #ddd;padding:6px 10px;text-align:left;vertical-align:top}}
 code{{font-size:12px;word-break:break-all}}
 .sum{{font-size:16px}}
 .box{{background:#f6f8fa;border:1px solid #e1e4e8;padding:12px;border-radius:6px}}
</style></head><body>
<h1>raucle audit export</h1>
<p class="sum">Chain: <strong>{chain_state}</strong> ·
 {s["receipt_count"]} receipts · ✅ {g} green · ⚠️ {a} amber · ⛔ {rd} red</p>
<p>Generated at {body["generated_at"]} · tool v{_esc(body["tool_version"])} ·
 signed by <code>{_esc(signer)}</code></p>

<h2>Agents &amp; tools</h2>
<table><tr><th>Node</th><th>Status</th><th>Evidence</th></tr>{node_rows}</table>

<h2>Proof obligations</h2>
<table><tr><th>Obligation</th><th>Status</th><th>Certificate</th><th>Detail</th></tr>{obl_rows}</table>
{global_block}
<div class="box">
<h3>What this report does and does not claim</h3>
<p>This is a <strong>reproducible attestation</strong>, not a certification.
 Every status is recomputable offline from the inputs below. GREEN proof
 obligations rest on an explicit prover-soundness axiom (the SMT solver is a
 trusted oracle). The binding from a cited proof to a tool's (schema, policy) is
 enforced operationally by the gate's strict proof mode, not mechanised in Lean.
 See the v0.17.0 CHANGELOG "Scope &amp; claims" note.</p>
</div>

<h2>Inputs (SHA-256)</h2>
<p>Chain: <code>{_esc(body["input_hashes"]["chain_sha256"])}</code></p>
<p>Public keys:</p><ul>{pk or "<li>none</li>"}</ul>
<p>Capability statements (gate allowed-tools / models — they affect node
 status):</p><ul>{cs or "<li>none (no per-agent tool/model enforcement applied)</li>"}</ul>
<p>Proof certificates: {_esc(", ".join(body["input_hashes"]["proofs"]) or "none")}</p>

<h2>Verify this report yourself</h2>
<ol>
 <li>Recompute the chain SHA-256 and confirm it matches above.</li>
 <li>Run <code>raucle provenance verify &lt;chain&gt; --pubkeys &lt;the same
  capability-statement files&gt;</code> — pass the capability statements, not bare
  PEM keys, so the agents' allowed-tools/models are enforced; confirm the verdict
  matches "Chain" above. (A capability-violation status is only reproducible with
  the statements listed above.)</li>
 <li>Recompute each proof certificate hash and confirm it matches the obligations table.</li>
 <li>Verify the manifest signature with the signer public key embedded in the manifest JSON.</li>
</ol>
</body></html>"""
