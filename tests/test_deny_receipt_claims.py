"""Q15 verdict remedy (D3): pin the receipted-deny claim in the shipped docs.

The #321 checker verdict flagged a FALSE claim: the demo-service comment in
docker-compose.gateway.yml and two docs pages said unauthenticated demo
traffic earns receipted DENYs, while raucle.gateway_app._gate_deny_response
returns receipt_id None and the pre-gate refusal fires before any receipt
trail (verified live: a pre-gate refusal writes nothing to the receipt
store, an authenticated constraint violation writes one). The docs now
state the boundary precisely; these tests stop the overclaim from drifting
back and stay wrap-tolerant by asserting on whitespace-collapsed text.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _flatten(rel: str) -> str:
    text = (ROOT / rel).read_text(encoding="utf-8")
    return " ".join(text.split())


def test_compose_states_the_receipt_boundary():
    flat = _flatten("docker-compose.gateway.yml")
    assert "receipt_id null" in flat
    assert "transport-layer refusals, not receipted evidence" in flat
    assert "authenticated caller's gate deny is receipted" in flat
    # The overclaim is gone, not just amended.
    assert "receipted DENY" not in flat


def test_demonstrator_states_when_deny_receipts_exist():
    flat = _flatten("docs/deployment-demonstrator.md")
    assert "`receipt_id` null" in flat
    assert "receipt trail starts at `check_tool_call`" in flat
    assert "transport-layer refusals, not receipted evidence" in flat
    assert "the gate verdict itself was deny" in flat
    assert "receipted DENYs" not in flat


def test_production_hardening_states_when_deny_receipts_exist():
    flat = _flatten("docs/getting-started/20-production-hardening.md")
    assert "**receipted DENY** is what an authenticated caller earns" in flat
    assert "`receipt_id` null" in flat
    assert "transport-layer refusals, not evidence" in flat
    assert "an unauthenticated attempt is itself evidence" not in flat
