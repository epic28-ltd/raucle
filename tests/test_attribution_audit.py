"""B2: attribution field review across the adapters.

Invariant: every ALLOWED execution carries a real acting identity, and no
minted receipt ever carries a fabricated placeholder. An attempt without an
attributable identity is DENIED with the reason recorded - the same
fail-closed doctrine the gateway enforces (v0.23.2) and the prerequisite
for B1 (agent+user pair permissioning).

Audit findings (29 Oct):
- langchain: agent_id fell back to the placeholder "<unbound>" and the call
  RAN attributed to it (bearer mode by default). FIXED: require_agent_id
  defaults True; unattributed attempts deny; no placeholder is minted.
- crewai: agent_id=None meant bearer mode - the call ran with a receipt
  attributed to JSON null. FIXED: unattributed attempts deny.
- autogen: agent_id is an explicit parameter with no empty-check; an empty
  identity flowed into the receipt. FIXED: empty denies.
- agent_framework: ACCEPTED (documented, deliberate): the caller id comes
  from the framework context; only when the framework surfaces none does it
  fall back to the token's own agent_id, a real identity under bearer trust.
  B1 should surface the acting-for user so the fallback never triggers.
- a2a: identity is required by construction; no gap.
"""

from __future__ import annotations

import json
import pathlib

import pytest

pytest.importorskip("cryptography")

from raucle.audit import Ed25519Signer, HashChainSink  # noqa: E402
from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402


def _sink(tmp_path: pathlib.Path):
    log = tmp_path / "receipts.jsonl"
    return HashChainSink(log, signer=Ed25519Signer.generate()), log


def test_crewai_unattributed_call_denies(tmp_path):
    pytest.importorskip("crewai")
    from pydantic import BaseModel

    from raucle.integrations.crewai import CapabilityDenied, guard_tool, set_in_force_token

    class _Args(BaseModel):
        to: str

    from crewai.tools import BaseTool

    class _Tool(BaseTool):
        name: str = "lookup_contact"
        description: str = "test tool"
        args_schema: type = _Args

        def _run(self, to: str) -> str:
            return f"LOOKED UP {to}"

    issuer = CapabilityIssuer.generate(issuer="test.platform")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink, log = _sink(tmp_path)
    guarded = guard_tool(_Tool(), gate=gate, sink=sink, agent_id=None)  # bearer-mode attempt
    token = issuer.mint(agent_id="agent:test", tool="lookup_contact", ttl_seconds=60)
    set_in_force_token(token)
    try:
        with pytest.raises(CapabilityDenied):
            guarded.run(to="someone")
        # the receipt records the attempt honestly: a real decision, no
        # fabricated identity
        receipt = json.loads(log.read_text().strip().splitlines()[-1])["event"]
        assert receipt["decision"] == "DENY"
        assert "agent_id" in receipt  # present, honestly None
        assert receipt["agent_id"] is None
        assert receipt["decision_reason"], receipt
    finally:
        set_in_force_token(None)


def test_langchain_unattributed_call_denies_by_default(tmp_path):
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    from raucle.integrations.langchain import (
        CapabilityDenied,
        RaucleCallbackHandler,
        set_in_force_token,
    )

    @tool
    def lookup_contact(name: str) -> str:
        """Lookup `name` (test tool)."""
        return f"LOOKED UP {name}"

    issuer = CapabilityIssuer.generate(issuer="test.platform")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink, log = _sink(tmp_path)
    handler = RaucleCallbackHandler(gate=gate, sink=sink)  # default require_agent_id
    token = issuer.mint(agent_id="agent:test", tool="lookup_contact", ttl_seconds=60)
    set_in_force_token(token)
    try:
        # no metadata.agent_id: the call must deny, not run attributed to a
        # placeholder
        with pytest.raises(CapabilityDenied):
            lookup_contact.invoke({"name": "someone"}, {"callbacks": [handler]})
        receipts = [
            json.loads(ln)["event"]
            for ln in log.read_text().strip().splitlines()
            if json.loads(ln).get("event") is not None
        ]
        assert receipts, "no receipt minted"
        for receipt in receipts:
            assert "unbound" not in json.dumps(receipt), receipt
            assert receipt["decision"] == "DENY"
            assert receipt["agent_id"] is None, receipt
            assert receipt["decision_reason"], receipt
    finally:
        set_in_force_token(None)


def test_langchain_attributed_call_still_allows(tmp_path):
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    from raucle.integrations.langchain import RaucleCallbackHandler, set_in_force_token

    @tool
    def lookup_contact(name: str) -> str:
        """Lookup `name` (test tool)."""
        return f"LOOKED UP {name}"

    issuer = CapabilityIssuer.generate(issuer="test.platform")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink, log = _sink(tmp_path)
    handler = RaucleCallbackHandler(gate=gate, sink=sink)
    token = issuer.mint(agent_id="agent:test", tool="lookup_contact", ttl_seconds=60)
    set_in_force_token(token)
    try:
        result = lookup_contact.invoke(
            {"name": "someone"}, {"callbacks": [handler], "metadata": {"agent_id": "agent:test"}}
        )
        assert result == "LOOKED UP someone"
        receipt = json.loads(log.read_text().strip().splitlines()[-1])["event"]
        assert receipt["decision"] == "ALLOW"
        assert receipt["agent_id"] == "agent:test"
    finally:
        set_in_force_token(None)


@pytest.mark.asyncio
async def test_autogen_empty_identity_denies(tmp_path):
    pytest.importorskip("autogen_core.tools")
    from autogen_core.tools import FunctionTool

    from raucle.integrations.autogen import CapabilityDenied, gated_tools, set_in_force_token

    issuer = CapabilityIssuer.generate(issuer="test.platform")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    sink, log = _sink(tmp_path)

    async def lookup_contact(name: str) -> str:
        return f"LOOKED UP {name}"

    raw = FunctionTool(lookup_contact, description="Look up a contact (test).")
    # empty string is not an identity: deny rather than mint a receipt
    # attributed to ""
    tools = gated_tools([raw], gate=gate, sink=sink, agent_id="")
    token = issuer.mint(agent_id="agent:test", tool="lookup_contact", ttl_seconds=60)
    set_in_force_token(token)
    try:
        with pytest.raises(CapabilityDenied) as excinfo:
            await tools[0].run_json(args={"name": "someone"}, cancellation_token=None)
        assert excinfo.value is not None
        receipt = json.loads(log.read_text().strip().splitlines()[-1])["event"]
        assert receipt["decision"] == "DENY"
        assert not receipt["agent_id"], receipt
    finally:
        set_in_force_token(None)
