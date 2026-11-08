"""Generate the standards test vectors for cap:v1, proof:v1, gate-decision:v1.

Run:
    PYTHONPATH=. python standards/test-vectors/generate.py

Produces vectors that any conforming implementation must round-trip.

Vectors are deterministic given a fixed RNG seed for the Ed25519 keys, so the
output is reproducible across runs. Implementations re-running this script
should get bit-identical output.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from raucle import capability as _cap_mod
from raucle.capability import Capability, CapabilityIssuer
from raucle.prove import JSONSchemaProver
from raucle.tool_schema import SchemaPolicyLoadError, ToolSchemaRegistry

OUT = Path(__file__).parent

# Fixed Ed25519 secret seed for reproducibility. NOT a real production key.
ISSUER_SEED = bytes(range(32))
AUDIT_SEED = bytes([0xFE] * 32)

# Pin the clock so re-runs produce bit-identical vectors.
# 2026-05-14T12:00:00Z = 1747224000.
FROZEN_NOW = 1_747_224_000
_cap_mod._now = lambda: FROZEN_NOW


def write_json(path: Path, obj: dict) -> None:
    """Pretty-print with stable key order so two runs produce identical files."""
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    print(f"  wrote {path.name}")


def build_issuer() -> CapabilityIssuer:
    key = Ed25519PrivateKey.from_private_bytes(ISSUER_SEED)
    return CapabilityIssuer(issuer="vectors.example", private_key=key)


# ---------------------------------------------------------------------------
# cap:v1 vectors
# ---------------------------------------------------------------------------


def cap_vectors() -> None:
    issuer = build_issuer()
    print(f"Issuer key_id = {issuer.key_id}")
    Path(OUT / "cap_issuer_pubkey.pem").write_text(issuer.public_key_pem)

    # Vector 1: minimal token, no constraints, no parent.
    v1 = issuer.mint(
        agent_id="agent:demo",
        tool="echo",
        constraints={},
        ttl_seconds=3600,
    )
    write_json(OUT / "cap_v1_01_minimal.json", v1.to_dict())

    # Vector 2: token with constraints.
    v2 = issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={
            "max_value": {"amount": 100},
            "allowed_values": {"currency": ["USD", "EUR", "GBP"]},
        },
        ttl_seconds=3600,
    )
    write_json(OUT / "cap_v1_02_constraints.json", v2.to_dict())

    # Vector 3: attenuated child of vector 2.
    v3 = issuer.attenuate(
        v2,
        extra_constraints={"max_value": {"amount": 50}},
    )
    write_json(OUT / "cap_v1_03_attenuated.json", v3.to_dict())

    # Vector 4: token with policy_proof_hash binding.
    v4 = issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={"max_value": {"amount": 100}},
        ttl_seconds=3600,
        policy_proof_hash="sha256:" + "c" * 64,
    )
    write_json(OUT / "cap_v1_04_with_proof.json", v4.to_dict())

    # Vector 5: deliberately tampered. Same token as v2 but with the
    # max_value bound silently raised. Must fail verification.
    v5 = Capability.from_dict(v2.to_dict())
    v5.constraints = {
        "max_value": {"amount": 999_999},
        "allowed_values": {"currency": ["USD", "EUR", "GBP"]},
    }
    # Keep the original signature; the body now mismatches.
    write_json(OUT / "cap_v1_05_tampered.json", v5.to_dict())


# ---------------------------------------------------------------------------
# proof:v1 vectors
# ---------------------------------------------------------------------------


def proof_vectors() -> None:
    schema_basic = {
        "type": "object",
        "properties": {
            "to": {"type": "string", "enum": ["alice@example.com", "bob@example.com"]},
            "amount": {"type": "number", "minimum": 0, "maximum": 100},
            "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]},
        },
        "required": ["to", "amount", "currency"],
    }

    # Vector 1: trivially PROVEN.
    policy_ok = {
        "max_value": {"amount": 100},
        "forbidden_values": {"to": ["attacker@evil.example"]},
    }
    r1 = JSONSchemaProver().prove(schema_basic, policy_ok)
    write_json(OUT / "proof_v1_01_proven.json", r1.to_dict())

    # Vector 2: REFUTED with concrete counterexample.
    policy_too_strict = {"max_value": {"amount": 50}}
    r2 = JSONSchemaProver().prove(schema_basic, policy_too_strict)
    write_json(OUT / "proof_v1_02_refuted.json", r2.to_dict())


# ---------------------------------------------------------------------------
# gate-decision:v1 vectors (representative, JSON only — actual emission depends
# on a runtime gate; we generate the canonical shape here)
# ---------------------------------------------------------------------------


def gate_decision_vectors() -> None:
    # We generate three illustrative events plus the schema for review.
    schema = {
        "version": "gate-decision:v1",
        "fields": [
            "event_id",
            "timestamp",
            "decision",
            "deny_reason",
            "deny_check",
            "tool",
            "agent_id",
            "caller_session",
            "args_hash",
            "token_id",
            "issuer_key_id",
            "policy_proof_hash",
            "gate_id",
            "gate_version",
            "prev_event_hash",
            "chain_index",
            "signature",
        ],
        "notes": (
            "Event-body hashing excludes event_id and signature. "
            "See standards/owasp-ai-exchange/03-gate-decision-profile.md."
        ),
    }
    write_json(OUT / "gate_decision_v1_schema.json", schema)


def schema_enforcement_vectors() -> None:
    """X1: schema-bound enforcement vectors (schema_enforcement:v1).

    The acceptance case is vector 01: the tool declares `amount` as a
    number, the policy carries NO bound on it, and the string "99999"
    must still DENY because it is type-confused against the schema.
    Reasons are produced by the reference implementation, so the JSON is
    a byte-stable conformance artifact.
    """
    accept_schema = {
        "type": "object",
        "properties": {
            "recipient": {"type": "string"},
            "amount": {"type": "number"},
        },
        "required": ["recipient", "amount"],
    }

    # 01: the acceptance case.
    reg = ToolSchemaRegistry()
    reg.register("send_money", accept_schema)
    reasons = reg.violations("send_money", {"recipient": "alice@example", "amount": "99999"})
    assert reasons, "acceptance vector must assert the schema_violation deny"
    write_json(
        OUT / "schema_enforcement_v1_01_type_confusion_denies.json",
        {
            "spec": "raucle-schema-enforcement/v1",
            "name": "type-confused amount denies with no max bound (acceptance case)",
            "tool": "send_money",
            "inputSchema": accept_schema,
            "policy_rule": {"required_present": ["amount"]},
            "bound_rule": {
                "tool": "send_money",
                "agent_id": "agent:pay",
                "required_present": ["amount"],
            },
            "args": {"recipient": "alice@example", "amount": "99999"},
            "decision": {
                "decision": "deny",
                "reason": f"schema_violation: {reasons[0]}",
            },
            "note": (
                "The rule carries no max_value; the DENY comes purely from the "
                "schema binding (amount is declared number, value is str)."
            ),
        },
    )

    # 02: undeclared policy field is a load-time error.
    load_schema = {"type": "object", "properties": {"amount": {"type": "number"}}}
    reg2 = ToolSchemaRegistry()
    reg2.register("transfer", load_schema)
    load_err = _load_error_capture(reg2, "transfer")
    write_json(
        OUT / "schema_enforcement_v1_02_undeclared_field_load_error.json",
        {
            "spec": "raucle-schema-enforcement/v1",
            "name": "policy rule referencing an undeclared field is a load-time error",
            "tool": "transfer",
            "inputSchema": load_schema,
            "policy_rule": {"forbidden_values": {"recipient": ["US133000000121212121212"]}},
            "load": {
                "outcome": "error",
                "error_kind": "SchemaPolicyLoadError",
                "message": load_err,
            },
        },
    )

    # 03: bool/int coercion edge — true is not an integer.
    reg3 = ToolSchemaRegistry()
    reg3.register("t", {"type": "object", "properties": {"n": {"type": "integer"}}})
    bool_reasons = reg3.violations("t", {"n": True})
    assert bool_reasons
    write_json(
        OUT / "schema_enforcement_v1_03_bool_not_integer.json",
        {
            "spec": "raucle-schema-enforcement/v1",
            "name": "boolean value denies an integer-typed field",
            "tool": "t",
            "inputSchema": {"type": "object", "properties": {"n": {"type": "integer"}}},
            "args": {"n": True},
            "decision": {"decision": "deny", "reason": f"schema_violation: {bool_reasons[0]}"},
        },
    )


def _load_error_capture(reg: ToolSchemaRegistry, tool: str) -> str:
    """Bind a rule referencing an undeclared field and capture the message."""
    try:
        reg.bind_policy(tool, {"forbidden_values": {"recipient": ["x"]}})
    except SchemaPolicyLoadError as exc:
        return str(exc)
    raise AssertionError("expected SchemaPolicyLoadError")


def main() -> None:
    print("=== cap:v1 vectors ===")
    cap_vectors()
    print("\n=== proof:v1 vectors ===")
    proof_vectors()
    print("\n=== gate-decision:v1 schema ===")
    gate_decision_vectors()
    print("\n=== schema-enforcement:v1 vectors ===")
    schema_enforcement_vectors()
    print(f"\nAll vectors written under {OUT}")


if __name__ == "__main__":
    main()
