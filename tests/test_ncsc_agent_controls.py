# ruff: noqa: F811
"""NCSC agent-control matrix: controls from the NCSC agentic AI deployment
guidance mapped to receipted evidence in the running product.

The NCSC's deployment test: "if you cannot understand, monitor or contain an
agent's actions, it is not ready for deployment". This harness is the
machine-checkable half of the mapping documented in
docs/security/ncsc-agent-controls.md: every control names the flow, the
receipt artefact and the assertion that proves it.

The fixtures are imported from the authority-attribution suite on purpose:
the matrix cannot drift from the product behaviour it claims to evidence, and
any change to those flows fails here too.
"""

import json

from raucle.provenance import ProvenanceVerifier
from tests.test_authority_attribution import (
    AUTH,
    OP_AUTH,
    POLICY,
    _chain_records,
    _decode_payload,
    _pay_key,
    _svc_key,
    admin,  # noqa: F401  imported for its fixture registration
    config,  # noqa: F401  imported for its fixture registration
    gate,  # noqa: F401  imported for its fixture registration
    gw,  # noqa: F401  imported for its fixture registration
)

GATE_CALL_SVC_BALANCE = {
    "tool": "lookup_balance",
    "args": {"account": "ACC-001"},
    "agent_id": "agent:svc",
}


def _receipt_hashes(gw):
    with open(gw.config.receipt_store, encoding="utf-8") as fh:
        return [json.loads(line)["receipt_hash"] for line in fh if line.strip()]


# --------------------------------------------------------------------------
# Control 1: least privilege; agents hold no standing authority beyond
# TTL-scoped, tool-scoped policy
# --------------------------------------------------------------------------
def _evidence_no_standing_authority(gw, gate):
    key = _svc_key(gw)
    resp = gate.post("/gate", json=GATE_CALL_SVC_BALANCE, headers={"X-Api-Key": key})
    body = resp.json()
    assert body["decision"] == "allow"
    rec = _chain_records(gw)[-1]
    payload = _decode_payload(rec["jws"])
    # the receipt binds the exact agent, tool and arguments: authority was in
    # the request, not standing on the machine. The signer is the gate
    # identity; the acting agent is bound inside x_gate.
    assert payload["x_gate"]["agent_id"] == "agent:svc"
    assert payload["x_gate"]["tool"] == "lookup_balance"
    bound = (payload["x_gate"]["agent_id"], payload["x_gate"]["tool"])
    return {"receipt_id": body["receipt_id"], "bound": bound}


# --------------------------------------------------------------------------
# Control 2: limit scope; out-of-policy tools and arguments fail receipted
# --------------------------------------------------------------------------
def _evidence_scoped_denial(gw, gate):
    # agent:svc asking for transfer_money, which the policy grants only to agent:pay
    key = _svc_key(gw)
    out_of_scope = {
        "tool": "transfer_money",
        "args": {"from_account": "ACC-001", "amount": 500},
        "agent_id": "agent:svc",
    }
    resp = gate.post("/gate", json=out_of_scope, headers={"X-Api-Key": key})
    assert resp.json()["decision"] == "deny"
    deny_receipt = resp.json()["receipt_id"]
    assert deny_receipt.startswith("sha256:")
    # also: an unknown tool is denied, not hallucinated into existence
    resp2 = gate.post(
        "/gate",
        json={"tool": "no_such_tool", "args": {}, "agent_id": "agent:svc"},
        headers={"X-Api-Key": key},
    )
    assert resp2.json()["decision"] == "deny"
    assert resp2.json()["receipt_id"].startswith("sha256:")
    return {"deny_receipt": deny_receipt, "denies": 2}


# --------------------------------------------------------------------------
# Control 3: monitor behaviour; every decision is a signed, chained receipt
# verified by the standard offline verifier
# --------------------------------------------------------------------------
def _evidence_signed_chain(gw, gate):
    key = _svc_key(gw)
    resp = gate.post("/gate", json=GATE_CALL_SVC_BALANCE, headers={"X-Api-Key": key})
    receipt_id = resp.json()["receipt_id"]
    verifier = ProvenanceVerifier(
        public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
    )
    report = verifier.verify_chain(gw.config.receipt_store)
    assert report.valid, report.errors
    assert receipt_id in _receipt_hashes(gw)
    return {"receipt_id": receipt_id, "chain_valid": True}


# --------------------------------------------------------------------------
# Control 4: named accountability; a specific human role can stop an agent,
# the stop itself is receipted, and revocation bites immediately
# --------------------------------------------------------------------------
def _evidence_named_stop(gw, gate, admin):
    key = _svc_key(gw)
    resp = gate.post("/gate", json=GATE_CALL_SVC_BALANCE, headers={"X-Api-Key": key})
    assert resp.json()["decision"] == "allow"
    # only the admin role may stop an agent
    r_op = admin.post(
        "/api/agents/agent:svc/suspend", json={"reason": "not allowed"}, headers=OP_AUTH
    )
    assert r_op.status_code == 403
    # the named accountability holder stops the agent
    r_admin = admin.post(
        "/api/agents/agent:svc/suspend", json={"reason": "incident test"}, headers=AUTH
    )
    assert r_admin.status_code == 200
    body = r_admin.json()
    assert body["suspended"] is True
    assert "apikey" in body["revoked"]
    assert body["receipt_id"].startswith("sha256:")
    # the credential is dead immediately
    resp2 = gate.post("/gate", json=GATE_CALL_SVC_BALANCE, headers={"X-Api-Key": key})
    assert resp2.json()["decision"] == "deny"
    assert "invalid or revoked" in resp2.json()["reason"]
    # the stop is evidence, not an event log line: actor, reason, receipt
    stops = [r for r in _chain_records(gw) if _decode_payload(r["jws"]).get("x_stop")]
    assert stops
    stop_payload = _decode_payload(stops[-1]["jws"])
    assert stop_payload["x_stop"]["agent_id"] == "agent:svc"
    assert stop_payload["x_stop"]["reason"] == "incident test"
    assert stop_payload["x_stop"]["actor"] == "Admin"
    return {"stop_receipt": body["receipt_id"], "post_stop_decision": resp2.json()["decision"]}


# --------------------------------------------------------------------------
# Control 5: high-impact actions need a human; the approval is bound to exact
# args and the action receipt cites the approval
# --------------------------------------------------------------------------
def _evidence_human_approval(gw, gate, admin):
    key = _pay_key(gw)
    call = {
        "tool": "transfer_money",
        "args": {"from_account": "ACC-001", "amount": 500},
        "agent_id": "agent:pay",
    }
    r1 = gate.post("/gate", json=call, headers={"X-Api-Key": key})
    body = r1.json()
    assert body["decision"] == "escalate"
    approval_id = body["approval_request_id"]
    r2 = admin.post(f"/api/approvals/{approval_id}/decision", json={"approved": True}, headers=AUTH)
    assert r2.status_code == 200
    # the approval bound the exact args: a different amount cannot ride it
    r_ride = gate.post(
        "/gate",
        json={**call, "args": {**call["args"], "amount": 5000}},
        headers={"X-Api-Key": key, "X-Approval-Id": approval_id},
    )
    assert r_ride.json()["decision"] != "allow"
    # the bound call is allowed and cites the approval in its receipt
    r3 = gate.post("/gate", json=call, headers={"X-Api-Key": key, "X-Approval-Id": approval_id})
    assert r3.json()["decision"] == "allow"
    action_payload = _decode_payload(_chain_records(gw)[-1]["jws"])
    assert action_payload["x_gate"]["approval_id"] == approval_id
    dec = [
        r
        for r in _chain_records(gw)
        if _decode_payload(r["jws"]).get("x_approval", {}).get("request_id") == approval_id
        and _decode_payload(r["jws"]).get("guardrail_verdict") == "approval_granted"
    ]
    assert dec
    assert _decode_payload(dec[0]["jws"])["x_approval"]["approver"] == "Admin"
    return {"approval_id": approval_id, "final_decision": r3.json()["decision"]}


# --------------------------------------------------------------------------
# Control 6: the authority an agent held (and could use) is a signed snapshot
# --------------------------------------------------------------------------
def _evidence_authority_envelope(gw, admin):
    resp = admin.get("/api/agents/agent:pay/authority", headers=AUTH)
    assert resp.status_code == 200
    body = resp.json()
    tools = {p["tool"] for p in body["envelope"]["policies"]}
    assert "transfer_money" in tools
    assert body["envelope"]["credential"]["apikey_active"] is True
    payload = _decode_payload(body["jws"])
    assert payload["typ"] == "raucle/authority-envelope/v1"
    assert payload["agent_id"] == "agent:pay"
    return {"typ": payload["typ"], "tools": sorted(tools)}


# --------------------------------------------------------------------------
# Control 7: tampering is provable, not suspected
# --------------------------------------------------------------------------
def _evidence_tamper_detection(gw, admin):
    from pathlib import Path as _Path

    r1 = admin.put("/api/policies", json={"content": POLICY}, headers=AUTH)
    assert r1.status_code == 200
    admin.put("/api/policies", json={"content": POLICY}, headers=OP_AUTH)
    path = _Path(gw.config.policy_ledger_path)
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    rec = json.loads(lines[-1])
    rec["actor"] = "ghost"
    lines[-1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = admin.get("/api/policy-ledger", headers=AUTH).json()
    assert result["integrity"]["valid"] is False
    return {"integrity_valid": False, "entries": result["count"]}


# --------------------------------------------------------------------------
# Control 8: who changed the policy is first-class evidence
# --------------------------------------------------------------------------
def _evidence_policy_ledger(gw, admin):
    new_policy = POLICY.replace("ACC-002", "ACC-007")
    resp = admin.put("/api/policies", json={"content": new_policy}, headers=AUTH)
    assert resp.status_code == 200
    ledger = admin.get("/api/policy-ledger", headers=AUTH).json()
    assert ledger["count"] >= 1
    entry = ledger["entries"][-1]
    assert entry["actor"] == "Admin"
    assert entry["action"] == "policy_updated"
    assert entry["sha256"]
    assert entry["prev_hash"]
    assert ledger["integrity"]["valid"] is True
    return {"actor": entry["actor"], "action": entry["action"], "integrity": True}


CONTROLS = [
    ("least privilege, no standing authority", _evidence_no_standing_authority),
    ("limit scope, receipted denial", _evidence_scoped_denial),
    ("monitor behaviour, verifiable chain", _evidence_signed_chain),
    ("named accountability, receipted stop", _evidence_named_stop),
    ("human approval on high-impact actions", _evidence_human_approval),
    ("authority envelope snapshot", _evidence_authority_envelope),
    ("tamper-evident records", _evidence_tamper_detection),
    ("traceable policy governance", _evidence_policy_ledger),
]


class TestNCSCAgentControlMatrix:
    def test_matrix_is_complete(self):
        assert len(CONTROLS) == 8
        names = [c[0] for c in CONTROLS]
        assert len(names) == len(set(names))

    def test_control_1_least_privilege(self, gw, gate):
        ev = _evidence_no_standing_authority(gw, gate)
        assert ev["bound"] == ("agent:svc", "lookup_balance")

    def test_control_2_scoped_denial(self, gw, gate):
        ev = _evidence_scoped_denial(gw, gate)
        assert ev["denies"] == 2

    def test_control_3_signed_chain(self, gw, gate):
        ev = _evidence_signed_chain(gw, gate)
        assert ev["chain_valid"] is True

    def test_control_4_named_stop(self, gw, gate, admin):
        ev = _evidence_named_stop(gw, gate, admin)
        assert ev["post_stop_decision"] == "deny"

    def test_control_5_human_approval(self, gw, gate, admin):
        ev = _evidence_human_approval(gw, gate, admin)
        assert ev["final_decision"] == "allow"

    def test_control_6_envelope(self, gw, admin):
        ev = _evidence_authority_envelope(gw, admin)
        assert ev["typ"] == "raucle/authority-envelope/v1"

    def test_control_7_tamper_detection(self, gw, admin):
        ev = _evidence_tamper_detection(gw, admin)
        assert ev["integrity_valid"] is False

    def test_control_8_policy_ledger(self, gw, admin):
        ev = _evidence_policy_ledger(gw, admin)
        assert ev["actor"] == "Admin" and ev["integrity"] is True
