"""Receipts v1.2 (lane K3): revocation-event receipts, the v1.2 kind.

Spec: docs/spec/provenance/v1.2/revocation-receipts.md. The shipped
emitter mints the v1.0 shape; when a revocation receipt kind is
requested the emitter extends to the full v1.2 block: version, kind,
revoked_ids, revoked_hashes (chain linkage, keys exactly equal to the
ids), optional root, actor, reason_class (closed vocabulary),
optional reason and revoked_at. Revocation is a new link in the chain,
never an edit: prior digests are unchanged, pre-revocation receipts
stay valid, and receipts minted after the revocation line that cite
the revoked authority are invalid with a named error. A consumer
meeting an unknown version, kind or reason class refuses with a named
error, never a skip; a revocation reason quoting a constraint value
fails the bounded-disclosure rule.
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from raucle.capability import CapabilityIssuer, DelegationLedger
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import ProvenanceVerifier, _canonical_json, _sha256_hex
from raucle.trust_registry import TrustRegistry

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: [\"ACC-001\", \"ACC-002\"]
"""


def _setup(tmp_path, chains=1):
    """A delegated gateway: root -> child per chain, revocations file
    live (the cascade harness)."""
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    config.policy_file = tmp_path / "policies.yaml"
    config.policy_file.write_text(POLICY)
    config.gate_auth = "token"
    config.delegations_file = str(tmp_path / "delegations.jsonl")
    config.revocations_file = str(tmp_path / "revocations.jsonl")

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger = DelegationLedger(tmp_path / "delegations.jsonl")
    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(pem, issuer="test-issuer")

    tokens = {}
    for c in range(chains):
        root = issuer.mint(
            agent_id="agent:svc",
            tool="lookup_balance",
            constraints={"allowed_values": {"account": [f"ACC-{c + 1:03d}"]}},
            ttl_seconds=600,
        )
        child = issuer.attenuate(root)
        ledger.register(root, "agent:svc", verifying_key=issuer)
        ledger.register(child, "agent:svc", verifying_key=issuer)
        tokens[f"root{c}"] = root
        tokens[f"child{c}"] = child

    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))
    return gw, client, tokens, tmp_path


def _gate(client, token, account="ACC-001", amount=1):
    return client.post(
        "/gate",
        json={
            "tool": "lookup_balance",
            "args": {"account": account, "amount": amount},
            "agent_id": "agent:svc",
        },
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )


def _payload_of(envelope):
    seg = envelope["jws"].split(".")[1]
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def _revocation_payloads(tmp_path):
    """Every x_revocation payload in the chain, in file order. An absent
    store is an empty list: a refused revocation mints nothing, so no
    file is created either."""
    store = tmp_path / "receipts.jsonl"
    if not store.exists():
        return []
    out = []
    for line in store.read_text().strip().splitlines():
        payload = _payload_of(json.loads(line))
        if "x_revocation" in payload:
            out.append(payload)
    return out


def _verify(gw, tmp_path):
    return ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()}
    ).verify_chain(tmp_path / "receipts.jsonl")


def _token_hash(token):
    """The chain linkage digest the emitter derives: sha256 over the
    canonical token bytes."""
    return "sha256:" + _sha256_hex(_canonical_json(token.to_dict()))


def _emit_revocation(gw, extension):
    """Mint an arbitrary x_revocation receipt through the authority
    emitter (the DLP-test pattern: claim-then-verify)."""
    return gw._emit_authority_receipt(
        verdict="authority_revoked",
        extension_key="x_revocation",
        extension=extension,
    )


def _v12_block(ids, hashes, **overrides):
    base = {
        "version": "revocation/v1",
        "kind": "capability",
        "revoked_ids": ids,
        "revoked_hashes": hashes,
        "actor": "admin",
        "reason_class": "compromise",
        "revoked_at": 1,
        "reason": "suspected compromise",
    }
    base.update(overrides)
    for key, value in list(overrides.items()):
        if value is None:
            base.pop(key)
    return base


def _emitter_only(tmp_path):
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    return RaucleGateway(config), tmp_path


# ---------------------------------------------------------------------------
# Emitter: the v1.2 kind on the shipped family
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        b'{"token_id":"tok-good"}\nnot-json\n',
        b'{"token_id":"tok-good"}\n{"reason":"missing id"}\n',
        b'{"token_id":"tok-good"}\n[]\n',
        b'{"token_id":"tok-good"}\n{"token_id":""}\n',
    ],
)
def test_revocation_registry_corruption_is_rejected(tmp_path, data):
    """A malformed registry must not silently drop revocations."""
    with pytest.raises(ValueError, match="revocation registry"):
        RaucleGateway._revoked_ids_from_bytes(data)


def test_revoke_capability_mints_v12_block(tmp_path):
    """A requested revocation receipt kind extends the shipped emitter
    to the full v1.2 shape, with the ledger-backed chain linkage."""
    gw, client, tokens, tmp = _setup(tmp_path)
    result = gw.revoke_capability(
        tokens["child0"].token_id,
        reason="suspected compromise",
        actor="admin",
        kind="capability",
        reason_class="compromise",
    )
    assert result["receipt_id"]
    rev = _revocation_payloads(tmp)[0]["x_revocation"]
    assert rev["version"] == "revocation/v1"
    assert rev["kind"] == "capability"
    assert rev["revoked_ids"] == [tokens["child0"].token_id]
    # the chain linkage: keys exactly equal the revoked ids, each value
    # the digest of the revoked token a third party holding it re-derives
    assert set(rev["revoked_hashes"]) == set(rev["revoked_ids"])
    assert rev["revoked_hashes"][tokens["child0"].token_id] == _token_hash(tokens["child0"])
    assert rev["actor"] == "admin"
    assert rev["reason_class"] == "compromise"
    assert rev["reason"] == "suspected compromise"
    assert rev["root"] == tokens["child0"].token_id
    payload = _revocation_payloads(tmp)[0]
    assert isinstance(rev["revoked_at"], int)
    assert rev["revoked_at"] <= payload["iat"]
    # the chain stays verifiable: the revocation is a new link
    assert _verify(gw, tmp).valid


def test_revoke_without_kind_ships_v10_shape(tmp_path):
    """Backwards compatibility: no kind requested, the shipped v1.0
    block (byte-compat with the accepted 30 October emitter)."""
    gw, client, tokens, tmp = _setup(tmp_path)
    gw.revoke_capability(tokens["child0"].token_id, reason="test", actor="admin")
    rev = _revocation_payloads(tmp)[0]["x_revocation"]
    assert set(rev) == {"revoked_ids", "root", "actor", "reason"}


def test_unknown_kind_refused_with_named_error(tmp_path):
    """The closed kind vocabulary is enforced at emission: an unknown
    kind is refused by name and mints nothing."""
    gw, client, tokens, tmp = _setup(tmp_path)
    with pytest.raises(ValueError) as exc:
        gw.revoke_capability(
            tokens["child0"].token_id,
            reason="test",
            actor="admin",
            kind="token",
            reason_class="compromise",
        )
    assert "kind" in str(exc.value)
    assert _revocation_payloads(tmp) == []


def test_unknown_reason_class_refused_with_named_error(tmp_path):
    gw, client, tokens, tmp = _setup(tmp_path)
    with pytest.raises(ValueError) as exc:
        gw.revoke_capability(
            tokens["child0"].token_id,
            reason="test",
            actor="admin",
            kind="capability",
            reason_class="misclick",
        )
    assert "reason_class" in str(exc.value)
    assert _revocation_payloads(tmp) == []


def test_capability_kind_needs_ledger_linkage(tmp_path):
    """Fail-closed: with no delegation ledger holding the revoked
    token, the v1.2 block cannot cite what it cannot hash, so the
    request is refused rather than fabricated."""
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    config.revocations_file = str(tmp_path / "revocations.jsonl")
    gw = RaucleGateway(config)
    with pytest.raises(ValueError) as exc:
        gw.revoke_capability(
            "tok-missing",
            reason="test",
            actor="admin",
            kind="capability",
            reason_class="compromise",
        )
    assert "ledger" in str(exc.value)


def test_owner_departure_mints_v12_for_every_chain(tmp_path):
    gw, client, tokens, tmp = _setup(tmp_path, chains=2)
    result = gw.revoke_agent_chains(
        "agent:svc",
        reason="departure",
        actor="hr",
        kind="capability",
        reason_class="owner_departure",
    )
    assert result["receipt_id"]
    rev = _revocation_payloads(tmp)[0]["x_revocation"]
    assert len(rev["revoked_ids"]) == 4
    assert set(rev["revoked_hashes"]) == set(rev["revoked_ids"])
    assert rev["reason_class"] == "owner_departure"
    for key, _kindname in (("root0", "root"), ("child0", "child")):
        assert rev["revoked_hashes"][tokens[key].token_id] == _token_hash(tokens[key])
    assert _verify(gw, tmp).valid


def test_admin_route_passes_kind_and_reason_class(tmp_path):
    """The admin-plane request model carries the v1.2 kind request."""
    gw, client, tokens, tmp = _setup(tmp_path)
    resp = client.post(
        "/api/revoke",
        json={
            "token_id": tokens["child0"].token_id,
            "reason": "suspected compromise",
            "kind": "capability",
            "reason_class": "compromise",
        },
        headers={"Authorization": "Bearer k"},
    )
    assert resp.status_code == 200, resp.text
    rev = _revocation_payloads(tmp)[0]["x_revocation"]
    assert rev["version"] == "revocation/v1"
    assert rev["reason_class"] == "compromise"


# ---------------------------------------------------------------------------
# Verifier: the v1.2 structural rules (forged blocks, claim-then-verify)
# ---------------------------------------------------------------------------


def test_valid_v12_revocation_verifies(tmp_path):
    gw, tmp = _emitter_only(tmp_path)
    _emit_revocation(
        gw,
        _v12_block(["tok-1"], {"tok-1": "sha256:" + "ab" * 32}, root="tok-1"),
    )
    report = _verify(gw, tmp)
    assert report.valid, report.errors


def test_unknown_version_refuses_never_ignores(tmp_path):
    gw, tmp = _emitter_only(tmp_path)
    _emit_revocation(
        gw,
        _v12_block(["tok-1"], {"tok-1": "sha256:" + "ab" * 32}, version="revocation/v2"),
    )
    report = _verify(gw, tmp)
    assert not report.valid
    assert any("x_revocation" in e and "revocation/v2" in e for e in report.errors), report.errors


@pytest.mark.parametrize("kind", ["token", "session", ""])
def test_unknown_kind_fails_verification(tmp_path, kind):
    gw, tmp = _emitter_only(tmp_path)
    _emit_revocation(gw, _v12_block(["tok-1"], {"tok-1": "sha256:" + "ab" * 32}, kind=kind))
    report = _verify(gw, tmp)
    assert not report.valid
    assert any("kind" in e for e in report.errors), report.errors


@pytest.mark.parametrize("reason_class", ["misclick", "urgent", ""])
def test_unknown_reason_class_fails_verification(tmp_path, reason_class):
    gw, tmp = _emitter_only(tmp_path)
    _emit_revocation(
        gw, _v12_block(["tok-1"], {"tok-1": "sha256:" + "ab" * 32}, reason_class=reason_class)
    )
    report = _verify(gw, tmp)
    assert not report.valid
    assert any("reason_class" in e for e in report.errors), report.errors


def test_revoked_hashes_keys_must_equal_ids(tmp_path):
    gw, tmp = _emitter_only(tmp_path)
    _emit_revocation(
        gw,
        _v12_block(["tok-1", "tok-2"], {"tok-1": "sha256:" + "ab" * 32}, root="tok-1"),
    )
    report = _verify(gw, tmp)
    assert not report.valid
    assert any("revoked_hashes" in e for e in report.errors), report.errors


def test_revoked_at_after_iat_fails(tmp_path):
    """A post-dated revocation timestamp is editorial, not evidence."""
    gw, tmp = _emitter_only(tmp_path)
    import time

    _emit_revocation(
        gw,
        _v12_block(["tok-1"], {"tok-1": "sha256:" + "ab" * 32}, revoked_at=int(time.time()) + 60),
    )
    report = _verify(gw, tmp)
    assert not report.valid
    assert any("revoked_at" in e for e in report.errors), report.errors


def test_missing_mandatory_field_fails(tmp_path):
    gw, tmp = _emitter_only(tmp_path)
    _emit_revocation(
        gw,
        _v12_block(["tok-1"], {"tok-1": "sha256:" + "ab" * 32}, reason_class=None),
    )
    report = _verify(gw, tmp)
    assert not report.valid
    assert any("reason_class" in e for e in report.errors), report.errors


def test_receipt_kind_ghost_citation_fails(tmp_path):
    """kind = receipt: every cited receipt hash must exist in the
    chain (the same membership rule every extension citation obeys)."""
    gw, tmp = _emitter_only(tmp_path)
    ghost = "sha256:" + "cd" * 32
    _emit_revocation(gw, _v12_block([ghost], {ghost: ghost}, kind="receipt"))
    report = _verify(gw, tmp)
    assert not report.valid
    assert any("cites receipt" in e or "not in the chain" in e for e in report.errors), (
        report.errors
    )


def test_receipt_kind_valid_citation_verifies(tmp_path):
    gw, tmp = _emitter_only(tmp_path)
    from raucle.gateway import GateReceiptContext

    cited = gw._emit_gate_receipt(
        GateReceiptContext(
            decision="deny",
            reason="no policy",
            tool="lookup_balance",
            agent_id="agent:svc",
            args={"account": "ACC-001"},
            policy=None,
            latency_us=100,
            source="agent:svc",
            destination="lookup_balance",
            trace_id="trace-1",
        )
    )
    _emit_revocation(gw, _v12_block([cited], {cited: cited}, kind="receipt"))
    report = _verify(gw, tmp)
    assert report.valid, report.errors


def test_digest_shape_enforced(tmp_path):
    gw, tmp = _emitter_only(tmp_path)
    _emit_revocation(gw, _v12_block(["tok-1"], {"tok-1": "sha256:deadbeef"}))
    report = _verify(gw, tmp)
    assert not report.valid
    assert any("revoked_hashes" in e and "sha256" in e for e in report.errors)


def test_forbidden_field_in_revocation_fails(tmp_path):
    """Bounded disclosure: no content-like field may appear in a signed
    revocation block, so a leaky emitter cannot hide revoked material
    inside the evidence."""
    gw, tmp = _emitter_only(tmp_path)
    _emit_revocation(
        gw,
        _v12_block(["tok-1"], {"tok-1": "sha256:" + "ab" * 32}, token="tok-1-secret-bytes"),
    )
    report = _verify(gw, tmp)
    assert not report.valid
    assert any("content-like" in e for e in report.errors), report.errors


def test_reason_quoting_constraint_value_fails(tmp_path):
    """A revocation receipt is retained for the life of the archive:
    the reason must stay at class level and must not quote constraint
    values the chain's receipts carry."""
    gw, tmp = _emitter_only(tmp_path)
    from raucle.gateway import GateReceiptContext

    intent = {
        "statement": "Look up the account balance",
        "tools": ["lookup_balance"],
        "constraints": {"allowed_values": {"account": ["ACC-001"]}},
    }
    gw._emit_gate_receipt(
        GateReceiptContext(
            decision="allow",
            reason="ok",
            tool="lookup_balance",
            agent_id="agent:svc",
            args={"account": "ACC-001"},
            policy=None,
            latency_us=100,
            source="agent:svc",
            destination="lookup_balance",
            trace_id="trace-1",
            intent_block={
                "intent": intent,
                "intent_check": {
                    "tool": "lookup_balance",
                    "satisfied_fields": {"account": "ACC-001"},
                },
            },
        )
    )
    _emit_revocation(
        gw,
        _v12_block(
            ["tok-1"],
            {"tok-1": "sha256:" + "ab" * 32},
            reason="account ACC-001 was over-scoped",
        ),
    )
    report = _verify(gw, tmp)
    assert not report.valid
    assert any("bounded disclosure" in e for e in report.errors), report.errors


def test_reason_at_class_level_verifies(tmp_path):
    gw, tmp = _emitter_only(tmp_path)
    _emit_revocation(
        gw,
        _v12_block(
            ["tok-1"],
            {"tok-1": "sha256:" + "ab" * 32},
            reason="authority was wider than intended",
        ),
    )
    report = _verify(gw, tmp)
    assert report.valid, report.errors


def test_v10_shape_stays_valid(tmp_path):
    """The shipped v1.0 block keeps the shipped semantics: no version
    field, no v1.2 checks, chain valid (rule 4: revocations minted
    before this document are valid and stay valid)."""
    gw, tmp = _emitter_only(tmp_path)
    _emit_revocation(
        gw,
        {"revoked_ids": ["tok-1"], "root": "tok-1", "actor": "admin", "reason": "test"},
    )
    report = _verify(gw, tmp)
    assert report.valid, report.errors


# ---------------------------------------------------------------------------
# Effect: the shipped 30 Oct verifier behaviour extends to the v1.2 kind
# ---------------------------------------------------------------------------


def test_post_revocation_citations_invalid_under_v12(tmp_path):
    """Receipts minted after the v1.2 revocation line that cite the
    revoked authority are invalid with a named error; receipts before
    the line stay valid (revocation is not retroactive)."""
    gw, client, tokens, tmp = _setup(tmp_path)
    # 1: a legitimate allow under the child (pre-revocation)
    assert _gate(client, tokens["child0"]).json()["decision"] == "allow"
    # 2: the v1.2 revocation
    gw.revoke_capability(
        tokens["child0"].token_id,
        reason="test",
        actor="admin",
        kind="capability",
        reason_class="compromise",
    )
    # 3: a forged allow citing the revoked child (bypasses the gate)
    from raucle.gateway import GateReceiptContext
    from raucle.provenance import authorization_block

    gw._emit_gate_receipt(
        GateReceiptContext(
            decision="allow",
            reason="ok",
            tool="lookup_balance",
            agent_id="agent:svc",
            args={"account": "ACC-001"},
            policy=None,
            latency_us=100,
            source="agent:svc",
            destination="lookup_balance",
            trace_id="t-forged",
            authorization=authorization_block(tokens["child0"].to_dict()),
        )
    )
    report = _verify(gw, tmp)
    assert not report.valid
    assert any("revoked" in e for e in report.errors), report.errors


def test_revocation_isolated_between_chains(tmp_path):
    """Org isolation: revoking one chain's subtree never marks receipts
    citing another chain's live authority invalid."""
    gw, client, tokens, tmp = _setup(tmp_path, chains=2)
    # both chains exercised
    assert _gate(client, tokens["child0"], account="ACC-001").json()["decision"] == "allow"
    assert _gate(client, tokens["child1"], account="ACC-002").json()["decision"] == "allow"
    # revoke chain 0 only
    gw.revoke_capability(
        tokens["child0"].token_id,
        reason="test",
        actor="admin",
        kind="capability",
        reason_class="compromise",
    )
    # a receipt citing chain 1's live child minted after the line stays valid
    from raucle.gateway import GateReceiptContext
    from raucle.provenance import authorization_block

    gw._emit_gate_receipt(
        GateReceiptContext(
            decision="allow",
            reason="ok",
            tool="lookup_balance",
            agent_id="agent:svc",
            args={"account": "ACC-002"},
            policy=None,
            latency_us=100,
            source="agent:svc",
            destination="lookup_balance",
            trace_id="t-other-chain",
            authorization=authorization_block(tokens["child1"].to_dict()),
        )
    )
    report = _verify(gw, tmp)
    assert report.valid, report.errors
    # and the gate still serves chain 1
    assert _gate(client, tokens["child1"], account="ACC-002").json()["decision"] == "allow"
