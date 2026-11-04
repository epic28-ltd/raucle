"""Chain graph resolver tests (P1.1a).

Coverage:
- complete resolution of every receipt in a dogfood corpus
- depth/breadth truncation with explicit markers
- unknown/unresolvable links as explicit states (never inferred)
- deep delegation chains
- revoked / historical receipts (verification at event time)
- phase-5 policy_deployed binding: the policy node appears by digest
- HTTP GET /api/chains/{receipt_hash}: auth, 404, bounded work
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raucle.chain_graph import resolve_chain_graph, resolve_chain_graph_for_gateway
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app

POLICY = """
version: 1
issuer: bank
"""


@pytest.fixture()
def gw(tmp_path: Path) -> RaucleGateway:
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        emit_receipts=True,
    )
    return RaucleGateway(config)


def _emit(gateway: RaucleGateway, **overrides: object) -> str:
    """Emit a real signed gate-shaped receipt through the gateway core."""
    payload: dict[str, object] = {
        "iss": "raucle-gateway",
        "typ": "provenance-receipt/v1",
        "iat": 1_700_000_000,
        "agent_id": "agent:gate",
        "agent_key_id": gateway._gate_identity.key_id,  # noqa: SLF001
        "operation": "guardrail_scan",
        "parents": [],
        "taint": ["gate:observed"],
        "input_hash": "a" * 64,
        "ruleset_hash": "b" * 64,
        "guardrail_verdict": "allow",
        "x_gate": {"decision": "allow", "reason": "ok", "tool": "http.request"},
        **overrides,
    }
    receipt_hash = gateway._sign_and_store_receipt(payload)  # noqa: SLF001
    assert receipt_hash
    return receipt_hash


def _load_records(
    gateway: RaucleGateway,
) -> list[dict[str, object]]:
    path = Path(gateway.config.receipt_store)
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _keys(gateway: RaucleGateway) -> dict[str, str]:
    return {
        str(gateway._gate_identity.key_id): gateway._gate_identity.public_key_pem().decode(  # noqa: SLF001
            "ascii"
        )
    }


def _node_map(graph: dict) -> dict[str, dict]:
    return {node["id"]: node for node in graph["nodes"]}


def _edge_set(graph: dict, kind: str) -> set[tuple[str, str]]:
    return {(e["from"], e["to"]) for e in graph["edges"] if e["kind"] == kind}


class TestCompleteCorpusResolution:
    def test_every_receipt_resolves_completely(self, gw: RaucleGateway) -> None:
        r0 = _emit(gw, iat=1_700_000_000)
        r1 = _emit(gw, iat=1_700_000_001, parents=[r0])
        r2 = _emit(gw, iat=1_700_000_002, parents=[r1])
        r3 = _emit(gw, iat=1_700_000_003, parents=[r0, r2])
        records = _load_records(gw)
        keys = _keys(gw)
        for target in (r0, r1, r2, r3):
            graph = resolve_chain_graph(target, records, public_keys=keys)
            node_ids = set(_node_map(graph))
            assert target in node_ids
            # Complete: every cited parent in the corpus resolves as a
            # node, every parent edge is marked found, nothing unknown,
            # nothing truncated.
            for node in graph["nodes"]:
                for parent in node.get("parents", []):
                    assert parent in node_ids
                    assert graph["truncated"] is False
            assert all(e.get("found") for e in graph["edges"] if e["kind"] == "parent")
            assert graph["unknown"] == []
            assert graph["pruned"] == []
            assert graph["truncated"] is False

    def test_deterministic_output(self, gw: RaucleGateway) -> None:
        r0 = _emit(gw)
        r1 = _emit(gw, parents=[r0])
        for _ in range(2):
            assert resolve_chain_graph(
                r1, _load_records(gw), public_keys=_keys(gw)
            ) == resolve_chain_graph(r1, _load_records(gw), public_keys=_keys(gw))


class TestSignatureStates:
    def test_verified_with_key(self, gw: RaucleGateway) -> None:
        r0 = _emit(gw)
        graph = resolve_chain_graph(r0, _load_records(gw), public_keys=_keys(gw))
        node = _node_map(graph)[r0]
        assert node["signature"]["status"] == "verified"
        assert node["signature"]["key_id"] == str(gw._gate_identity.key_id)  # noqa: SLF001

    def test_key_absent_is_a_node_state_not_a_failure(self, gw: RaucleGateway) -> None:
        """Historical receipt: the key is rotated away; the graph stays
        COMPLETE and states the status honestly (verification at event
        time is the receipt's own iat + recorded status)."""
        _emit(gw)
        records = _load_records(gw)
        target = records[0]["receipt_hash"]
        graph = resolve_chain_graph(target, records, public_keys=None)
        node = _node_map(graph)[str(target)]
        assert node["signature"]["status"] == "key_absent"
        assert graph["truncated"] is False
        # The iat is still the recorded decision time.
        assert node["iat"] == 1_700_000_000

    def test_invalid_signature_is_explicit(self, gw: RaucleGateway) -> None:
        r0 = _emit(gw)
        # Tamper the signature of the second receipt and resolve IT: the
        # invalid state rides the node, never hidden.
        r1 = _emit(gw, parents=[r0])
        tampered = []
        for record in _load_records(gw):
            record = dict(record)
            if record["receipt_hash"] == r1:
                head, payload, sig = str(record["jws"]).split(".")
                sig = sig[:-4] + ("BBBB" if sig[-4:] != "BBBB" else "CCCC")
                record["jws"] = f"{head}.{payload}.{sig}"
            tampered.append(record)
        graph = resolve_chain_graph(r1, tampered, public_keys=_keys(gw))
        node = _node_map(graph)[r1]
        assert node["signature"]["status"] == "invalid"


class TestTruncation:
    def test_depth_truncated_explicitly(self, gw: RaucleGateway) -> None:
        r0 = _emit(gw)
        r1 = _emit(gw, parents=[r0])
        _emit(gw, parents=[r1])
        graph = resolve_chain_graph(
            _load_records(gw)[-1]["receipt_hash"], _load_records(gw), depth=1
        )
        assert graph["truncated"] is True
        assert any(p["reason"] == "depth_limit_exceeded" for p in graph["pruned"])
        ids = set(_node_map(graph))
        # depth 1 resolves the root and its parents (hop 1); everything
        # beyond hops into pruned.
        newest = str(_load_records(gw)[-1]["receipt_hash"])
        assert newest in ids
        assert any(
            p["reference"] == r0 and p["reason"] == "depth_limit_exceeded" for p in graph["pruned"]
        )

    def test_breadth_truncated_explicitly(self, gw: RaucleGateway) -> None:
        r0 = _emit(gw)
        _emit(gw, parents=[r0])
        records = _load_records(gw)
        root = str(records[-1]["receipt_hash"])
        graph = resolve_chain_graph(root, records, breadth=1)
        assert graph["truncated"] is True
        assert any(p["reason"] == "breadth_limit_exceeded" for p in graph["pruned"])

    def test_caps_are_bounded(self, gw: RaucleGateway) -> None:
        r0 = _emit(gw)
        graph = resolve_chain_graph(r0, _load_records(gw), depth=999, breadth=2000)
        assert graph["depth_limit"] == 20
        assert graph["breadth_limit"] == 1000


class TestUnknownStates:
    def test_unresolvable_parent_link_is_explicit(self, gw: RaucleGateway) -> None:
        r0 = _emit(gw, parents=["sha256:" + "f" * 64])
        graph = resolve_chain_graph(r0, _load_records(gw), public_keys=_keys(gw))
        assert _node_map(graph)[r0]["parents"] == ["sha256:" + "f" * 64]
        edge = _edge_set(graph, "parent")
        assert (r0, "sha256:" + "f" * 64) in edge
        parent_edge = [e for e in graph["edges"] if e["kind"] == "parent"][0]
        assert parent_edge["found"] is False
        assert graph["unknown"] == [
            {"kind": "receipt", "reference": "sha256:" + "f" * 64, "reason": "not_found"}
        ]
        assert graph["truncated"] is False

    def test_unknown_root(self, gw: RaucleGateway) -> None:
        graph = resolve_chain_graph("sha256:" + "0" * 64, [])
        assert graph["root"]["state"] == "unknown"
        assert graph["unknown"][0]["reference"] == "sha256:" + "0" * 64


class TestDelegationChain:
    def _ledger_record(
        self, token_id: str, parent_id: str | None, issuer: str = "issuer:bank"
    ) -> dict:
        return {
            "record_hash": "sha256:" + ("d" + token_id[-7:]).ljust(64, "0"),
            "delegated_to_agent": "agent:child-" + token_id[-7:],
            "capability": {
                "token_id": token_id,
                "issuer": issuer,
                "key_id": "k" + token_id[-7:],
                "parent_id": parent_id,
                "nbf": 1_700_000_000,
                "iat": 1_700_000_000,
                "exp": 1_700_000_600,
                "constraints": {"allow": {"account": ["ACC-1"]}},
            },
        }

    def test_deep_delegation_chain_resolved(self, gw: RaucleGateway) -> None:
        ledger = [
            self._ledger_record("tok-1", None),
            self._ledger_record("tok-2", "tok-1"),
            self._ledger_record("tok-3", "tok-2"),
        ]
        auth = {
            "capability_id": "tok-3",
            "parent_id": "tok-2",
            "issuer": "issuer:bank",
            "attenuated": True,
            "chain_digest": "sha256:" + "c" * 64,
        }
        r0 = _emit(gw, x_gate={"decision": "allow", "tool": "t", "authorization": auth})
        graph = resolve_chain_graph(
            r0,
            _load_records(gw),
            delegation_records=ledger,
            depth=5,
        )
        ids = set(_node_map(graph))
        assert {"delegation:tok-1", "delegation:tok-2", "delegation:tok-3"} <= ids
        parents = _edge_set(graph, "delegation_parent")
        assert ("delegation:tok-3", "delegation:tok-2") in parents
        assert ("delegation:tok-2", "delegation:tok-1") in parents
        assert ("delegation:tok-1", "delegation:tok-1") not in parents
        assert _node_map(graph)["delegation:tok-1"]["parent_token_id"] is None
        assert graph["unknown"] == []

    def test_unresolvable_delegation_hop_is_explicit(self, gw: RaucleGateway) -> None:
        auth = {
            "capability_id": "tok-ghost",
            "parent_id": None,
            "issuer": "issuer:bank",
            "attenuated": False,
            "chain_digest": "sha256:" + "c" * 64,
        }
        r0 = _emit(gw, x_gate={"decision": "allow", "tool": "t", "authorization": auth})
        graph = resolve_chain_graph(r0, _load_records(gw), delegation_records=[])
        assert any(
            u == {"kind": "delegation", "reference": "tok-ghost", "reason": "not_found"}
            for u in graph["unknown"]
        )


class TestLeaseAndRevocation:
    def test_lease_grant_and_revocation_inline(self, gw: RaucleGateway) -> None:
        lease = {"lease_id": "lease-7", "action": "granted", "ttl": 120, "scopes": {"read": 1}}
        with_lease = _emit(gw, iat=1_700_000_100, x_lease=lease)
        revoke = _emit(
            gw,
            iat=1_700_000_200,
            x_revocation={"revoked_ids": ["tok-3"], "reason": "operator kill switch"},
        )
        records = _load_records(gw)
        lease_node = _node_map(resolve_chain_graph(with_lease, records))[with_lease]
        assert lease_node["events"] == [
            {
                "type": "lease_grant",
                "lease_id": "lease-7",
                "iat": 1_700_000_100,
                "ttl": 120,
                "scopes": {"read": 1},
                "source": "x_lease",
            }
        ]
        revoke_node = _node_map(resolve_chain_graph(revoke, records))[revoke]
        assert revoke_node["events"][0]["type"] == "revocation"
        assert revoke_node["events"][0]["revoked_ids"] == ["tok-3"]
        assert revoke_node["events"][0]["iat"] == 1_700_000_200


class TestPolicyBinding:
    def test_phase5_deployment_binds_policy_node(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A receipt whose policy came through the phase-5 intake gets a
        policy node bound BY DIGEST to the policy_deployed chain event."""
        from tests.test_deployment_intake import PortalKey, _accept_body, _client

        portal = PortalKey()
        keyfile = tmp_path / "portal-public.pem"
        keyfile.write_bytes(portal.public_pem)
        policy_path = tmp_path / "live-policies.yaml"
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file=str(policy_path),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
            deployment_trust={
                "issuer": "raucle-portal",
                "key_path": str(keyfile),
                "policy_target": str(policy_path),
                "nonce_cache": str(tmp_path / "deploy-nonces.json"),
            },
        )
        gateway = RaucleGateway(config)
        jws, _ = portal.jws()
        resp = _client(gateway).post("/api/deployments/accept", json=_accept_body(jws))
        assert resp.status_code == 200, resp.text
        gate_receipt_hash = str(resp.json()["gate_receipt_hash"])
        policy_digest = str(resp.json()["policy_digest"])

        from raucle.chain_graph import load_audit_events  # noqa: F401

        graph = resolve_chain_graph_for_gateway(gateway, gate_receipt_hash)
        policy_nodes = [n for n in graph["nodes"] if n["kind"] == "policy"]
        assert len(policy_nodes) == 1
        policy_node = policy_nodes[0]
        assert policy_node["binding_state"] == "deployment_bound"
        assert len(policy_node["deployments"]) == 1
        assert policy_node["deployments"][0]["policy_digest"] == policy_digest
        audit_node = _node_map(graph)["audit:" + policy_node["deployments"][0]["receipt_hash"]]
        assert audit_node["kind"] == "audit_event"
        assert audit_node["type"] == "policy_deployed"

    def test_plain_gate_receipt_policy_digest_only(self, gw: RaucleGateway) -> None:
        r0 = _emit(gw)
        graph = resolve_chain_graph(r0, _load_records(gw), public_keys=_keys(gw))
        policy_nodes = [n for n in graph["nodes"] if n["kind"] == "policy"]
        assert len(policy_nodes) == 1
        assert policy_nodes[0]["binding_state"] == "receipt_rule_digest_only"
        assert policy_nodes[0]["deployments"] == []


class TestGatewayResolution:
    def test_resolve_chain_graph_for_gateway(self, gw: RaucleGateway) -> None:
        r0 = _emit(gw)
        r1 = _emit(gw, parents=[r0])
        graph = resolve_chain_graph_for_gateway(gateway=gw, receipt_hash=r1)
        assert _node_map(graph)[r1]["signature"]["status"] == "verified"
        assert _node_map(graph)[r0]["signature"]["status"] == "verified"
        assert _edge_set(graph, "parent") == {(r1, r0)}


class TestChainGraphHTTP:
    @pytest.fixture()
    def admin(self, gw: RaucleGateway) -> TestClient:
        users = UserManager()
        users.add_user("admin-key", "admin", "Admin")
        return TestClient(create_admin_app(gw, users))

    def test_chain_endpoint_authed(self, admin: TestClient, gw: RaucleGateway) -> None:
        r0 = _emit(gw)
        r1 = _emit(gw, parents=[r0])
        resp = admin.get("/api/chains/" + r1, headers={"Authorization": "Bearer admin-key"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["root"] == r1
        receipt_nodes = [n for n in body["nodes"] if n["kind"] == "receipt"]
        assert len(receipt_nodes) == 2

    def test_chain_endpoint_requires_auth(self, admin: TestClient) -> None:
        assert admin.get("/api/chains/whatever").status_code == 401

    def test_chain_endpoint_unknown_is_404(self, admin: TestClient) -> None:
        resp = admin.get(
            "/api/chains/sha256:" + "0" * 64,
            headers={"Authorization": "Bearer admin-key"},
        )
        assert resp.status_code == 404

    def test_chain_endpoint_bounded_work(self, admin: TestClient, gw: RaucleGateway) -> None:
        r0 = _emit(gw)
        r1 = _emit(gw, parents=[r0])
        resp = admin.get(
            "/api/chains/" + r1,
            params={"depth": 999, "breadth": 999},
            headers={"Authorization": "Bearer admin-key"},
        )
        assert resp.status_code == 200
        assert resp.json()["depth_limit"] == 20
        assert 1 <= int(resp.json()["breadth_limit"]) <= 1000
