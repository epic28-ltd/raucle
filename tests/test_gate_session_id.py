"""Gate session_id tests (EPIC Q lane Q-1): session continuity plumbing.

The optional ``session_id`` on a gate request binds the decision to a
cross-window behavioural session key WITHOUT fabricating continuity: when
absent, no session_id is recorded anywhere (the receipt byte-shape is
exactly today's) and no trace_id fallback is applied. Verification never
consults the index; the index (schema v3) just accelerates (session_id,
iat) queries.
"""

import base64
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import ProvenanceVerifier
from raucle.receipt_index import ReceiptIndex

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
"""


@pytest.fixture
def config(tmp_path):
    return GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        receipt_store_dir=str(tmp_path / "segments"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        emit_receipts=True,
    )


@pytest.fixture
def gw(config, tmp_path):
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    config.policy_file = str(policy)
    return RaucleGateway(config)


@pytest.fixture
def client(gw):
    return TestClient(create_gateway_app(gw))


def _receipt_envelope(gw, receipt_hash):
    """Fetch the stored receipt envelope for *receipt_hash* from the
    segmented store (find_by_hash), returning its decoded JWS payload."""
    rec = gw._receipt_store.find_by_hash(receipt_hash)
    assert rec is not None, f"receipt {receipt_hash} not in store"
    b = rec["jws"].split(".")[1]
    return json.loads(base64.urlsafe_b64decode(b + "=" * ((4 - len(b) % 4) % 4)))


class TestGateSessionId:
    def test_valid_session_id_binds_receipt(self, gw, client):
        """(a) A gate call carrying a valid session_id produces a signed
        x_gate receipt whose payload carries x_gate.session_id verbatim."""
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
                "session_id": "run-abc-123",
            },
        )
        body = resp.json()
        assert body["decision"] == "allow", body
        payload = _receipt_envelope(gw, body["receipt_id"])
        assert payload["x_gate"]["session_id"] == "run-abc-123"
        # the receipt still verifies offline like any other gate receipt
        verifier = ProvenanceVerifier(
            public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
        )
        for seg in gw._receipt_store.segments():  # the chain lives in segments
            report = verifier.verify_chain(str(seg))
            assert report.valid, report.errors

    def test_session_id_indexed_and_queryable(self, gw, client, tmp_path):
        """(b) A fresh schema-v3 index projects the receipt and returns it
        via the (session_id, iat) query path, with acting_for captured."""
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
                "acting_for": "alice@example.test",
                "session_id": "run-abc-123",
            },
        )
        assert resp.json()["decision"] == "allow"
        # a fresh index rebuilt FROM THE CHAIN answers the session query
        index = ReceiptIndex(sqlite_path=tmp_path / "index.fresh.sqlite")
        count = index.rebuild_from_store(gw._receipt_store)
        assert count == 1
        rows = index.query(session_id="run-abc-123")
        assert len(rows) == 1
        assert rows[0]["acting_for"] == "alice@example.test"
        assert rows[0]["tool"] == "lookup_balance"
        # an indexed live path too: the gateway fed its own index
        assert gw._receipt_index is not None
        live = gw._receipt_index.query(session_id="run-abc-123")
        assert len(live) == 1
        assert live[0]["session_id"] == "run-abc-123"

    def test_absent_session_id_recorded_nowhere(self, gw, client):
        """(c) A session-free call produces today's receipt shape: no
        session_id key in x_gate, no trace_id-based fallback anywhere."""
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
        )
        body = resp.json()
        assert body["decision"] == "allow"
        payload = _receipt_envelope(gw, body["receipt_id"])
        assert "session_id" not in payload["x_gate"]

    def test_invalid_session_id_fails_closed(self, client):
        """Bounded-identifier discipline: bad charset or length is rejected,
        fail-closed, before any policy evaluation."""
        for bad in ("<script>", "a" * 200, "has space"):
            resp = client.post(
                "/gate",
                json={
                    "tool": "lookup_balance",
                    "args": {"account": "ACC-001"},
                    "agent_id": "agent:svc",
                    "session_id": bad,
                },
            )
            assert resp.status_code in (400, 422), (bad, resp.status_code)


class TestSessionBindingRequired:
    """Q17 gate hardening (phase-3 review close 3): when session behavioural
    rules are CONFIGURED, the gate refuses requests that omit a session ID.

    A configured control cannot be silently disabled by the caller dropping
    the field. Choice pinned (read from the rule evaluation): the session
    key is caller-supplied and the bounded windows are keyed on it, so
    deriving the key server-side from agent identity + trace id would hand
    a fresh trace a fresh empty window and weaken exactly the rate
    semantics the rules enforce. The honest closure is refuse-with-name.
    Session values themselves stay caller-supplied until the server-issued
    workflow identity work (registered follow-up family).
    """

    SESSION_RULES_POLICY = (
        POLICY
        + """
session_rules:
  - id: ban-balance-read-chain
    kind: forbidden_tool_chain
    window_seconds: 60
    sequence: [lookup_balance]
"""
    )

    @pytest.fixture
    def rules_gw(self, tmp_path):
        """A gateway whose policy configures one session rule."""
        policy = tmp_path / "policies.yaml"
        policy.write_text(self.SESSION_RULES_POLICY)
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file=str(policy),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            receipt_store_dir=str(tmp_path / "segments"),
            receipt_index_path=str(tmp_path / "index.sqlite"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
        )
        return RaucleGateway(config)

    @pytest.fixture
    def rules_client(self, rules_gw):
        return TestClient(create_gateway_app(rules_gw))

    def test_rules_configured_session_omitted_refuses_named(self, rules_client):
        """(a) Session rules configured + no session ID = the named
        session_binding_required refusal (a configured control cannot be
        silently disabled by the caller's omission)."""
        resp = rules_client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["decision"] == "deny", body
        assert "session_binding_required" in body["reason"]

    def test_rules_configured_session_supplied_evaluates_as_today(self, rules_client):
        """(b) Rules configured + session supplied: rule evaluation is
        unchanged - the configured forbidden chain fires on the balance
        read by its own rule id, not by the binding refusal."""
        resp = rules_client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
                "session_id": "run-1",
            },
        )
        body = resp.json()
        assert body["decision"] == "deny", body
        assert "ban-balance-read-chain" in body["reason"]
        assert "session_binding_required" not in body["reason"]

    def test_no_rules_configured_session_omitted_unchanged(self, client):
        """(c) Zero regression for unconfigured deployments: no session
        rules configured + no session ID is exactly today's behaviour (the
        call evaluates and allows; no refusal is minted)."""
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
        )
        body = resp.json()
        assert body["decision"] == "allow", body
        assert "session_binding_required" not in body["reason"]

    def test_malformed_rules_block_session_free_calls_unchanged(self, tmp_path):
        """A session_rules block that fails to parse produces NO rules: the
        binding requirement keys on rules existing and parsing, so
        session-free calls keep today's shape - while session-bearing calls
        still deny fail-closed on the config error, as before the close."""
        policy = tmp_path / "policies.yaml"
        policy.write_text(
            POLICY
            + """
session_rules:
  - 42
"""
        )
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file=str(policy),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            receipt_store_dir=str(tmp_path / "segments"),
            receipt_index_path=str(tmp_path / "index.sqlite"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
        )
        client = TestClient(create_gateway_app(RaucleGateway(config)))
        free = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
        ).json()
        assert free["decision"] == "allow", free
        assert "session_binding_required" not in free["reason"]
        # the fail-closed leg of the malformed config is unchanged
        sessioned = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
                "session_id": "run-1",
            },
        ).json()
        assert sessioned["decision"] == "deny", sessioned
        assert "session rule config malformed" in sessioned["reason"]


class TestReceiptIndexV3:
    def test_schema_version_is_three(self):
        assert ReceiptIndex.SCHEMA_VERSION == 3

    def test_v2_file_rebuilds_to_v3(self, tmp_path):
        """A v2 index file (existing fixture shape) opens, keeps its rows
        and is upgraded in place to user_version 3 without error."""
        path = tmp_path / "v2.sqlite"
        conn = sqlite3.connect(str(path))
        conn.execute(
            """
            CREATE TABLE receipts (
                receipt_hash TEXT NOT NULL, iat INTEGER NOT NULL,
                agent_id TEXT NOT NULL, tool TEXT NOT NULL,
                decision TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
                policy TEXT, latency_us INTEGER NOT NULL DEFAULT 0,
                trace_id TEXT, source TEXT NOT NULL DEFAULT '',
                destination TEXT NOT NULL DEFAULT '',
                parents_json TEXT NOT NULL DEFAULT '[]',
                segment TEXT, line_no INTEGER
            )
            """
        )
        conn.execute(
            "INSERT INTO receipts (receipt_hash, iat, agent_id, tool, decision)"
            " VALUES ('sha256:legacy', 1758000000, 'agent:svc', 't', 'allow')"
        )
        conn.execute("PRAGMA user_version = 2")
        conn.commit()
        conn.close()

        index = ReceiptIndex(sqlite_path=path)
        conn = sqlite3.connect(str(path))
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 3
        conn.close()
        rows = index.query()
        assert len(rows) == 1
        assert rows[0]["receipt_hash"] == "sha256:legacy"
        assert rows[0]["session_id"] is None  # no fabricated continuity

    def test_session_index_exists(self, tmp_path):
        """The composite (session_id, iat) index exists for Q3 queries."""
        index = ReceiptIndex(sqlite_path=tmp_path / "ix.sqlite")
        conn = sqlite3.connect(str(index._path))  # noqa: SLF001
        names = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'").fetchall()
        }
        conn.close()
        assert "idx_receipts_session" in names
