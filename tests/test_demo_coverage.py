"""Demo coverage surface: the receipted-share metric contract, read-only.

Covers:
- the aggregate plane over the REAL gate receipt stream (receipts minted by
  driving gateway.check_tool_call, the public path the HTTP gate and the
  framework wrappers share): exact bucket numbers, the partition invariant,
  rollup cohesion, the unavailable-not-zero contract, determinism
  (byte identity incl. shuffled input order),
- bounded disclosure: denial-reason values, reason keys and receipt hashes
  never enter the response; aggregates only,
- the receipt-side-only discipline: a receipt minted without a bound trace
  id (the check_tool_call API allows an empty trace_id) never inflates the
  action number and stays disclosed under its explicit label,
- the endpoint family on the admin app: 200 in demo mode against the flat
  chain, the index projection and the segmented store, 404 with demo mode
  off, 401 without credentials, GET-only, endpoint-to-builder equality,
  determinism, malformed-chain-line tolerance,
- the panel: nav item in the Assurance stack after Key model, the
  demo-only card in the receipts tab, the loadDemoCoverage loader
  (textContent-only), the receipts dispatch wiring and the __HI
  delegation entry.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raucle import demo_coverage as demo_coverage_mod
from raucle.demo_coverage import aggregate_coverage, build_demo_coverage
from raucle.demo_ops import SIMULATED_LABEL
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import ADMIN_PANEL_HTML, create_admin_app

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
  - tool: ledger_write
    agent_id: agent:aud
    ttl_seconds: 60
"""


def _policy_file(tmp_path) -> str:
    path = tmp_path / "policies.yaml"
    path.write_text(POLICY, encoding="utf-8")
    return str(path)


def _gateway(tmp_path, **overrides) -> RaucleGateway:
    config = GatewayConfig(
        policy_file=_policy_file(tmp_path),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="admin-key-0123456789",
        signer_backend="local",
        **overrides,
    )
    return RaucleGateway(config)


def _users() -> UserManager:
    users = UserManager()
    users.add_user("admin-key-0123456789", "admin", "Admin")
    users.add_user("demo-key-sim", "auditor", "Demo (read-only)")
    return users


def mint_demo_receipts(gateway: RaucleGateway) -> None:
    """Drive the REAL gate: two agents, two tools, one attributable deny.

    The deny quotes a constraint value (ACC-777) — the bounded-disclosure
    test asserts that value never leaves the receipt layer's own plane.
    """
    gateway.check_tool_call(
        "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-allow-1"
    )
    gateway.check_tool_call(
        "lookup_balance", {"account": "ACC-777"}, agent_id="agent:svc", trace_id="t-deny-1"
    )
    gateway.check_tool_call(
        "ledger_write", {"amount": 10}, agent_id="agent:aud", trace_id="t-allow-2"
    )


@pytest.fixture
def flat_stack(tmp_path, monkeypatch) -> tuple[TestClient, RaucleGateway]:
    """Demo mode on, receipts on the legacy flat chain (no index, no store)."""
    monkeypatch.setenv("RAUCLE_DEMO_MODE", "1")
    monkeypatch.setenv("RAUCLE_DEMO_KEY", "demo-key-sim")
    gateway = _gateway(tmp_path)
    mint_demo_receipts(gateway)
    return TestClient(create_admin_app(gateway, _users())), gateway


@pytest.fixture
def indexed_stack(tmp_path, monkeypatch) -> tuple[TestClient, RaucleGateway]:
    """Demo mode on, receipts through the segmented store with its index."""
    monkeypatch.setenv("RAUCLE_DEMO_MODE", "1")
    monkeypatch.setenv("RAUCLE_DEMO_KEY", "demo-key-sim")
    gateway = _gateway(tmp_path, receipt_store_dir=str(tmp_path / "store"))
    mint_demo_receipts(gateway)
    return TestClient(create_admin_app(gateway, _users())), gateway


@pytest.fixture
def store_only_stack(indexed_stack) -> tuple[TestClient, RaucleGateway]:
    """Force the segmented-store enumeration path (projection set aside)."""
    client, gateway = indexed_stack
    gateway._receipt_index = None
    return client, gateway


@pytest.fixture
def plain_stack(tmp_path, monkeypatch) -> tuple[TestClient, RaucleGateway]:
    """Admin app with demo mode off entirely, real receipts on the plane."""
    monkeypatch.delenv("RAUCLE_DEMO_MODE", raising=False)
    monkeypatch.delenv("RAUCLE_DEMO_KEY", raising=False)
    gateway = _gateway(tmp_path)
    mint_demo_receipts(gateway)
    return TestClient(create_admin_app(gateway, _users())), gateway


def _hand_row(
    trace_id: str | None, tool: str = "shell", agent: str = "agent-a", decision: str = "allow"
) -> dict:
    return {
        "agent_id": agent,
        "tool": tool,
        "decision": decision,
        "iat": 0,
        "trace_id": trace_id,
    }


# ---------------------------------------------------------------------------
# Aggregate plane: exact contract numbers
# ---------------------------------------------------------------------------


class TestDemoCoverageAggregate:
    def test_exact_numbers_over_the_real_receipt_stream(self, flat_stack):
        _client, gateway = flat_stack
        got = build_demo_coverage(gateway)
        assert got["schema_version"] == "raucle.demo.coverage/v1"
        assert got["metric"] == "receipted_share"
        assert got["breakdown"] == {
            "total": 3,
            "receipted": 3,
            "out_of_gate": 0,
            "pending": 0,
        }
        assert got["receipted_share"] == 1.0
        assert got["states"] == {"traced": 3}
        assert got["decisions"] == {"allow": 2, "deny": 1}
        assert got["by_tool"] == {
            "ledger_write": {
                "total": 1,
                "receipted": 1,
                "out_of_gate": 0,
                "pending": 0,
                "receipted_share": 1.0,
            },
            "lookup_balance": {
                "total": 2,
                "receipted": 2,
                "out_of_gate": 0,
                "pending": 0,
                "receipted_share": 1.0,
            },
        }
        assert got["by_agent"]["agent:aud"]["total"] == 1
        assert got["by_agent"]["agent:svc"]["receipted_share"] == 1.0
        assert got["vantage"] == "gate-side receipt plane (single-demo-org)"
        assert got["label"] == SIMULATED_LABEL
        assert "x_gate.trace_id" in got["basis"]
        assert got["window"]["rows_considered"] == 3
        assert got["window"]["truncated"] is False

    def test_partition_invariant_and_rollup_cohesion(self, flat_stack):
        _client, gateway = flat_stack
        got = build_demo_coverage(gateway)
        breakdown = got["breakdown"]
        assert breakdown["total"] == (
            breakdown["receipted"] + breakdown["out_of_gate"] + breakdown["pending"]
        )
        assert sum(r["total"] for r in got["by_tool"].values()) == breakdown["total"]
        assert sum(r["receipted"] for r in got["by_tool"].values()) == breakdown["receipted"]
        assert sum(r["total"] for r in got["by_agent"].values()) == breakdown["total"]
        assert sum(r["receipted"] for r in got["by_agent"].values()) == breakdown["receipted"]

    def test_buckets_carry_the_disclosed_vantage(self, flat_stack):
        _client, gateway = flat_stack
        got = build_demo_coverage(gateway)
        basis = {b["bucket"]: b["at_this_vantage"] for b in got["contract"]["buckets"]}
        assert "not computed" in basis["out_of_gate"]
        assert "not computed" in basis["pending"]
        assert "computed" in basis["receipted"]
        assert got["breakdown"]["out_of_gate"] == 0
        assert got["breakdown"]["pending"] == 0

    def test_flags_carry_semantics_and_no_computed_counts(self):
        got = aggregate_coverage([_hand_row("t1")])
        flags = {f["flag"]: f for f in got["contract"]["flags"]}
        assert set(flags) == {"bypass_candidates", "shadow_agents", "uninstrumented_tools"}
        for flag in flags.values():
            assert flag["computed_at_this_vantage"] is False
            assert "coverage/{org}" in flag["vantage_note"] or flag["vantage_note"]
            assert flag["semantics"]

    def test_untraced_receipt_never_inflates_the_action_number(self):
        got = aggregate_coverage([_hand_row(None)])
        assert got["breakdown"] == {"total": 0, "receipted": 0, "out_of_gate": 0, "pending": 0}
        assert got["receipted_share"] is None
        # the zero is disclosed, never folded away: both correlation states name themselves
        assert got["states"] == {"(trace id not recorded)": 1, "traced": 0}
        assert got["unavailable_note"], "an empty action plane is unavailable, never zero"

    def test_untraced_receipt_is_disclosed_alongside_a_traced_plane(self):
        got = aggregate_coverage([_hand_row("t1"), _hand_row(None, tool="file_write")])
        assert got["breakdown"] == {"total": 1, "receipted": 1, "out_of_gate": 0, "pending": 0}
        assert got["states"] == {"(trace id not recorded)": 1, "traced": 1}
        assert got["by_tool"] == {
            "shell": {
                "total": 1,
                "receipted": 1,
                "out_of_gate": 0,
                "pending": 0,
                "receipted_share": 1.0,
            }
        }
        assert got["receipted_share"] == 1.0

    def test_unattributed_tool_and_agent_get_explicit_unknown_labels(self):
        got = aggregate_coverage([_hand_row("t1", tool="", agent="")])
        assert got["breakdown"]["total"] == 1
        assert list(got["by_tool"]) == ["(tool not recorded)"]
        assert list(got["by_agent"]) == ["(agent not recorded)"]

    def test_unavailable_never_zero_on_the_empty_plane(self):
        got = aggregate_coverage([])
        assert got["receipted_share"] is None
        assert got["breakdown"] == {"total": 0, "receipted": 0, "out_of_gate": 0, "pending": 0}
        assert "unavailable" in got["unavailable_note"]
        assert "never zero" in got["unavailable_note"]
        assert got["by_tool"] == {}
        assert got["by_agent"] == {}

    def test_determinism_byte_identical_serialisation(self, flat_stack):
        _client, gateway = flat_stack
        one = json.dumps(build_demo_coverage(gateway), sort_keys=True)
        two = json.dumps(build_demo_coverage(gateway), sort_keys=True)
        assert one == two

    def test_determinism_holds_for_shuffled_input_order(self):
        rows = [
            _hand_row("t2", tool="tool-a", agent="agent-x", decision="deny"),
            _hand_row("t1", tool="tool-b", agent="agent-y"),
            _hand_row("t3", tool="tool-a", agent="agent-x"),
        ]
        forward = json.dumps(aggregate_coverage(rows), sort_keys=True)
        backward = json.dumps(aggregate_coverage(list(reversed(rows))), sort_keys=True)
        assert forward == backward

    def test_row_cap_truncation_is_disclosed(self, flat_stack, monkeypatch):
        _client, gateway = flat_stack
        monkeypatch.setattr(demo_coverage_mod, "DEMO_COVERAGE_ROW_CAP", 2)
        got = build_demo_coverage(gateway)
        assert got["window"] == {"row_cap": 2, "rows_considered": 2, "truncated": True}
        assert got["breakdown"]["total"] == 2
        assert got["states"] == {"traced": 2}


# ---------------------------------------------------------------------------
# Bounded disclosure: aggregates only
# ---------------------------------------------------------------------------


class TestDemoCoverageDisclosure:
    def test_denial_reason_value_and_keys_never_ship(self, flat_stack):
        client, _gateway = flat_stack
        r = client.get("/api/demo/coverage", headers={"Authorization": "demo-key-sim"})
        assert "ACC-777" not in r.text, "the deny reason quotes constraint values"
        assert '"reason"' not in r.text
        assert "sha256:" not in r.text, "aggregate rows carry no receipt hashes"

    def test_credentials_never_ship(self, flat_stack):
        client, _gateway = flat_stack
        r = client.get("/api/demo/coverage", headers={"Authorization": "demo-key-sim"})
        assert "admin-key-0123456789" not in r.text
        assert "demo-key-sim" not in r.text

    def test_malformed_chain_lines_are_skipped(self, flat_stack):
        client, gateway = flat_stack
        chain = Path(gateway.config.receipt_store)
        lines = chain.read_text(encoding="utf-8").strip().splitlines()
        junk = ["{", "not json at all", '{"receipt_hash": "orphan"}', '["a", "list"]']
        chain.write_text("\n".join(junk + lines) + "\n", encoding="utf-8")
        r = client.get("/api/demo/coverage", headers={"Authorization": "demo-key-sim"})
        assert r.status_code == 200
        assert r.json()["breakdown"] == {"total": 3, "receipted": 3, "out_of_gate": 0, "pending": 0}


# ---------------------------------------------------------------------------
# Endpoint: the demo-plane contract family
# ---------------------------------------------------------------------------


class TestDemoCoverageEndpoint:
    def test_demo_reader_reads_the_surface(self, flat_stack):
        client, _gateway = flat_stack
        r = client.get("/api/demo/coverage", headers={"Authorization": "demo-key-sim"})
        assert r.status_code == 200
        for key in (
            "schema_version",
            "metric",
            "vantage",
            "basis",
            "receipted_share",
            "breakdown",
            "states",
            "decisions",
            "contract",
            "by_tool",
            "by_agent",
            "window",
        ):
            assert key in r.json(), key

    @pytest.mark.parametrize("build", ["flat_stack", "indexed_stack", "store_only_stack"], ids=str)
    def test_enumeration_paths_agree_with_the_builder(self, build, request):
        client, gateway = request.getfixturevalue(build)
        r = client.get("/api/demo/coverage", headers={"Authorization": "demo-key-sim"})
        assert r.status_code == 200
        assert r.json() == build_demo_coverage(gateway)

    def test_surface_closed_without_demo_mode(self, plain_stack):
        client, _gateway = plain_stack
        r = client.get("/api/demo/coverage", headers={"Authorization": "admin-key-0123456789"})
        assert r.status_code == 404

    def test_surface_requires_credentials(self, flat_stack):
        client, _gateway = flat_stack
        assert client.get("/api/demo/coverage").status_code == 401

    def test_empty_plane_answers_unavailable_never_zero(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAUCLE_DEMO_MODE", "1")
        monkeypatch.setenv("RAUCLE_DEMO_KEY", "demo-key-sim")
        gateway = _gateway(tmp_path)
        client = TestClient(create_admin_app(gateway, _users()))
        r = client.get("/api/demo/coverage", headers={"Authorization": "demo-key-sim"})
        assert r.status_code == 200
        body = r.json()
        assert body["receipted_share"] is None
        assert "never zero" in body["unavailable_note"]

    def test_surfaces_stay_deterministic(self, flat_stack):
        client, _gateway = flat_stack
        first = client.get("/api/demo/coverage", headers={"Authorization": "demo-key-sim"})
        second = client.get("/api/demo/coverage", headers={"Authorization": "demo-key-sim"})
        assert first.content == second.content

    @pytest.mark.parametrize(
        "path",
        ["/api/demo/users", "/api/demo/siem", "/api/demo/config", "/api/demo/coverage"],
    )
    def test_demo_plane_registers_no_mutation_routes(self, plain_stack, path):
        client, _gateway = plain_stack
        mutations = [
            (route.path, method)
            for route in client.app.routes
            for p in (path,)
            if getattr(route, "path", "") == p
            for method in getattr(route, "methods", set())
            if method != "GET"
        ]
        assert mutations == []


# ---------------------------------------------------------------------------
# Panel integration
# ---------------------------------------------------------------------------


class TestDemoCoveragePanel:
    def test_nav_item_sits_in_the_assurance_stack_after_key_model(self):
        nav_item = (
            '<div class="tab" tabindex="0" data-hi="navCoverage()" '
            'data-tab-id="coverage">Coverage</div>'
        )
        assert nav_item in ADMIN_PANEL_HTML
        key_model = 'data-hi="navKeyModel()" data-tab-id="keymodel"'
        assert ADMIN_PANEL_HTML.find(nav_item) > ADMIN_PANEL_HTML.find(key_model)

    def test_coverage_card_is_demo_only(self):
        assert "body:not(.demo) #rcptCoverageCard" in ADMIN_PANEL_HTML
        assert '<div class="card hidden" id="rcptCoverageCard">' in ADMIN_PANEL_HTML

    def test_card_lives_in_the_receipts_tab_after_the_key_model_card(self):
        assert ADMIN_PANEL_HTML.find('id="rcptCoverageCard"') > ADMIN_PANEL_HTML.find(
            'id="rcpt-keymodel"'
        )

    def test_card_label_is_simulated_demo_data(self):
        start = ADMIN_PANEL_HTML.find('id="rcptCoverageCard"')
        section = ADMIN_PANEL_HTML[start : start + 2000]
        assert "Simulated demo data" in section

    def test_loader_branches_on_demo_mode(self):
        assert "typeof demoMode!=='undefined'&&demoMode){loadDemoCoverage()}" in ADMIN_PANEL_HTML

    def test_receipts_tab_entry_routes_to_the_coverage_loader(self):
        dispatch = (
            "if(t==='receipts'){loadReceipts();loadKeyFamily();loadKeyModel();"
            "if(typeof demoMode!=='undefined'&&demoMode)loadCoverage();}"
        )
        assert ADMIN_PANEL_HTML.count(dispatch) == 2, (
            "both dispatch lines must stay live: a partial edit kills the tab"
        )

    def test_loader_targets_the_demo_endpoint(self):
        assert "api('/api/demo/coverage')" in ADMIN_PANEL_HTML

    def test_demo_404_fallback_message_wired(self):
        assert ADMIN_PANEL_HTML.count("Demo mode is not configured on this deployment.") >= 5

    def test_delegation_map_carries_the_coverage_nav(self):
        assert '"navCoverage()":(ev,el)=>navCoverage(el),' in ADMIN_PANEL_HTML
        script = "".join(re.findall(r"<script[^>]*>(.*?)</script>", ADMIN_PANEL_HTML, re.S))
        fn_at = script.find("function navCoverage(el)")
        assert fn_at != -1
        assert "rcptCoverageCard" in script[fn_at : fn_at + 240]

    def test_demo_loader_renders_textcontent_only(self):
        script = "".join(re.findall(r"<script[^>]*>(.*?)</script>", ADMIN_PANEL_HTML, re.S))
        start = script.find("DEMO COVERAGE")
        end = script.find("// ================= DEMO FINDINGS", start)
        assert start != -1
        assert end != -1
        assert end > start
        section = script[start:end]
        assert "innerHTML" not in section
        assert "onclick" not in section
        assert section.count("textContent") >= 10
