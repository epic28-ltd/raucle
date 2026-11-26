"""Live non-enforcing shadow policy evaluation (issue #344 items 8-12).

Contract pinned here (ADR 0010 section 4):
1. Default OFF: a gateway without shadow config behaves exactly as before.
2. The shadow evaluator compares the SAME normalized request the live gate
   enforced against a CANDIDATE policy, evaluated with the gate's own
   deterministic rule-matching + constraint machinery, never echoing the
   live decision.
3. Shadow surface cannot block, delay, mutate or forward enforcement:
   worker-stuck, over-budget and exception paths all leave the live
   decision (and its receipt) untouched, with named loss counters.
4. Shadow rows are a DISTINCT evidence family: dedicated row-capped JSONL
   artifact, ``kind=shadow_eval`` + mode marker, metadata-only, schema
   bounded by allowlist, never argument values, never reasons, never
   inside the receipt store and never a signed receipt.
5. Bounded queue sheds BY NAME (overflow counter) instead of pushing back
   on enforcement; sampling is deterministic with counted unsampled
   coverage; shutdown sheds later submissions and leaves enforcement fine.
6. Historical simulation compatibility: resolve_candidate_policy and the
   x_sim machinery are untouched (their own tests stay the source of
   truth); this file only asserts evidence-family separation.
"""

import json
import threading
import time

import pytest

from raucle import policy_shadow as ps
from raucle.gateway import GatewayConfig, RaucleGateway

ACTIVE_POLICY = """
version: 1
issuer: shadow.example
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-999"]
"""

CANDIDATE_STRICTER = """
version: 1
issuer: shadow.example
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    id: cand-strict
    constraints:
      allow:
        account: ["ACC-001"]
"""

CANDIDATE_ESCALATE = """
version: 1
issuer: shadow.example
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    id: cand-guard
    constraints:
      allow:
        account: ["ACC-001"]
    require_approval_when:
      amount_gt: 100
"""

CANDIDATE_OTHER_TOOL = """
version: 1
issuer: shadow.example
policies:
  - tool: other_tool
    agent_id: agent:x
    ttl_seconds: 60
    id: cand-elsewhere
    constraints:
      allow:
        account: ["ACC-001"]
"""

CANDIDATE_TAINT_ONLY = """
version: 1
issuer: shadow.example
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    id: cand-taint
    participant: tool_response_taint
    constraints:
      allow:
        account: ["ACC-001"]
"""

CANDIDATE_WRONG_SOURCE = """
version: 1
issuer: shadow.example
policies:
  - tool: export_records
    agent_id: agent:svc
    source: "not-this-source/*"
    ttl_seconds: 60
    id: cand-sourcemiss
    constraints:
      allow:
        account: ["ACC-001"]
"""

NOT_A_POLICY = "not: a\npolicy: document"

SECRET = "TOPSECRET-CALLER-VALUE-77"

CANDIDATE_HASH = ps._HASH_PREFIX


def _candidate_path(tmp_path, text):
    p = tmp_path / "candidate.yaml"
    p.write_text(text)
    return p


def _shadow_gateway(
    tmp_path,
    *,
    candidate_yaml=CANDIDATE_STRICTER,
    queue_max=64,
    budget_ms=200,
    sample_every=1,
    max_records=4096,
):
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
    config.policy_file.write_text(ACTIVE_POLICY)
    config.gate_auth = "off"
    config.shadow_eval_enabled = True
    config.shadow_candidate_policy = str(_candidate_path(tmp_path, candidate_yaml))
    config.shadow_eval_output = str(tmp_path / "shadow.jsonl")
    config.shadow_eval_queue_max = queue_max
    config.shadow_eval_budget_ms = budget_ms
    config.shadow_eval_sample_every = sample_every
    config.shadow_eval_max_records = max_records
    gateway = RaucleGateway(config)
    return gateway, tmp_path / "shadow.jsonl"


def _call(gateway, account="ACC-001", trace="t1", args_extra=None):
    args = {"account": account}
    if args_extra:
        args.update(args_extra)
    return gateway.check_tool_call("export_records", args, agent_id="agent:svc", trace_id=trace)


def _rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _counter_total(stats, name):
    slot = stats["counters"].get(name, {})
    return slot.get("total", 0)


# ---------------------------------------------------------------------------
# 1. Default off


def test_shadow_off_by_default_is_untouched(tmp_path):
    """No shadow config: no evaluator, no rows, no counters surface, no
    behaviour change on the decision or receipt path."""
    policy_path = tmp_path / "policies.yaml"
    policy_path.write_text(ACTIVE_POLICY)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(policy_path),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    config.gate_auth = "off"
    gateway = RaucleGateway(config)
    assert gateway._shadow_eval is None
    assert gateway.shadow_eval_stats() is None
    assert gateway.shutdown_shadow_eval() is None
    result = _call(gateway)
    assert result["decision"] == "allow"
    assert result["receipt_id"]
    assert (
        not (tmp_path / "receipts.jsonl").exists()
        or "shadow_eval" not in (tmp_path / "receipts.jsonl").read_text()
    )


# ---------------------------------------------------------------------------
# 2. Boot validation (fail closed, named)


@pytest.fixture
def _shadow_boot_cases(tmp_path):
    """Builds all five boot-refusal configs, so every refusal test body
    holds exactly one raising invocation (S5778)."""
    good = _candidate_path(tmp_path, CANDIDATE_STRICTER)
    bad = tmp_path / "not-policy.yaml"
    bad.write_text(NOT_A_POLICY)

    def _cfg(candidate, **kw):
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file=str(tmp_path / "policies.yaml"),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
        )
        config.gate_auth = "off"
        config.shadow_eval_enabled = True
        config.shadow_candidate_policy = candidate
        for k, v in kw.items():
            setattr(config, k, v)
        return config

    return {
        "empty_candidate": _cfg(""),
        "missing_candidate": _cfg(str(tmp_path / "missing.yaml")),
        "non_policy_file": _cfg(str(bad)),
        "zero_sample_every": _cfg(str(good), shadow_eval_sample_every=0),
        "zero_queue_max": _cfg(str(good), shadow_eval_queue_max=0),
    }


def test_boot_refuses_empty_candidate(_shadow_boot_cases):
    with pytest.raises(ValueError, match="shadow_eval_config_invalid"):
        RaucleGateway(_shadow_boot_cases["empty_candidate"])


def test_boot_refuses_missing_candidate_file(_shadow_boot_cases):
    with pytest.raises(ValueError, match="shadow_eval_config_invalid"):
        RaucleGateway(_shadow_boot_cases["missing_candidate"])


def test_boot_refuses_non_policy_candidate_file(_shadow_boot_cases):
    with pytest.raises(ValueError, match="shadow_eval_config_invalid"):
        RaucleGateway(_shadow_boot_cases["non_policy_file"])


def test_boot_refuses_zero_sample_every(_shadow_boot_cases):
    with pytest.raises(ValueError, match="shadow_eval_config_invalid"):
        RaucleGateway(_shadow_boot_cases["zero_sample_every"])


def test_boot_refuses_zero_queue_max(_shadow_boot_cases):
    with pytest.raises(ValueError, match="shadow_eval_config_invalid"):
        RaucleGateway(_shadow_boot_cases["zero_queue_max"])


def test_env_loader_wires_shadow_fields(monkeypatch, tmp_path):
    candidate = _candidate_path(tmp_path, CANDIDATE_STRICTER)
    monkeypatch.setenv("RAUCLE_SHADOW_EVAL", "1")
    monkeypatch.setenv("RAUCLE_SHADOW_CANDIDATE_POLICY", str(candidate))
    monkeypatch.setenv("RAUCLE_SHADOW_EVAL_SAMPLE_EVERY", "3")
    monkeypatch.setenv("RAUCLE_SHADOW_EVAL_BUDGET_MS", "50")
    config = GatewayConfig.from_env()
    assert config.shadow_eval_enabled is True
    assert config.shadow_candidate_policy == str(candidate)
    assert config.shadow_eval_sample_every == 3
    assert config.shadow_eval_budget_ms == 50


# ---------------------------------------------------------------------------
# 3. The comparison itself


def test_shadow_compares_same_request_against_candidate(tmp_path):
    """Same normalized request enforced (allow), candidate stricter (deny):
    the row binds candidate hash, active digest, request identity by the
    receipt input-hash convention, and no payload leaves the surface."""
    gateway, out = _shadow_gateway(tmp_path)
    result = _call(gateway, account="ACC-999", trace="t-cmp")
    assert result["decision"] == "allow"
    assert result["receipt_id"]
    assert gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 1
    row = rows[0]
    assert row["kind"] == ps.SHADOW_RECORD_KIND
    assert row["mode"] == ps.SHADOW_MODE
    assert row["live_decision"] == "allow"
    assert row["shadow_decision"] == "deny"
    assert row["diverges"] is True
    assert row["candidate_rule_id"] == "cand-strict"
    assert row["candidate_rule_matched"] is True
    from raucle.policy_simulate import resolve_candidate_policy

    _, candidate_hash = resolve_candidate_policy(candidate_policy_yaml=CANDIDATE_STRICTER)
    assert row["candidate_policy_hash"] == CANDIDATE_HASH + candidate_hash
    assert row["active_policy_hash"].startswith("sha256:")
    assert row["input_hash"] == ps._input_hash({"account": "ACC-999"})
    assert row["trace_id"] == "t-cmp"
    assert row["tool"] == "export_records"
    assert set(row) == set(ps.SHADOW_ROW_KEYS)


def test_candidate_missing_tool_deny_is_fail_closed_not_live_echo(tmp_path):
    gateway, out = _shadow_gateway(tmp_path, candidate_yaml=CANDIDATE_OTHER_TOOL)
    result = _call(gateway, account="ACC-001", trace="t-nopol")
    assert result["decision"] == "allow"
    gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 1
    assert rows[0]["shadow_decision"] == "deny"
    assert rows[0]["candidate_rule_matched"] is False
    assert rows[0]["candidate_rule_id"] == ""
    assert rows[0]["diverges"] is True


def test_candidate_taint_participant_rule_never_authorises(tmp_path):
    """A taint-participant candidate rule is a deny-only overlay exactly as
    in enforcement: skipped for authority, so the comparison fails closed
    to deny instead of granting under the overlay."""
    gateway, out = _shadow_gateway(tmp_path, candidate_yaml=CANDIDATE_TAINT_ONLY)
    result = _call(gateway, account="ACC-001", trace="t-taint")
    assert result["decision"] == "allow"
    gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 1
    assert rows[0]["shadow_decision"] == "deny"
    assert rows[0]["candidate_rule_matched"] is False


def test_candidate_source_mismatch_skips_and_deny_wins(tmp_path):
    gateway, out = _shadow_gateway(tmp_path, candidate_yaml=CANDIDATE_WRONG_SOURCE)
    result = _call(gateway, account="ACC-001", trace="t-src")
    assert result["decision"] == "allow"
    gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 1
    assert rows[0]["shadow_decision"] == "deny"  # no candidate rule matched
    assert rows[0]["candidate_rule_matched"] is False
    assert rows[0]["diverges"] is True


def test_candidate_approval_threshold_shadows_escalate(tmp_path):
    gateway, out = _shadow_gateway(tmp_path, candidate_yaml=CANDIDATE_ESCALATE)
    result = _call(gateway, account="ACC-001", trace="t-esc", args_extra={"amount": 5000})
    assert result["decision"] == "allow"
    gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 1
    assert rows[0]["shadow_decision"] == "escalate"
    assert rows[0]["candidate_rule_id"] == "cand-guard"
    assert rows[0]["diverges"] is True


# ---------------------------------------------------------------------------
# 4. Cannot block / delay / mutate / forward


def test_stuck_worker_cannot_block_or_delay_enforcement(tmp_path, monkeypatch):
    """Worker stuck mid-evaluation: queue fills, overflow SHEDS BY NAME and
    live calls still return their allow in bounded time."""
    gateway, out = _shadow_gateway(tmp_path, queue_max=1)
    entered = threading.Event()
    release = threading.Event()

    def stuck(request, ruleset, *, deadline_mono):
        entered.set()
        release.wait(timeout=10)
        return {
            "shadow_decision": "deny",
            "candidate_rule_id": "",
            "candidate_rule_matched": False,
        }

    monkeypatch.setattr(ps, "_evaluate_request", stuck)
    first = _call(gateway, account="ACC-001", trace="t-stuck-1")
    assert first["decision"] == "allow"
    # Prove the worker is genuinely inside evaluation before the bound calls.
    assert entered.wait(timeout=5)

    t0 = time.perf_counter()
    second = _call(gateway, account="ACC-001", trace="t-stuck-2")
    elapsed = time.perf_counter() - t0
    t1 = time.perf_counter()
    third = _call(gateway, account="ACC-001", trace="t-stuck-3")
    elapsed3 = time.perf_counter() - t1
    release.set()

    assert second["decision"] == "allow"
    assert third["decision"] == "allow"
    assert elapsed < 2.0
    assert elapsed3 < 2.0
    stats = gateway.shadow_eval_stats()
    assert _counter_total(stats, "shadow_queue_overflow") == 1
    assert stats["submitted"] == 2
    assert gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 2
    for row in rows:
        assert row["live_decision"] == "allow"
        assert row["shadow_decision"] == "deny"  # the stuck fake's verdict
        assert row["diverges"] is True
    assert {r["trace_id"] for r in rows} == {"t-stuck-1", "t-stuck-2"}


def test_over_budget_is_dropped_named_and_worker_recovers(tmp_path, monkeypatch):
    gateway, out = _shadow_gateway(tmp_path, budget_ms=1)

    def slow(request, ruleset, *, deadline_mono):
        time.sleep(0.25)
        raise ps.ShadowBudgetExceeded("past budget")

    monkeypatch.setattr(ps, "_evaluate_request", slow)
    result = _call(gateway, account="ACC-001", trace="t-slow")
    assert result["decision"] == "allow"
    assert result["receipt_id"]  # receipt path fully intact
    gateway._shadow_eval.flush()
    assert _rows(out) == []
    stats = gateway.shadow_eval_stats()
    assert _counter_total(stats, "shadow_over_budget") == 1
    assert _counter_total(stats, "shadow_row_written") == 0
    assert stats["running"] is True

    # The worker recovers: an on-budget evaluation still lands.
    def normal(request, ruleset, *, deadline_mono):
        return {
            "shadow_decision": "allow",
            "candidate_rule_id": "cand-strict",
            "candidate_rule_matched": True,
        }

    monkeypatch.setattr(ps, "_evaluate_request", normal)
    normal_call = _call(gateway, account="ACC-001", trace="t-after-slow")
    assert normal_call["decision"] == "allow"
    assert gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 1
    assert rows[0]["trace_id"] == "t-after-slow"
    assert rows[0]["shadow_decision"] == "allow"
    assert rows[0]["candidate_rule_id"] == "cand-strict"


def test_evaluator_exception_cannot_alter_live_decision(tmp_path, monkeypatch):
    gateway, out = _shadow_gateway(tmp_path)

    def boom(request, ruleset, *, deadline_mono):
        raise RuntimeError("ShadowFaultInjected")

    monkeypatch.setattr(ps, "_evaluate_request", boom)
    result = _call(gateway, account="ACC-999", trace="t-boom")
    assert result["decision"] == "allow"
    assert result["receipt_id"]
    gateway._shadow_eval.flush()
    assert _rows(out) == []
    stats = gateway.shadow_eval_stats()
    assert _counter_total(stats, "shadow_eval_error") == 1
    assert _counter_total(stats, "shadow_row_written") == 0


def test_mutation_after_submit_cannot_change_evaled_request(tmp_path):
    gateway, out = _shadow_gateway(tmp_path)
    args = {"account": "ACC-001", "caller_secret": SECRET}
    result = gateway.check_tool_call("export_records", args, agent_id="agent:svc", trace_id="t-mut")
    assert result["decision"] == "allow"
    # Mutate the caller's dict AFTER submission: the captured request was
    # deep-copied at the boundary and cannot be retroactively changed.
    args["account"] = "TAMPERED-ACC"
    args["caller_secret"] = "TAMPERED-SECRET"
    assert gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 1
    assert rows[0]["input_hash"] == ps._input_hash({"account": "ACC-001", "caller_secret": SECRET})
    content = out.read_text()
    assert "TAMPERED" not in content


def test_shutdown_sheds_by_name_and_gateway_still_enforces(tmp_path):
    gateway, out = _shadow_gateway(tmp_path)
    first = _call(gateway, account="ACC-001", trace="t-close-1")
    assert first["decision"] == "allow"
    assert gateway.shutdown_shadow_eval(timeout_s=5.0) is True
    after = _call(gateway, account="ACC-001", trace="t-close-2")
    assert after["decision"] == "allow"
    assert after["receipt_id"]
    stats = gateway.shadow_eval_stats()
    assert stats["closed"] is True
    assert _counter_total(stats, "shadow_after_close") >= 1
    assert gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 1
    assert rows[0]["trace_id"] == "t-close-1"


# ---------------------------------------------------------------------------
# 5. Bounds and coverage


def test_evaluator_row_schema_tampering_fails_closed(tmp_path, monkeypatch):
    """A row that would leave the bounded schema is refused, not written."""
    gateway, out = _shadow_gateway(tmp_path)
    monkeypatch.setattr(ps, "SHADOW_ROW_KEYS", frozenset({"unexpected"}))
    result = _call(gateway, account="ACC-001", trace="t-shape")
    assert result["decision"] == "allow"
    gateway._shadow_eval.flush()
    assert _rows(out) == []
    stats = gateway.shadow_eval_stats()
    assert _counter_total(stats, "shadow_eval_error") == 1


def test_flush_reports_timeout_while_worker_is_busy(tmp_path, monkeypatch):
    gateway, out = _shadow_gateway(tmp_path, budget_ms=5000)
    entered = threading.Event()
    release = threading.Event()

    def held(request, ruleset, *, deadline_mono):
        entered.set()
        release.wait(timeout=5)
        return {
            "shadow_decision": "allow",
            "candidate_rule_id": "",
            "candidate_rule_matched": False,
        }

    monkeypatch.setattr(ps, "_evaluate_request", held)
    result = _call(gateway, account="ACC-001", trace="t-flush")
    assert result["decision"] == "allow"
    assert entered.wait(timeout=5)
    assert gateway._shadow_eval.flush(timeout_s=0.2) is False
    release.set()
    assert gateway._shadow_eval.flush(timeout_s=5.0) is True
    assert len(_rows(out)) == 1


def test_completed_but_late_evaluation_is_dropped_by_name(tmp_path, monkeypatch):
    """A row that returns after its wall-clock budget never becomes
    evidence: the budget is on emission, not only on raising."""
    gateway, out = _shadow_gateway(tmp_path, budget_ms=1)

    def late(request, ruleset, *, deadline_mono):
        time.sleep(0.05)
        return {
            "shadow_decision": "allow",
            "candidate_rule_id": "",
            "candidate_rule_matched": False,
        }

    monkeypatch.setattr(ps, "_evaluate_request", late)
    result = _call(gateway, account="ACC-001", trace="t-late")
    assert result["decision"] == "allow"
    assert result["receipt_id"]
    gateway._shadow_eval.flush()
    assert _rows(out) == []
    stats = gateway.shadow_eval_stats()
    assert _counter_total(stats, "shadow_over_budget") == 1
    assert _counter_total(stats, "shadow_row_written") == 0


def test_explicit_output_path_is_honoured(tmp_path):
    gateway, _ = _shadow_gateway(tmp_path)
    result = _call(gateway, account="ACC-001", trace="t-outp")
    assert result["decision"] == "allow"
    assert gateway._shadow_eval.flush()
    assert (tmp_path / "shadow.jsonl").exists()


def test_boot_without_receipt_store_falls_back_to_cwd(tmp_path, monkeypatch):
    policy_path = tmp_path / "policies.yaml"
    policy_path.write_text(ACTIVE_POLICY)
    monkeypatch.chdir(tmp_path)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(policy_path),
        receipt_store="",
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
        emit_receipts=False,
    )
    config.gate_auth = "off"
    config.shadow_eval_enabled = True
    config.shadow_candidate_policy = str(policy_path)  # boot accepted as candidate too
    gateway = RaucleGateway(config)
    assert gateway._shadow_eval is not None
    assert gateway._shadow_eval._output_path == tmp_path / "policy-shadow.jsonl"
    gateway.shutdown_shadow_eval()


def test_shutdown_without_worker_returns_true(tmp_path):
    out = tmp_path / "shadow.jsonl"
    evaluator = ps.ShadowEvaluator(
        candidate_policy_path=_candidate_path(tmp_path, CANDIDATE_STRICTER),
        output_path=out,
        autostart=False,
    )
    assert evaluator.shutdown() is True
    assert evaluator.stats()["running"] is False


def test_counter_failure_is_swallowed_and_evidence_still_lands(tmp_path, monkeypatch):
    gateway, out = _shadow_gateway(tmp_path)

    def broken(*_a, **_kw):
        raise OSError("disk gone")

    monkeypatch.setattr(gateway._shadow_eval._counter, "increment", broken)
    result = _call(gateway, account="ACC-001", trace="t-countfail")
    assert result["decision"] == "allow"
    assert result["receipt_id"]
    assert gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 1
    assert rows[0]["shadow_decision"] == "allow"
    stats = gateway.shadow_eval_stats()
    assert stats["submitted"] == 1
    assert stats["counters"] == {}


# ---------------------------------------------------------------------------


def test_bounded_queue_sheds_by_name_without_blocking(tmp_path):
    """Direct evaluator, autostart off: overflow sheds instantly, the shed
    is named, and the queued work still runs once a worker starts."""
    out = tmp_path / "shadow.jsonl"
    evaluator = ps.ShadowEvaluator(
        candidate_policy_path=_candidate_path(tmp_path, CANDIDATE_STRICTER),
        output_path=out,
        queue_maxsize=1,
        max_records=4096,
        autostart=False,
    )
    for _ in range(3):
        evaluator.submit(
            tool="export_records",
            args={"account": "ACC-001"},
            agent_id="agent:svc",
            source="",
            destination="",
            trace_id="t-shed",
            live_decision="allow",
            active_policy_hash="sha256:" + "0" * 64,
        )
    stats = evaluator.stats()
    assert _counter_total(stats, "shadow_queue_overflow") == 2
    assert stats["submitted"] == 1
    evaluator._start_worker()
    assert evaluator.flush()
    rows = _rows(out)
    assert len(rows) == 1
    assert rows[0]["shadow_decision"] == "allow"
    evaluator.shutdown(timeout_s=5.0)


def test_record_cap_bounds_the_artifact(tmp_path):
    gateway, out = _shadow_gateway(tmp_path, max_records=1)
    first = _call(gateway, account="ACC-001", trace="t-cap-1")
    assert first["decision"] == "allow"
    second = _call(gateway, account="ACC-999", trace="t-cap-2")
    assert second["decision"] == "allow"
    assert gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 1
    stats = gateway.shadow_eval_stats()
    assert _counter_total(stats, "shadow_record_cap") == 1
    assert stats["rows_written"] == 1


def test_sampling_metadata_deterministic_and_unsample_counted(tmp_path):
    gateway, out = _shadow_gateway(tmp_path, sample_every=3)
    traces = [f"t-s{i}" for i in range(6)]
    for i, trace in enumerate(traces):
        account = "ACC-001" if i % 2 == 0 else "ACC-999"
        result = _call(gateway, account=account, trace=trace)
        assert result["decision"] == "allow"
    assert gateway._shadow_eval.flush()
    rows = _rows(out)
    expected_selected = [ps._sample_selected(t, 3) for t in traces]
    assert len(rows) == sum(expected_selected)
    for row in rows:
        assert row["sampling"] == {"sample_every": 3, "selected": True}
        assert row["trace_id"] in traces
    stats = gateway.shadow_eval_stats()
    assert _counter_total(stats, "shadow_unsampled") == 6 - sum(expected_selected)
    assert stats["submitted"] == sum(expected_selected)


# ---------------------------------------------------------------------------
# 6. Evidence-family separation (bounded disclosure)


def test_rows_metadata_only_bounded_schema_payload_free(tmp_path):
    gateway, out = _shadow_gateway(tmp_path)
    result = _call(
        gateway,
        account="ACC-001",
        trace="t-disc",
        args_extra={"caller_secret": SECRET, "system_prompt": "REVEAL-ALL"},
    )
    assert result["decision"] == "allow"
    gateway._shadow_eval.flush()
    rows = _rows(out)
    assert len(rows) == 1
    for row in rows:
        assert set(row) == set(ps.SHADOW_ROW_KEYS)
        assert "reason" not in row
        assert row["kind"] == ps.SHADOW_RECORD_KIND
        assert row["mode"] == ps.SHADOW_MODE
        assert isinstance(row["live_decision"], str)
        assert row["live_decision"] in ("allow", "deny", "escalate")
        assert row["shadow_decision"] in ("allow", "deny", "escalate")
    content = out.read_text()
    # Sensitive PAYLOADS never captured: no caller values, no prompts.
    assert SECRET not in content
    assert "REVEAL-ALL" not in content
    # Distinct evidence family: no simulation-receipt marker on shadow
    # rows.
    assert "x_sim" not in content


def test_shadow_rows_never_enter_receipt_or_fault_evidence(tmp_path):
    gateway, out = _shadow_gateway(tmp_path)
    for i, account in enumerate(("ACC-001", "ACC-999")):
        result = _call(gateway, account=account, trace=f"t-sep-{i}")
        assert result["decision"] == "allow"
    assert gateway._shadow_eval.flush()
    receipts_path = tmp_path / "receipts.jsonl"
    receipts = receipts_path.read_text()
    assert "shadow_eval" not in receipts
    assert "policy_shadow/v1" not in receipts
    # Live receipts are separate signed evidence, emitted per call.
    assert len(receipts.splitlines()) >= 2
    rows = _rows(out)
    assert len(rows) == 2
    for row in rows:
        # No JWS/signature structure of any family on shadow rows.
        for forbidden in ("jws", "signature", "receipt_id", "x_sim"):
            assert forbidden not in row
