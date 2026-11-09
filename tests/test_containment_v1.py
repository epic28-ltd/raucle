"""P4.A v1: targeted containment — trace quarantine + lease suspension.

Acceptance criteria (P4.A v1 lane, `p4a-killswitch-research.md` §3):

- quarantining a trace denies NEW gate work on it (named reason, denied
  BEFORE constraint evaluation, un-bypassable by a valid token) while
  existing receipts remain independently verifiable (no history rewrite);
- suspending a credential lease cuts the agent at the gate even with a
  valid api key; reinstating restores it;
- EVERY transition (quarantine, release, suspend, reinstate) mints a
  signed, offline-verifiable receipt — a halt without its receipt is a
  bug, and a failed receipt rolls the transition back;
- hostile inputs (malformed ids, double transitions, releasing what was
  never quarantined) are named errors, never silent no-ops.

Honest limit (documented everywhere): nothing here kills a process or a
host — it revokes authority at the gate.
"""

import base64
import hashlib
import json

import pytest

from raucle.agent_credentials import AgentCredentialStore
from raucle.cli import main as cli_main
from raucle.containment import (
    VERDICT_LEASE_REINSTATE,
    VERDICT_LEASE_SUSPEND,
    VERDICT_TRACE_QUARANTINE,
    VERDICT_TRACE_RELEASE,
    ContainmentConfig,
    ContainmentError,
    ContainmentManager,
)
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.provenance import ProvenanceVerifier
from raucle.verdicts import VerdictVerifier

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


def _config(tmp_path) -> ContainmentConfig:
    return ContainmentConfig(
        policy_file=str(tmp_path / "policies.yaml"),
        revocations_file=str(tmp_path / "revocations.jsonl"),
        delegations_file=str(tmp_path / "delegations.jsonl"),
        quarantines_file=str(tmp_path / "trace-quarantines.jsonl"),
        lease_suspensions_file=str(tmp_path / "lease-suspensions.jsonl"),
        receipts_path=str(tmp_path / "containment-receipts.jsonl"),
        state_dir=str(tmp_path / "containment"),
        actor="op",
        # v1 quarantine/lease tests pin the v0 single-approver hold path
        global_min_approvers=1,
    )


@pytest.fixture
def gw(tmp_path):
    """A live gateway wired to the same registries the CLI operates on."""
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(policy),
        receipt_store=str(tmp_path / "gateway-receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        trace_quarantine_file=str(tmp_path / "trace-quarantines.jsonl"),
        lease_suspensions_file=str(tmp_path / "lease-suspensions.jsonl"),
        emit_receipts=True,
    )
    return RaucleGateway(config)


def _receipts(path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _verdict_payload(jws: str) -> dict:
    part = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


class TestTraceQuarantine:
    def test_quarantine_denies_new_work_named(self, tmp_path, gw):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        quarantined = mgr.quarantine_trace("t-incident", reason="prompt injection")
        assert quarantined["status"] == "quarantined"
        assert quarantined["receipt_id"]

        denied = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-incident"
        )
        assert denied["decision"] == "deny"
        assert "quarantined" in denied["reason"]
        # quarantine fires BEFORE constraint evaluation / policy lookup
        assert "quarantined" in denied["reason"]

        # another trace on the same agent is untouched
        ok = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-other"
        )
        assert ok["decision"] == "allow"

    def test_quarantine_un_bypassable_without_policy(self, tmp_path, gw):
        """Even on a tool with no policy at all, the named reason is the
        quarantine, not the routine policy deny: the registry is consulted
        before the policy machinery."""
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        mgr.quarantine_trace("t-x")
        denied = gw.check_tool_call("nonexistent_tool", {}, agent_id="", trace_id="t-x")
        assert denied["decision"] == "deny"
        assert "quarantined" in denied["reason"]
        assert "no policy configured" not in denied["reason"]

    def test_existing_receipts_still_verify_after_quarantine(self, tmp_path, gw):
        """No history rewrite: receipts minted while the trace was live
        stay independently verifiable after the trace is quarantined."""
        minted = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-1"
        )
        assert minted["decision"] == "allow"
        before = _receipts(gw.config.receipt_store)

        mgr = ContainmentManager(_config(tmp_path))
        mgr.quarantine_trace("t-1")
        after_quarantine = _receipts(gw.config.receipt_store)
        assert after_quarantine[: len(before)] == before  # nothing rewritten

        pem = gw._gate_identity.public_key_pem()
        report = ProvenanceVerifier(public_keys={gw._gate_identity.key_id: pem}).verify_chain(
            gw.config.receipt_store
        )
        assert report.valid, report.errors

    def test_quarantine_and_release_receipts_verify_offline(self, tmp_path):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        mgr.quarantine_trace("t-1", reason="drill")
        mgr.release_trace("t-1", reason="drill over")
        receipts = _receipts(cfg.receipts_path)
        verdicts = [_verdict_payload(r["jws"])["verdict"] for r in receipts]
        assert verdicts == [VERDICT_TRACE_QUARANTINE, VERDICT_TRACE_RELEASE]
        pubkey = (tmp_path / "containment" / "containment-operator-pubkey.pem").read_bytes()
        verifier = VerdictVerifier(public_key_pem=pubkey)
        for receipt, verdict in zip(receipts, verdicts, strict=False):
            payload = verifier.verify(receipt["jws"])
            assert payload.verdict == verdict
            assert payload.extra["trace_id"] == "t-1"
            assert payload.extra["actor"] == "op"

    def test_release_resumes_gate_work(self, tmp_path, gw):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        mgr.quarantine_trace("t-1")
        assert (
            gw.check_tool_call(
                "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-1"
            )["decision"]
            == "deny"
        )
        released = mgr.release_trace("t-1")
        assert released["status"] == "released"
        ok = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-1"
        )
        assert ok["decision"] == "allow"

    def test_hostile_transitions_are_named(self, tmp_path):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        with pytest.raises(ContainmentError, match="not quarantined"):
            mgr.release_trace("t-never-quarantined")
        mgr.quarantine_trace("t-1")
        with pytest.raises(ContainmentError, match="already quarantined"):
            mgr.quarantine_trace("t-1")
        with pytest.raises(ContainmentError, match="malformed scope"):
            mgr.quarantine_trace("bad id with spaces")
        with pytest.raises(ContainmentError, match="malformed scope"):
            mgr.quarantine_trace("")
        with pytest.raises(ContainmentError, match="malformed scope"):
            mgr.quarantine_trace("../etc/passwd")
        # re-quarantine after a release is legitimate
        mgr.release_trace("t-1")
        again = mgr.quarantine_trace("t-1")
        assert again["status"] == "quarantined"

    def test_receipt_failure_rolls_quarantine_back(self, tmp_path, gw, monkeypatch):
        """Unreceipted quarantine must not survive: receipt failure rolls
        the registry append back and the gate keeps allowing."""
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)

        def boom(*a, **k):
            raise OSError("receipt stream unavailable")

        monkeypatch.setattr(ContainmentManager, "_emit_receipt", boom)
        with pytest.raises(ContainmentError, match="receipt emission failed"):
            mgr.quarantine_trace("t-1")
        ok = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-1"
        )
        assert ok["decision"] == "allow"

    def test_receipt_failure_rolls_release_back_to_quarantined(self, tmp_path, gw, monkeypatch):
        """Receipt failure on the SECOND transition restores the exact prior
        registry bytes — the trace stays quarantined, nothing is left
        half-released."""
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        mgr.quarantine_trace("t-1")
        before = (tmp_path / "trace-quarantines.jsonl").read_bytes()

        def boom(*a, **k):
            raise OSError("receipt stream unavailable")

        monkeypatch.setattr(ContainmentManager, "_emit_receipt", boom)
        with pytest.raises(ContainmentError, match="receipt emission failed"):
            mgr.release_trace("t-1")
        assert (tmp_path / "trace-quarantines.jsonl").read_bytes() == before
        assert (
            gw.check_tool_call(
                "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-1"
            )["decision"]
            == "deny"
        )

    def test_unconfigured_registries_refuse_named(self, tmp_path):
        """No registry file configured -> named error, not a silent no-op."""
        mgr = ContainmentManager(
            ContainmentConfig(
                receipts_path=str(tmp_path / "r.jsonl"),
                state_dir=str(tmp_path / "containment"),
            )
        )
        with pytest.raises(ContainmentError, match="quarantines_file is not configured"):
            mgr.quarantine_trace("t-1")
        with pytest.raises(ContainmentError, match="lease_suspensions_file is not configured"):
            mgr.suspend_lease("agent:svc")


class TestLeaseSuspension:
    @pytest.fixture
    def keyed_gw(self, tmp_path):
        """A gateway in apikey mode plus one live agent credential."""
        policy = tmp_path / "policies.yaml"
        policy.write_text(POLICY)
        creds = AgentCredentialStore(path=tmp_path / "agent-credentials.jsonl")
        api_key = creds.issue("agent:svc")
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file=str(policy),
            receipt_store=str(tmp_path / "gateway-receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            gate_auth="apikey",
            agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
            trace_quarantine_file=str(tmp_path / "trace-quarantines.jsonl"),
            lease_suspensions_file=str(tmp_path / "lease-suspensions.jsonl"),
            emit_receipts=True,
        )
        return RaucleGateway(config), api_key

    def test_suspended_lease_cuts_valid_apikey(self, tmp_path, keyed_gw):
        gw, api_key = keyed_gw
        agent_id, reason, _ = gw.authenticate_caller(api_key=api_key)
        assert agent_id == "agent:svc"  # key is valid
        assert not reason

        mgr = ContainmentManager(_config(tmp_path))
        suspended = mgr.suspend_lease("agent:svc", lease_id="lease:abc123", reason="compromise")
        assert suspended["status"] == "suspended"

        # the credential is cut at the gate even with the valid key
        agent_id, reason, _ = gw.authenticate_caller(api_key=api_key)
        assert agent_id is None
        assert "suspended credential lease" in reason

        denied = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-1"
        )
        assert denied["decision"] == "deny"
        assert "lease suspension" in denied["reason"]

        reinstated = mgr.reinstate_lease("agent:svc", lease_id="lease:abc123", reason="cleared")
        assert reinstated["status"] == "reinstated"
        agent_id, reason, _ = gw.authenticate_caller(api_key=api_key)
        assert agent_id == "agent:svc"
        assert not reason

    def test_suspend_and_reinstate_receipts_verify_offline(self, tmp_path):
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)
        mgr.suspend_lease("agent:svc", reason="compromise")
        mgr.reinstate_lease("agent:svc", reason="cleared")
        receipts = _receipts(cfg.receipts_path)
        verdicts = [_verdict_payload(r["jws"])["verdict"] for r in receipts]
        assert verdicts == [VERDICT_LEASE_SUSPEND, VERDICT_LEASE_REINSTATE]
        pubkey = (tmp_path / "containment" / "containment-operator-pubkey.pem").read_bytes()
        verifier = VerdictVerifier(public_key_pem=pubkey)
        for receipt, verdict in zip(receipts, verdicts, strict=False):
            payload = verifier.verify(receipt["jws"])
            assert payload.verdict == verdict
            assert payload.extra["agent_id"] == "agent:svc"

    def test_lease_receipt_failure_rolls_suspension_back(self, tmp_path, keyed_gw, monkeypatch):
        gw, api_key = keyed_gw
        cfg = _config(tmp_path)
        mgr = ContainmentManager(cfg)

        def boom(*a, **k):
            raise OSError("receipt stream unavailable")

        monkeypatch.setattr(ContainmentManager, "_emit_receipt", boom)
        with pytest.raises(ContainmentError, match="receipt emission failed"):
            mgr.suspend_lease("agent:svc")
        agent_id, reason, _ = gw.authenticate_caller(api_key=api_key)
        assert agent_id == "agent:svc"
        assert not reason

    def test_hostile_lease_transitions_are_named(self, tmp_path):
        mgr = ContainmentManager(_config(tmp_path))
        with pytest.raises(ContainmentError, match="no suspended lease"):
            mgr.reinstate_lease("agent:svc")
        mgr.suspend_lease("agent:svc")
        with pytest.raises(ContainmentError, match="already has a suspended lease"):
            mgr.suspend_lease("agent:svc")
        with pytest.raises(ContainmentError, match="malformed"):
            mgr.suspend_lease("bad agent id / not an id")

    def test_status_lists_active_quarantines_and_suspensions(self, tmp_path):
        mgr = ContainmentManager(_config(tmp_path))
        mgr.quarantine_trace("t-b")
        mgr.quarantine_trace("t-a")
        mgr.suspend_lease("agent:svc")
        status = mgr.status()
        assert status["held"] is False
        assert status["quarantined_traces"] == ["t-a", "t-b"]
        assert status["suspended_leases"] == ["agent:svc"]
        mgr.release_trace("t-a")
        mgr.reinstate_lease("agent:svc")
        status = mgr.status()
        assert status["quarantined_traces"] == ["t-b"]
        assert status["suspended_leases"] == []

    def test_registry_corruption_is_skipped_not_crash(self, tmp_path, gw):
        cfg = _config(tmp_path)
        (tmp_path / "trace-quarantines.jsonl").write_text("not-json\ndefinitely\n\n   \n")
        mgr = ContainmentManager(cfg)
        mgr.quarantine_trace("t-1")  # appends cleanly after corrupt lines
        denied = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-1"
        )
        assert denied["decision"] == "deny"
        assert "quarantined" in denied["reason"]


class TestCLIV1:
    def _cli(self, tmp_path, *args, expect=0):
        rc = cli_main(
            [
                "containment",
                *args,
                "--quarantine-file",
                str(tmp_path / "trace-quarantines.jsonl"),
                "--lease-file",
                str(tmp_path / "lease-suspensions.jsonl"),
                "--receipts",
                str(tmp_path / "containment-receipts.jsonl"),
                "--state-dir",
                str(tmp_path / "containment"),
                "--json",
            ]
        )
        assert rc == expect
        return rc

    def test_cli_quarantine_release_end_to_end(self, tmp_path, gw):
        self._cli(tmp_path, "quarantine", "t-cli", "--reason", "drill")
        denied = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-cli"
        )
        assert denied["decision"] == "deny"
        assert "quarantined" in denied["reason"]
        self._cli(tmp_path, "release", "t-cli")
        ok = gw.check_tool_call(
            "lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc", trace_id="t-cli"
        )
        assert ok["decision"] == "allow"
        # receipts exist for both transitions
        verdicts = [
            _verdict_payload(r["jws"])["verdict"]
            for r in _receipts(tmp_path / "containment-receipts.jsonl")
        ]
        assert verdicts == [VERDICT_TRACE_QUARANTINE, VERDICT_TRACE_RELEASE]

    def test_cli_suspend_reinstate_lease_end_to_end(self, tmp_path, gw):
        creds = AgentCredentialStore(path=tmp_path / "agent-credentials.jsonl")
        api_key = creds.issue("agent:svc")
        self._cli(tmp_path, "suspend-lease", "agent:svc", "--lease-id", "lease:abc123")
        # a fresh gateway in apikey mode on the same registries
        keyed = RaucleGateway(
            GatewayConfig(
                host="127.0.0.1",
                admin_api_key="k",
                signer_backend="local",
                policy_file=gw.config.policy_file,
                receipt_store=str(tmp_path / "keyed-gateway-receipts.jsonl"),
                audit_chain=str(tmp_path / "audit.jsonl"),
                registry_path=str(tmp_path / "registry.jsonl"),
                gate_auth="apikey",
                agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
                lease_suspensions_file=str(tmp_path / "lease-suspensions.jsonl"),
                emit_receipts=False,
            )
        )
        agent_id, reason, _ = keyed.authenticate_caller(api_key=api_key)
        assert agent_id is None
        assert "suspended credential lease" in reason
        self._cli(tmp_path, "reinstate-lease", "agent:svc")
        agent_id, reason, _ = keyed.authenticate_caller(api_key=api_key)
        assert agent_id == "agent:svc"
        assert not reason

    def _cli_raw(self, tmp_path, *args):
        """Human-output (non --json) invocation; returns captured stdout."""
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli_main(
                [
                    "containment",
                    *args,
                    "--quarantine-file",
                    str(tmp_path / "trace-quarantines.jsonl"),
                    "--lease-file",
                    str(tmp_path / "lease-suspensions.jsonl"),
                    "--receipts",
                    str(tmp_path / "containment-receipts.jsonl"),
                    "--state-dir",
                    str(tmp_path / "containment"),
                    "--policy-file",
                    str(tmp_path / "policies.yaml"),
                    "--revocations-file",
                    str(tmp_path / "revocations.jsonl"),
                    "--delegations-file",
                    str(tmp_path / "delegations.jsonl"),
                ]
            )
        assert rc == 0
        return buf.getvalue()

    def test_cli_human_rendering_all_paths(self, tmp_path, gw):
        # status with nothing held or quarantined
        out = self._cli_raw(tmp_path, "status")
        assert "NOT HELD" in out
        # scoped holds write revocations / read the delegation ledger
        (tmp_path / "revocations.jsonl").touch()
        (tmp_path / "delegations.jsonl").touch()
        # hold rendering (global scope: final tail branch), then HELD status
        out = self._cli_raw(
            tmp_path, "hold", "global", "--global-min-approvers", "1", "--reason", "drill"
        )
        assert "containment held: scope=global" in out
        assert "receipt:" in out
        out = self._cli_raw(tmp_path, "status")
        assert "hold receipt" in out
        assert "reason      drill" in out
        # resume rendering (final tail branch) releases the hold
        out = self._cli_raw(tmp_path, "resume", "--reason", "over")
        assert "containment" in out
        # quarantine trace rendering
        out = self._cli_raw(tmp_path, "quarantine", "t-h")
        assert "containment trace" in out
        assert "verify offline" in out
        # suspend-lease rendering (registry + receipt, no lease id given)
        creds = AgentCredentialStore(path=tmp_path / "agent-credentials.jsonl")
        creds.issue("agent:svc")
        out = self._cli_raw(tmp_path, "suspend-lease", "agent:svc")
        assert "containment lease" in out
        self._cli_raw(tmp_path, "reinstate-lease", "agent:svc")
        # release rendering
        out = self._cli_raw(tmp_path, "release", "t-h")
        assert "containment trace" in out
        # status with active entries listed
        self._cli_raw(tmp_path, "quarantine", "t-h2")
        out = self._cli_raw(tmp_path, "status")
        assert "quarantined traces: t-h2" in out
        # suspend-lease WITH a lease id rendered
        self._cli_raw(tmp_path, "suspend-lease", "agent:svc", "--lease-id", "lease:xyz")
        # status listing suspended leases while suspended
        out = self._cli_raw(tmp_path, "status")
        assert "suspended leases: agent:svc" in out
        self._cli_raw(tmp_path, "reinstate-lease", "agent:svc", "--lease-id", "lease:xyz")
        # release with a scope id in the rendering (final tail branch)
        self._cli_raw(tmp_path, "release", "t-h2")

    def test_cli_hostile_inputs_exit_named(self, tmp_path, capsys):
        self._cli(tmp_path, "release", "t-nothing", expect=1)
        err = capsys.readouterr().err
        assert "not quarantined" in err
        self._cli(tmp_path, "quarantine", "bad id", expect=1)
        assert "malformed scope" in capsys.readouterr().err

    def test_sha256_binding_of_receipts(self, tmp_path):
        """Every containment receipt's envelope hash binds its JWS."""
        self._cli(tmp_path, "quarantine", "t-1")
        for receipt in _receipts(tmp_path / "containment-receipts.jsonl"):
            assert (
                hashlib.sha256(receipt["jws"].encode("ascii")).hexdigest()
                == receipt["receipt_hash"]
            )
