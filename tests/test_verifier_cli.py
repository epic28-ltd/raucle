"""Fail-closed regression tests for the offline verifier CLI (issue #346).

Covers the auditor-facing console entry point, the additive ``--json``
versioned report on ``raucle provenance verify``, the stable exit-code
contract and the adversarial classes from ADR 0011 §5: tampering,
downgrade attempts, unknown versions/algorithms/critical headers, missing
trust material, empty bundles and offline execution with networking made
unavailable (patched sockets).

Hybrid (raucle/pq1) tests skip automatically when the runtime's
cryptography build has no ML-DSA support, mirroring tests/test_pq.py.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import socket
from pathlib import Path

import pytest

from raucle import verifier_cli
from raucle.cli import main as raucle_main
from raucle.pq import (
    pq_available,
    pq_key_id_from_public_key,
    pq_public_key_from_pem,
    pq_public_key_pem,
)
from raucle.provenance import AgentIdentity, ProvenanceLogger

PQ_OK = pq_available()

# ---------------------------------------------------------------------------
# Shared chain builders
# ---------------------------------------------------------------------------


def _statement_file(tmp_path: Path, identity: AgentIdentity) -> Path:
    stmt = tmp_path / f"{identity.agent_id.replace(':', '_')}-capability.json"
    stmt.write_text(json.dumps(identity.statement.to_dict()), encoding="utf-8")
    return stmt


def _two_receipt_chain(tmp_path: Path) -> tuple[AgentIdentity, Path, Path]:
    """Root + model_call chain built with a single logger (correct parents)."""
    identity = AgentIdentity.generate(agent_id="agent:vcli2")
    chain = tmp_path / "chain2.jsonl"
    with ProvenanceLogger(agent=identity, sink_path=chain) as log:
        root = log.record_user_input(text="hello world")
        log.record_model_call(
            parents=[root], input_text="q", output_text="a", model="claude-sonnet-4-6"
        )
    stmt = _statement_file(tmp_path, identity)
    return identity, chain, stmt


def _run_json(argv: list[str]) -> tuple[int, dict]:
    """Run the auditor CLI in --json mode; return (exit_code, parsed body)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = verifier_cli.main(argv)
    return code, json.loads(buf.getvalue())


def _rewrite_jws(
    record: dict, mut_header=None, mut_payload=None, *, new_segments: list[str] | None = None
) -> str:
    """Re-encode a receipt's JWS after mutating its header or payload."""
    if new_segments is not None:
        record["jws"] = ".".join(new_segments)
        return json.dumps(record)
    parts = record["jws"].split(".")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    if mut_header is not None:
        mut_header(header)
    if mut_payload is not None:
        mut_payload(payload)
    parts[0] = (
        base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        .decode()
        .rstrip("=")
    )
    parts[1] = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        .decode()
        .rstrip("=")
    )
    record["jws"] = ".".join(parts)
    return json.dumps(record)


# ---------------------------------------------------------------------------
# Verified chains and the versioned output contract
# ---------------------------------------------------------------------------


class TestAuditorCliContract:
    def test_valid_chain_verifies_with_stable_exit(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        code, body = _run_json([str(chain), "--trust-roots", str(stmt), "--json"])
        assert code == 0
        assert body["verdict"] == "verified"
        assert body["invalid"] is False
        assert body["exit_code"] == 0
        assert body["schema_version"] == "raucle.verify.report/v1"
        assert body["receipt_count"] == 2
        assert body["failure_reasons"] == []
        assert body["offline"] is True
        kinds = [(row["kind"], row["path"]) for row in body["checked_artifacts"]]
        assert ("chain", str(chain)) in kinds
        assert ("trust_root", str(stmt)) in kinds
        for row in body["checked_artifacts"]:
            assert row["sha256"].startswith("sha256:") and len(row["sha256"]) == 64 + 7
            assert row["bytes"] > 0

    def test_human_output_is_deterministic(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        outs = []
        for _ in range(2):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = verifier_cli.main([str(chain), "--trust-roots", str(stmt)])
            outs.append(buf.getvalue())
            assert code == 0
        assert outs[0] == outs[1]
        assert "verified" in outs[0]

    def test_json_output_is_deterministic(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        outs = []
        for _ in range(2):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = verifier_cli.main([str(chain), "--trust-roots", str(stmt), "--json"])
            outs.append((code, buf.getvalue()))
        assert outs[0] == outs[1]


class TestAuditorCliFailClosed:
    def test_missing_trust_root_for_referenced_key_fails_closed(self, tmp_path):
        identity, chain, _stmt = _two_receipt_chain(tmp_path)
        stranger = AgentIdentity.generate(agent_id="agent:stranger")
        stranger_stmt = _statement_file(tmp_path, stranger)
        code, body = _run_json([str(chain), "--trust-roots", str(stranger_stmt), "--json"])
        assert code == verifier_cli.EXIT_MISSING_TRUST_MATERIAL
        assert body["verdict"] == "missing_trust_material"
        classes = {r["class"] for r in body["failure_reasons"]}
        assert "missing_trust_material" in classes
        assert any(
            "no supplied trust root" in r["message"] and identity.key_id in r["message"]
            for r in body["failure_reasons"]
        )

    def test_tampered_payload_fails_closed(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        lines = chain.read_text().splitlines()
        tampered = _rewrite_jws(
            json.loads(lines[1]), mut_payload=lambda payload: payload.update(model="evil")
        )
        path = tmp_path / "tampered.jsonl"
        path.write_text("\n".join([lines[0], tampered]) + "\n")
        code, body = _run_json([str(path), "--trust-roots", str(stmt), "--json"])
        assert code == verifier_cli.EXIT_INVALID
        assert body["verdict"] == "invalid"
        classes = {r["class"] for r in body["failure_reasons"]}
        assert "tamper" in classes
        assert body["tampered_receipts"]

    def test_unknown_receipt_payload_version_fails_closed(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        lines = chain.read_text().splitlines()
        downgraded = _rewrite_jws(
            json.loads(lines[1]),
            mut_payload=lambda payload: payload.update(typ="provenance-receipt/v9"),
        )
        path = tmp_path / "v9.jsonl"
        path.write_text("\n".join([lines[0], downgraded]) + "\n")
        code, body = _run_json([str(path), "--trust-roots", str(stmt), "--json"])
        assert code == verifier_cli.EXIT_UNSUPPORTED_PROFILE
        assert body["verdict"] == "unsupported_profile"
        assert any("payload typ" in r["message"] for r in body["failure_reasons"])

    def test_unknown_jose_typ_fails_closed(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        lines = chain.read_text().splitlines()
        hostile = _rewrite_jws(
            json.loads(lines[1]),
            mut_header=lambda header: header.update(typ="provenance-receipt/v9"),
        )
        path = tmp_path / "badtyp.jsonl"
        path.write_text("\n".join([lines[0], hostile]) + "\n")
        code, body = _run_json([str(path), "--trust-roots", str(stmt), "--json"])
        assert code == verifier_cli.EXIT_UNSUPPORTED_PROFILE
        assert any("unexpected JOSE typ" in r["message"] for r in body["failure_reasons"])

    def test_unknown_algorithm_fails_closed(self, tmp_path):
        identity, chain, _stmt = _two_receipt_chain(tmp_path)
        lines = chain.read_text().splitlines()
        hostile = _rewrite_jws(
            json.loads(lines[1]), mut_header=lambda header: header.update(alg="RS256")
        )
        path = tmp_path / "badalg.jsonl"
        path.write_text("\n".join([lines[0], hostile]) + "\n")
        stmt = _statement_file(tmp_path, identity)
        code, body = _run_json([str(path), "--trust-roots", str(stmt), "--json"])
        assert code == verifier_cli.EXIT_UNSUPPORTED_PROFILE
        assert any("unexpected JWS alg" in r["message"] for r in body["failure_reasons"])

    def test_unknown_critical_header_fails_closed(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        lines = chain.read_text().splitlines()

        def add_unknown_crit(header: dict) -> None:
            header["crit"] = ["raucle/v1", "raucle/composite-v9"]

        hostile = _rewrite_jws(json.loads(lines[1]), mut_header=add_unknown_crit)
        path = tmp_path / "badcrit.jsonl"
        path.write_text("\n".join([lines[0], hostile]) + "\n")
        code, body = _run_json([str(path), "--trust-roots", str(stmt), "--json"])
        assert code == verifier_cli.EXIT_UNSUPPORTED_PROFILE
        assert any("unknown critical header" in r["message"] for r in body["failure_reasons"])

    def test_incomplete_chain_parent_link_fails_closed(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        lines = chain.read_text().splitlines()
        incomplete = tmp_path / "incomplete.jsonl"
        incomplete.write_text(lines[1] + "\n")
        code, body = _run_json([str(incomplete), "--trust-roots", str(stmt), "--json"])
        assert code == verifier_cli.EXIT_INVALID
        classes = {r["class"] for r in body["failure_reasons"]}
        assert "parent_link" in classes

    def test_empty_chain_fails_closed_under_versioned_contract(self, tmp_path):
        _identity, _chain, stmt = _two_receipt_chain(tmp_path)
        empty = tmp_path / "empty.jsonl"
        empty.write_text("")
        code, body = _run_json([str(empty), "--trust-roots", str(stmt), "--json"])
        assert code == verifier_cli.EXIT_INVALID
        assert body["verdict"] == "invalid"
        assert any(r["class"] == "empty_chain" for r in body["failure_reasons"])

    def test_empty_chain_legacy_behaviour_unchanged(self, tmp_path):
        """The legacy command keeps its pre-slice behaviour on an empty bundle."""
        empty = tmp_path / "empty.jsonl"
        empty.write_text("")
        identity = AgentIdentity.generate(agent_id="agent:legacy")
        stmt = _statement_file(tmp_path, identity)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = raucle_main(["provenance", "verify", str(empty), "--pubkeys", str(stmt)])
        assert code == 0

    def test_require_pq_rejects_classical_only_chain(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        code, body = _run_json([str(chain), "--trust-roots", str(stmt), "--require-pq", "--json"])
        assert code == verifier_cli.EXIT_POLICY_REQUIREMENT_UNMET
        assert body["verdict"] == "policy_requirement_unmet"
        assert body["require_pq"] is True
        assert any(
            "--require-pq failed" in r["message"] and "not a raucle/pq1 hybrid" in r["message"]
            for r in body["failure_reasons"]
        )

    def test_missing_chain_file_is_operational_error(self, tmp_path):
        _identity, _chain, stmt = _two_receipt_chain(tmp_path)
        gone = tmp_path / "gone.jsonl"
        code, body = _run_json([str(gone), "--trust-roots", str(stmt), "--json"])
        assert code == verifier_cli.EXIT_OPERATIONAL_ERROR
        assert body["verdict"] == "operational_error"

    def test_missing_trust_root_file_reports_error_without_json(self, tmp_path):
        _identity, chain, _stmt = _two_receipt_chain(tmp_path)
        gone = tmp_path / "gone.json"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = verifier_cli.main([str(chain), "--trust-roots", str(gone)])
        assert code == verifier_cli.EXIT_OPERATIONAL_ERROR
        assert "error:" in err.getvalue()


class TestAuditorCliOffline:
    def test_verification_runs_with_sockets_unavailable(self, tmp_path, monkeypatch):
        """Offline execution: every socket constructor/connection raises."""

        def _deny(*_args, **_kwargs):
            raise OSError("network disabled by test")

        monkeypatch.setattr(socket, "socket", _deny)
        monkeypatch.setattr(socket, "create_connection", _deny)
        monkeypatch.setattr(socket, "socketpair", _deny)
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        code, body = _run_json([str(chain), "--trust-roots", str(stmt), "--json"])
        assert code == 0
        assert body["verdict"] == "verified"


class TestParentCliAdditiveFlag:
    def test_json_flag_emits_versioned_report(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = raucle_main(
                ["provenance", "verify", str(chain), "--pubkeys", str(stmt), "--json"]
            )
        assert code == 0
        body = json.loads(out.getvalue())
        assert body["schema_version"] == "raucle.verify.report/v1"
        assert body["verdict"] == "verified"

    def test_legacy_format_json_output_is_unversioned_and_unchanged(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = raucle_main(
                ["provenance", "verify", str(chain), "--pubkeys", str(stmt), "--format", "json"]
            )
        assert code == 0
        body = json.loads(out.getvalue())
        assert "schema_version" not in body
        assert body["valid"] is True

    def test_default_table_output_unchanged(self, tmp_path):
        _identity, chain, stmt = _two_receipt_chain(tmp_path)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = raucle_main(["provenance", "verify", str(chain), "--pubkeys", str(stmt)])
        assert code == 0
        assert "VALID" in out.getvalue()


# ---------------------------------------------------------------------------
# Hybrid raucle/pq1 (skipped without ML-DSA support)
# ---------------------------------------------------------------------------


def _hybrid_chain(tmp_path: Path) -> tuple[AgentIdentity, Path, Path, str]:
    """A pq1 hybrid chain plus its statement and pq PEM files on disk."""
    identity = AgentIdentity.generate(agent_id="agent:vcli-pq")
    chain = tmp_path / "chain-pq.jsonl"
    with ProvenanceLogger(agent=identity, sink_path=chain, quantum_mode="strict") as log:
        root = log.record_user_input(text="quantum era")
        log.record_model_call(
            parents=[root], input_text="q", output_text="a", model="claude-sonnet-4-6"
        )
    pq_pub = log._hybrid.pq_private.public_key()
    stmt = _statement_file(tmp_path, identity)
    pq_pem = tmp_path / "pq.pem"
    pq_pem.write_text(pq_public_key_pem(pq_pub), encoding="ascii")
    kid = pq_key_id_from_public_key(pq_public_key_from_pem(pq_pem.read_text(encoding="ascii")))
    return identity, chain, stmt, kid


@pytest.mark.skipif(not PQ_OK, reason="ML-DSA-65 unavailable in this cryptography build")
class TestAuditorCliPqHybrid:
    def test_hybrid_chain_verifies_offline(self, tmp_path):
        _identity, chain, stmt, _kid = _hybrid_chain(tmp_path)
        code, body = _run_json(
            [
                str(chain),
                "--trust-roots",
                str(stmt),
                "--pq-keys",
                str(tmp_path / "pq.pem"),
                "--json",
            ]
        )
        assert code == 0
        assert body["verdict"] == "verified"
        assert body["profiles_observed"]["pq1"] == 2

    def test_require_pq_accepts_full_hybrid_chain(self, tmp_path):
        _identity, chain, stmt, _kid = _hybrid_chain(tmp_path)
        code, body = _run_json(
            [
                str(chain),
                "--trust-roots",
                str(stmt),
                "--pq-keys",
                str(tmp_path / "pq.pem"),
                "--require-pq",
                "--json",
            ]
        )
        assert code == 0
        assert body["verdict"] == "verified"

    def test_hybrid_without_pq_keys_fails_closed_no_silent_downgrade(self, tmp_path):
        _identity, chain, stmt, _kid = _hybrid_chain(tmp_path)
        code, body = _run_json([str(chain), "--trust-roots", str(stmt), "--json"])
        assert code == verifier_cli.EXIT_MISSING_TRUST_MATERIAL
        assert body["verdict"] == "missing_trust_material"
        assert any("no supplied ML-DSA-65 key" in r["message"] for r in body["failure_reasons"])

    def test_stripped_hybrid_signature_never_verifies_classically(self, tmp_path):
        """Field-stripping downgrade: 4-segment slot cut back to Ed25519 only.

        The canonical v1 path refuses receipts whose header still declares
        the pq1 profile; stripping here therefore fails closed and never
        yields a verified verdict.
        """
        _identity, chain, stmt, _kid = _hybrid_chain(tmp_path)
        lines = chain.read_text().splitlines()
        record = json.loads(lines[0])
        parts = record["jws"].split(".")
        # Current-emission pq1: the ONE signature slot carries Ed25519 (64 B)
        # followed by ML-DSA-65 (3309 B). Stripping the ML-DSA half is the
        # downgrade attempt; the truncated slot is re-encoded in place.
        slot = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        ed_only = base64.urlsafe_b64encode(slot[:64]).decode().rstrip("=")
        stripped = _rewrite_jws(record, new_segments=[parts[0], parts[1], ed_only])
        path = tmp_path / "stripped.jsonl"
        path.write_text(stripped + "\n")
        code, body = _run_json(
            [
                str(path),
                "--trust-roots",
                str(stmt),
                "--pq-keys",
                str(tmp_path / "pq.pem"),
                "--json",
            ]
        )
        assert code != 0
        assert body["verdict"] in ("invalid", "unsupported_profile")
        assert body["invalid"] is True
