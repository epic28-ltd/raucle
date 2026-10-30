"""Tests for compliance evidence packs (P4) — receipt chain -> framework controls."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("cryptography")

from raucle.audit import Ed25519Signer, HashChainSink  # noqa: E402
from raucle.compliance import (  # noqa: E402
    ControlStatus,
    build_report,
    extract_evidence,
    render_markdown,
    supported_frameworks,
)


def _chain(tmp_path, *, signed=True, allow=5, deny=2, scans=1, flagged=1, _name="chain.jsonl"):
    path = tmp_path / _name
    signer = Ed25519Signer.generate() if signed else None
    sink = HashChainSink(path, signer=signer)
    for _ in range(allow):
        sink.append(
            {"kind": "capability_receipt", "decision": "ALLOW", "tool": "t", "agent_id": "agent:a"}
        )
    for _ in range(deny):
        sink.append(
            {"kind": "capability_receipt", "decision": "DENY", "tool": "t", "agent_id": "agent:a"}
        )
    for i in range(scans):
        verdict = "MALICIOUS" if i < flagged else "CLEAN"
        sink.append({"kind": "scan", "verdict": verdict})
    sink.close()
    return path, signer


class TestEvidenceExtraction:
    def test_counts_decisions_and_scans(self, tmp_path):
        ev = extract_evidence(_chain(tmp_path, allow=5, deny=2, scans=3, flagged=2)[0])
        assert ev.decisions == 7 and ev.allow == 5 and ev.deny == 2
        assert ev.scans == 3 and ev.flagged_scans == 2
        assert ev.signed is True and ev.checkpoints >= 1

    def test_unsigned_chain_flagged(self, tmp_path):
        ev = extract_evidence(_chain(tmp_path, signed=False)[0])
        assert ev.signed is False


class TestReports:
    def test_all_frameworks_supported(self):
        # dora joined the registry on 30 Oct 2026 (E1b, the compliance pack)
        assert set(supported_frameworks()) == {
            "dora",
            "eu-ai-act",
            "iso-42001",
            "soc2",
        }

    def test_eu_ai_act_logging_satisfied_only_with_verified_signatures(self, tmp_path):
        path, signer = _chain(tmp_path)
        # With the operator key, signatures are authenticated -> SATISFIED.
        report = build_report(path, framework="eu-ai-act", public_key_pem=signer.public_key_pem())
        art12 = next(c for c in report.controls if c.id == "Art.12")
        assert art12.status == ControlStatus.SATISFIED
        assert "signatures verified" in art12.evidence

    def test_signed_chain_without_key_is_partial_not_satisfied(self, tmp_path):
        # Honesty (codex #4): a signed chain whose signatures were NOT authenticated
        # must NOT be claimed SATISFIED.
        path, _signer = _chain(tmp_path)
        report = build_report(path, framework="eu-ai-act")  # no pubkey
        art12 = next(c for c in report.controls if c.id == "Art.12")
        assert art12.status == ControlStatus.PARTIAL
        assert "NOT authenticated" in art12.evidence

    def test_tampered_chain_not_satisfied(self, tmp_path):
        # A forged/tampered chain must fail verification, never SATISFIED.
        path, _signer = _chain(tmp_path)
        lines = path.read_text().splitlines()
        lines[2] = lines[2].replace("ALLOW", "DENY")  # tamper an event
        bad = tmp_path / "bad.jsonl"
        bad.write_text("\n".join(lines) + "\n")
        report = build_report(bad, framework="eu-ai-act", public_key_pem=_signer.public_key_pem())
        art12 = next(c for c in report.controls if c.id == "Art.12")
        assert art12.status == ControlStatus.PARTIAL
        assert "FAILED verification" in art12.evidence

    def test_logging_downgraded_to_partial_when_unsigned(self, tmp_path):
        path, _ = _chain(tmp_path, signed=False)
        report = build_report(path, framework="eu-ai-act")
        art12 = next(c for c in report.controls if c.id == "Art.12")
        assert art12.status == ControlStatus.PARTIAL

    def test_soc2_access_control_partial_with_honest_scope(self, tmp_path):
        report = build_report(_chain(tmp_path)[0], framework="soc2")
        cc61 = next(c for c in report.controls if c.id == "CC6.1")
        assert cc61.status == ControlStatus.PARTIAL  # never overclaims full IAM
        assert "out of scope" in cc61.evidence

    def test_report_carries_disclaimer(self, tmp_path):
        report = build_report(_chain(tmp_path)[0], framework="iso-42001")
        assert "EVIDENCE MAP, not a conformance attestation" in report.to_dict()["disclaimer"]

    def test_unknown_framework_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="unknown framework"):
            build_report(_chain(tmp_path)[0], framework="hipaa")

    def test_markdown_renders_table_and_disclaimer(self, tmp_path):
        md = render_markdown(build_report(_chain(tmp_path)[0], framework="eu-ai-act"))
        assert "| Control | Status | Evidence |" in md
        assert "EVIDENCE MAP" in md
        assert "Art.12" in md

    def test_summary_counts(self, tmp_path):
        report = build_report(_chain(tmp_path)[0], framework="soc2")
        s = report.summary()
        assert s["SATISFIED"] + s["PARTIAL"] + s["OUT_OF_SCOPE"] == len(report.controls)


class TestCLI:
    def test_cli_report_markdown(self, tmp_path, capsys):
        from raucle.cli import main

        rc = main(["compliance", "report", str(_chain(tmp_path)[0]), "--framework", "eu-ai-act"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "Compliance evidence map" in out and "Art.12" in out

    def test_cli_report_json_to_file(self, tmp_path):
        from raucle.cli import main

        out = tmp_path / "report.json"
        rc = main(
            [
                "compliance",
                "report",
                str(_chain(tmp_path)[0]),
                "--framework",
                "soc2",
                "--format",
                "json",
                "--out",
                str(out),
            ]
        )
        assert rc == 0
        doc = json.loads(out.read_text())
        assert doc["framework"] == "soc2" and "controls" in doc and doc["summary"]

    def test_cli_unknown_framework_errors(self, tmp_path, capsys):
        from raucle.cli import main

        rc = main(["compliance", "report", str(_chain(tmp_path)[0]), "--framework", "pci"])
        assert rc == 2
        assert "supported" in capsys.readouterr().err


def test_monitoring_partial_when_unsigned(tmp_path):
    """Monitoring is not SATISFIED on an unauthenticated chain (codex re-review
    #1): unsigned anomaly signals are not authenticated evidence."""
    path, _ = _chain(tmp_path, signed=False, deny=2, scans=2, flagged=2)
    report = build_report(path, framework="soc2")
    cc72 = next(c for c in report.controls if c.id == "CC7.2")
    assert cc72.status == ControlStatus.PARTIAL
    assert "unauthenticated" in cc72.evidence.lower()


def test_iso_a83_partial_without_authenticated_signatures(tmp_path):
    """ISO A.8.3 requires authenticated signatures for SATISFIED, not just a
    declared-signed flag (codex re-review #2)."""
    path, signer = _chain(tmp_path)  # signed, but verify WITHOUT the key
    report = build_report(path, framework="iso-42001")
    a83 = next(c for c in report.controls if c.id == "A.8.3")
    assert a83.status == ControlStatus.PARTIAL
    # With the key, it authenticates -> SATISFIED.
    report2 = build_report(path, framework="iso-42001", public_key_pem=signer.public_key_pem())
    a83b = next(c for c in report2.controls if c.id == "A.8.3")
    assert a83b.status == ControlStatus.SATISFIED


def test_malformed_chain_is_unverifiable_not_crash(tmp_path):
    """A malformed/garbage chain file yields PARTIAL controls, never an exception
    (codex r6)."""
    bad = tmp_path / "garbage.jsonl"
    bad.write_text("{not json\nalso not json\n")
    report = build_report(bad, framework="eu-ai-act")  # must not raise
    assert all(c.status != ControlStatus.SATISFIED for c in report.controls)
