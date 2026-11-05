"""Behaviour tests for raucle.export (red-team replay export).

Every test asserts an outcome: round-trip fidelity of saved datasets,
verdict-filter semantics, eviction invariants, and load-side tolerance.
"""

from __future__ import annotations

import json

import pytest

from raucle.export import AttackEntry, AttackLog, ExportFormat
from raucle.scanner import ScanResult


def _result(
    verdict: str,
    *,
    detected: bool | None = None,
    technique: str = "T1",
    categories: list[str] | None = None,
    rules: list[str] | None = None,
    confidence: float = 0.9,
    action: str = "ALLOW",
) -> ScanResult:
    if detected is None:
        detected = verdict != "CLEAN"
    return ScanResult(
        verdict=verdict,
        confidence=confidence,
        injection_detected=detected,
        categories=categories or ([verdict.lower()] if verdict != "CLEAN" else []),
        attack_technique=technique,
        layer_scores={"L1": confidence},
        matched_rules=rules or [f"RULE-{verdict}"],
        action=action,
    )


class TestVerdictFiltering:
    def test_default_min_verdict_drops_clean(self):
        log = AttackLog()
        assert log.record("benign", _result("CLEAN"), {"src": "unit"}) is False
        assert len(log) == 0

    def test_suspicious_is_recorded_under_default(self):
        log = AttackLog()
        assert log.record("susp", _result("SUSPICIOUS")) is True
        assert len(log) == 1

    def test_min_verdict_malicious_excludes_suspicious(self):
        log = AttackLog(min_verdict="MALICIOUS")
        log.record("susp", _result("SUSPICIOUS"))
        log.record("mal", _result("MALICIOUS"))
        assert len(log) == 1
        assert log._entries[0].prompt == "mal"

    def test_min_verdict_clean_records_everything(self):
        log = AttackLog(min_verdict="CLEAN")
        log.record("a", _result("CLEAN"))
        log.record("b", _result("SUSPICIOUS"))
        log.record("c", _result("MALICIOUS"))
        assert len(log) == 3

    def test_unknown_verdict_treated_as_below_default(self):
        log = AttackLog()
        assert log._should_record("WHATVER") is False

    def test_record_batch_counts_only_accepted(self):
        log = AttackLog()
        added = log.record_batch(
            ["c1", "s1", "m1"],
            [_result("CLEAN"), _result("SUSPICIOUS"), _result("MALICIOUS")],
            [{"run": "r1"}],
        )
        assert added == 2

    def test_batch_metadata_missing_entry_defaults_empty(self):
        log = AttackLog()
        log.record_batch(
            ["s1", "s2"], [_result("SUSPICIOUS"), _result("SUSPICIOUS")], [{"run": "r1"}]
        )
        assert [e.metadata for e in log] == [{"run": "r1"}, {}]

    def test_max_entries_evicts_oldest(self):
        log = AttackLog(max_entries=2)
        for i in range(4):
            log.record(f"p{i}", _result("MALICIOUS"))
        assert len(log) == 2
        assert [e.prompt for e in log] == ["p2", "p3"]


class TestStats:
    def test_empty_stats_is_total_zero(self):
        assert AttackLog().stats() == {"total": 0}

    def test_stats_aggregate_verdicts_categories_techniques_rules(self):
        log = AttackLog()
        log.record(
            "a", _result("MALICIOUS", technique="T1", categories=["injection"], rules=["R1"])
        )
        log.record("b", _result("MALICIOUS", technique="T2", categories=["exfil"], rules=["R2"]))
        s = log.stats()
        assert s["total"] == 2
        assert s["by_verdict"] == {"MALICIOUS": 2}
        assert s["top_categories"] == [("injection", 1), ("exfil", 1)]  # tie → insert order
        assert s["top_techniques"] == [("T1", 1), ("T2", 1)]
        assert s["top_rules"] == [("R1", 1), ("R2", 1)]  # tie → insert order

    def test_stats_top_lists_capped_at_ten(self):
        log = AttackLog()
        for i in range(12):
            log.record(f"p{i}", _result("MALICIOUS", rules=[f"R{i:02d}"]))
        assert len(log.stats()["top_rules"]) == 10

    def test_entry_without_technique_not_counted(self):
        log = AttackLog()
        log.record("a", _result("SUSPICIOUS", technique=""))
        s = log.stats()
        assert s["top_techniques"] == []


class TestSaveFormats:
    def _filled_log(self) -> AttackLog:
        log = AttackLog(min_verdict="CLEAN")
        log.record("clean-prompt", _result("CLEAN", technique=""))
        log.record(
            "attack-prompt",
            _result("MALICIOUS", categories=["injection"], rules=["R9"], action="BLOCK"),
        )
        return log

    def test_jsonl_round_trip(self, tmp_path):
        log = self._filled_log()
        out = tmp_path / "nested" / "raw.jsonl"  # parent dirs must be created
        written = log.save(out, ExportFormat.JSONL, include_clean=True)
        assert written == 2
        lines = [json.loads(line) for line in out.read_text().splitlines()]
        assert lines[0]["prompt"] == "clean-prompt"
        assert lines[1]["verdict"] == "MALICIOUS"
        assert lines[1]["action"] == "BLOCK"

        # Load must rebuild the same entries
        fresh = AttackLog()
        assert fresh.load(out) == 2
        assert fresh._entries[1].prompt == "attack-prompt"
        assert fresh._entries[1].result.matched_rules == ["R9"]

    def test_save_excludes_clean_by_default(self, tmp_path):
        out = tmp_path / "raw.jsonl"
        written = self._filled_log().save(out, ExportFormat.JSONL)
        assert written == 1
        assert json.loads(out.read_text().splitlines()[0])["prompt"] == "attack-prompt"

    def test_save_include_clean_keeps_all(self, tmp_path):
        out = tmp_path / "raw.jsonl"
        assert self._filled_log().save(out, include_clean=True) == 2

    def test_garak_format_fields(self, tmp_path):
        out = tmp_path / "garak.jsonl"
        assert self._filled_log().save(out, ExportFormat.GARAK) == 1
        rec = json.loads(out.read_text().splitlines()[0])
        assert rec["probe_classname"] == "raucle.injection"
        assert rec["prompt"] == "attack-prompt"
        assert rec["expected_result"] == "attack_detected"
        assert rec["notes"]["verdict"] == "MALICIOUS"
        assert rec["notes"]["rules"] == ["R9"]

    def test_pyrit_format_fields(self, tmp_path):
        out = tmp_path / "pyrit.jsonl"
        self._filled_log().save(out, ExportFormat.PYRIT)
        rec = json.loads(out.read_text().splitlines()[0])
        assert rec["role"] == "user"
        assert rec["labels"] == {"verdict": "malicious", "technique": "T1"}
        assert rec["prompt_metadata"]["source"] == "raucle"
        assert rec["prompt_metadata"]["matched_rules"] == ["R9"]

    def test_promptbench_label_is_injection_detected(self, tmp_path):
        log = AttackLog(min_verdict="CLEAN")
        log.record("c", _result("CLEAN"))
        log.record("m", _result("MALICIOUS"))
        out = tmp_path / "pb.json"
        assert log.save(out, ExportFormat.PROMPTBENCH, include_clean=True) == 2
        recs = json.loads(out.read_text())
        assert [r["label"] for r in recs] == [0, 1]
        assert recs[1]["metadata"]["verdict"] == "MALICIOUS"

    def test_load_skips_malformed_and_blank_lines(self, tmp_path):
        p = tmp_path / "messy.jsonl"
        good = {
            "prompt": "p",
            "verdict": "MALICIOUS",
            "confidence": 0.9,
            "injection_detected": True,
        }
        p.write_text(
            "\n"
            + json.dumps(good)
            + "\n"
            + "{not json}\n"
            + json.dumps({"prompt": "missing-verdict"})
            + "\n"
            + json.dumps(good)
            + "\n"
        )
        fresh = AttackLog()
        assert fresh.load(p) == 2

    def test_load_uses_optional_fields_with_defaults(self, tmp_path):
        p = tmp_path / "minimal.jsonl"
        p.write_text(
            json.dumps(
                {
                    "prompt": "p",
                    "verdict": "SUSPICIOUS",
                    "confidence": 0.5,
                    "injection_detected": True,
                }
            )
            + "\n"
        )
        fresh = AttackLog()
        assert fresh.load(p) == 1
        e = fresh._entries[0]
        assert e.result.categories == []
        assert e.result.action == "ALLOW"
        assert e.timestamp > 0

    def test_unknown_format_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Unknown export format"):
            self._filled_log().save(tmp_path / "x.bin", fmt="bogus")  # type: ignore[arg-type]


class TestAttackEntryDict:
    def test_to_dict_flattens_scan_result_fields(self):
        entry = AttackEntry(
            prompt="p", result=_result("MALICIOUS"), timestamp=123.0, metadata={"run": "r"}
        )
        d = entry.to_dict()
        assert d["prompt"] == "p"
        assert d["timestamp"] == 123.0
        assert d["metadata"] == {"run": "r"}
        assert d["verdict"] == "MALICIOUS"
        assert d["confidence"] == 0.9
