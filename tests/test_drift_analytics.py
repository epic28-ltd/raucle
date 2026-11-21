"""I2: drift and scope-drift analytics over receipts.

Deterministic reads over a receipt store (chain JSONL or segmented store
directory). Every signal is evidence-shaped: the row cites the receipt
hashes it rests on, a signal that cannot cite its receipts is not
emitted, and bounded disclosure holds over the whole report - digests
and names only, never content.
"""

from __future__ import annotations

import base64
import contextlib
import json
from pathlib import Path

import pytest

from raucle import cli
from raucle.drift import collect_drift_signals
from raucle.provenance import _FORBIDDEN_FIELD_NAMES

# ---------------------------------------------------------------------------
# Seeded-store helpers: hand-shaped minimal envelopes, full control over
# ordering, digests and authority transitions (crafted drift patterns).
# ---------------------------------------------------------------------------

_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _line(payload: dict, receipt_hash: str) -> str:
    header = _b64({"alg": "EdDSA", "typ": "provenance-receipt/v1", "crit": ["raucle/v1"]})
    envelope = {"receipt_hash": receipt_hash, "jws": f"{header}.{_b64(payload)}.sig"}
    return json.dumps(envelope)


def _gate(
    iat: int,
    decision: str,
    *,
    tool: str = "export_records",
    agent_id: str = "agent:svc",
    reason: str = "",
    **x_gate_extra: object,
) -> dict:
    x_gate: dict[str, object] = {
        "decision": decision,
        "tool": tool,
        "agent_id": agent_id,
        "policy": "policies.yaml",
        "rule_id": "r1",
        "source": agent_id,
        "destination": tool,
        "latency_us": 10,
        "trace_id": "t1",
        "approval_id": "",
        "retention_until": 0,
    }
    if reason:
        x_gate["reason"] = reason
    x_gate.update(x_gate_extra)
    return {
        "iss": "raucle-detect/provenance",
        "iat": iat,
        "input_hash": "ab" * 32,
        "agent_id": "agent:gate",
        "guardrail_verdict": decision,
        "x_gate": x_gate,
    }


def _definition(digest: str, manifest: str = "/tools/manifest.json") -> dict:
    return {
        "version": "tool-definition/v1",
        "definition_digest": digest,
        "definition_manifest": manifest,
        "definition_vantage": "none",
    }


def _auth(capability_id: str, parent_id: str | None) -> dict:
    return {
        "capability_id": capability_id,
        "issuer": "demo.bank",
        "key_id": "k1",
        "parent_id": parent_id,
        "attenuated": parent_id is not None,
        "chain_digest": "sha256:" + "cd" * 32,
    }


def _revocation_v12(
    revoked_ids: list[str],
    *,
    iat: int,
    actor: str = "admin:ops",
    reason_class: str = "compromise",
    root: str | None = None,
) -> dict:
    block: dict[str, object] = {
        "version": "revocation/v1",
        "kind": "capability",
        "revoked_ids": revoked_ids,
        "revoked_hashes": {rid: "sha256:" + "ff" * 32 for rid in revoked_ids},
        "actor": actor,
        "reason_class": reason_class,
        "revoked_at": iat,
    }
    if root is not None:
        block["root"] = root
    return {"iss": "raucle-detect/provenance", "iat": iat, "agent_id": actor, "x_revocation": block}


def _revocation_v10(revoked_ids: list[str], *, iat: int, actor: str = "admin:ops") -> dict:
    return {
        "iss": "raucle-detect/provenance",
        "iat": iat,
        "agent_id": actor,
        "x_revocation": {
            "revoked_ids": revoked_ids,
            "root": revoked_ids[0],
            "actor": actor,
            "reason": "routine rotation",
        },
    }


def _write_chain(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _seeded_drift_chain(path: Path) -> Path:
    """One chain carrying every crafted pattern: a definition digest change,
    one widening and one narrowing authority transition, a deny-rate spike
    and a revocation cascade, plus one unparsable line."""
    lines: list[str] = [
        # definition drift: agent:analyst, export_records, AAAA -> BBBB
        _line(
            _gate(1000, "allow", agent_id="agent:analyst", tool_definition=_definition(_DIGEST_A)),
            "r-defn-a1",
        ),
        _line(
            _gate(1010, "allow", agent_id="agent:analyst", tool_definition=_definition(_DIGEST_A)),
            "r-defn-a2",
        ),
        _line(
            _gate(1020, "allow", agent_id="agent:analyst", tool_definition=_definition(_DIGEST_B)),
            "r-defn-b1",
        ),
        _line(
            _gate(1030, "allow", agent_id="agent:analyst", tool_definition=_definition(_DIGEST_B)),
            "r-defn-b2",
        ),
        # authority widening: agent:wide, attenuated child -> root grant
        _line(
            _gate(
                1100,
                "allow",
                agent_id="agent:wide",
                tool="wire_transfer",
                authorization=_auth("cap:child-1", "cap:root-wide"),
            ),
            "r-wide-child",
        ),
        _line(
            _gate(
                1110,
                "allow",
                agent_id="agent:wide",
                tool="wire_transfer",
                authorization=_auth("cap:root-9", None),
            ),
            "r-wide-root",
        ),
        # authority narrowing: agent:tight, root grant -> attenuated child
        _line(
            _gate(
                1200,
                "allow",
                agent_id="agent:tight",
                tool="wire_transfer",
                authorization=_auth("cap:root-2", None),
            ),
            "r-tight-root",
        ),
        _line(
            _gate(
                1210,
                "allow",
                agent_id="agent:tight",
                tool="wire_transfer",
                authorization=_auth("cap:child-2", "cap:root-2"),
            ),
            "r-tight-child",
        ),
    ]
    # deny-rate spike: agent:spike, four allows then four denies
    for i in range(4):
        lines.append(
            _line(_gate(1300 + i, "allow", agent_id="agent:spike", tool="query"), f"r-spike-a{i}")
        )
    for i in range(4):
        lines.append(
            _line(_gate(1400 + i, "deny", agent_id="agent:spike", tool="query"), f"r-spike-d{i}")
        )
    # revocation cascade: prior use of cap:root-1, revocation, later denies
    lines.append(
        _line(
            _gate(
                1500,
                "allow",
                agent_id="agent:rev-user",
                tool="query",
                authorization=_auth("cap:root-1", None),
            ),
            "r-use-1",
        )
    )
    lines.append(
        _line(
            _gate(
                1510,
                "allow",
                agent_id="agent:rev-user",
                tool="query",
                authorization=_auth("cap:root-1", None),
            ),
            "r-use-2",
        )
    )
    lines.append(_line(_revocation_v12(["cap:root-1"], iat=1520, root="cap:root-1"), "r-revoke"))
    lines.append(_line(_gate(1530, "deny", agent_id="agent:rev-user", tool="query"), "r-deny-1"))
    lines.append(_line(_gate(1540, "deny", agent_id="agent:rev-user", tool="query"), "r-deny-2"))
    # one unparsable line: counted honestly, never crashes the read
    lines.append("this is not json")
    return _write_chain(path, lines)


def _chain_hashes(chain: Path) -> set[str]:
    hashes = set()
    for line in chain.read_text(encoding="utf-8").splitlines():
        with contextlib.suppress(json.JSONDecodeError, KeyError):
            hashes.add(json.loads(line)["receipt_hash"])
    return hashes


def _signals_of(report: dict, name: str) -> list[dict]:
    return [row for row in report["signals"] if row["signal"] == name]


def _all_cited_hashes(report: dict) -> set[str]:
    """Every receipt hash any row cites, from any citation field."""
    cited: set[str] = set()

    def _walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("receipt", "from_receipt", "to_receipt", "revocation_receipt"):
                    cited.add(str(value))
                elif key in ("receipts", "denies", "prior_use_receipts", "post_denial_receipts"):
                    cited.update(str(item) for item in value)
                else:
                    _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    for row in report["signals"]:
        _walk(row)
    return cited


# ---------------------------------------------------------------------------
# Seeded patterns -> the named signals
# ---------------------------------------------------------------------------


def test_seeded_patterns_emit_the_named_signals(tmp_path):
    chain = _seeded_drift_chain(tmp_path / "receipts.jsonl")
    report = collect_drift_signals(chain)

    assert report["source_kind"] == "chain"
    assert report["gate_receipts"] == 20
    assert report["revocation_receipts"] == 1
    assert report["unparsable_lines"] == 1
    # 20 gate + 1 revocation = 21 readable receipts
    assert report["receipts_scanned"] == 21

    names = {row["signal"] for row in report["signals"]}
    assert names == {
        "definition-drift",
        "authority-widening",
        "authority-narrowing",
        "deny-rate-delta",
        "revocation-cascade",
    }
    assert report["signal_counts"] == {
        "definition-drift": 1,
        "authority-widening": 1,
        "authority-narrowing": 1,
        "deny-rate-delta": 1,
        "revocation-cascade": 1,
    }

    # every citation resolves in the chain
    hashes = _chain_hashes(chain)
    assert _all_cited_hashes(report) <= hashes
    assert _all_cited_hashes(report) == {
        # definition drift cites the two receipts either side of the change
        "r-defn-a2",
        "r-defn-b1",
        # authority transitions cite the last old-authority and first
        # new-authority receipt
        "r-wide-child",
        "r-wide-root",
        "r-tight-root",
        "r-tight-child",
        # the deny-rate windows cite every window receipt
        "r-spike-a0",
        "r-spike-a1",
        "r-spike-a2",
        "r-spike-a3",
        "r-spike-d0",
        "r-spike-d1",
        "r-spike-d2",
        "r-spike-d3",
        # the cascade cites the revocation, its prior uses and the later denies
        "r-revoke",
        "r-use-1",
        "r-use-2",
        "r-deny-1",
        "r-deny-2",
    }


def test_definition_drift_row_is_evidence_shaped(tmp_path):
    chain = _seeded_drift_chain(tmp_path / "receipts.jsonl")
    report = collect_drift_signals(chain)
    row = _signals_of(report, "definition-drift")[0]

    assert row["tool"] == "export_records"
    assert row["from_digest"] == _DIGEST_A
    assert row["to_digest"] == _DIGEST_B
    assert row["from_receipt"] == "r-defn-a2"
    assert row["to_receipt"] == "r-defn-b1"
    assert row["from_iat"] == 1010
    assert row["to_iat"] == 1020
    assert row["agents"] == ["agent:analyst"]
    assert row["manifest"] == "/tools/manifest.json"


def test_authority_widening_row_names_who_got_widened(tmp_path):
    chain = _seeded_drift_chain(tmp_path / "receipts.jsonl")
    report = collect_drift_signals(chain)
    row = _signals_of(report, "authority-widening")[0]

    assert row["agent_id"] == "agent:wide"
    assert row["from_capability"] == "cap:child-1"
    assert row["to_capability"] == "cap:root-9"
    assert row["from_attenuated"] is True
    assert row["to_attenuated"] is False
    assert row["from_receipt"] == "r-wide-child"
    assert row["to_receipt"] == "r-wide-root"
    assert row["chain_digest"] == "sha256:" + "cd" * 32


def test_authority_narrowing_row_cites_the_transition(tmp_path):
    chain = _seeded_drift_chain(tmp_path / "receipts.jsonl")
    report = collect_drift_signals(chain)
    row = _signals_of(report, "authority-narrowing")[0]

    assert row["agent_id"] == "agent:tight"
    assert row["from_capability"] == "cap:root-2"
    assert row["to_capability"] == "cap:child-2"
    assert row["from_attenuated"] is False
    assert row["to_attenuated"] is True


def test_deny_rate_delta_row_cites_both_windows(tmp_path):
    chain = _seeded_drift_chain(tmp_path / "receipts.jsonl")
    report = collect_drift_signals(chain)
    row = _signals_of(report, "deny-rate-delta")[0]

    assert row["agent_id"] == "agent:spike"
    assert row["delta"] == 1.0
    assert row["window_first"]["receipts"] == [
        "r-spike-a0",
        "r-spike-a1",
        "r-spike-a2",
        "r-spike-a3",
    ]
    assert row["window_first"]["denies"] == []
    assert row["window_first"]["deny_rate"] == 0.0
    assert row["window_second"]["receipts"] == [
        "r-spike-d0",
        "r-spike-d1",
        "r-spike-d2",
        "r-spike-d3",
    ]
    assert row["window_second"]["denies"] == [
        "r-spike-d0",
        "r-spike-d1",
        "r-spike-d2",
        "r-spike-d3",
    ]
    assert row["window_second"]["deny_rate"] == 1.0


def test_revocation_cascade_row_cites_prior_use_and_later_denies(tmp_path):
    chain = _seeded_drift_chain(tmp_path / "receipts.jsonl")
    report = collect_drift_signals(chain)
    row = _signals_of(report, "revocation-cascade")[0]

    assert row["revocation_receipt"] == "r-revoke"
    assert row["revoked_ids"] == ["cap:root-1"]
    assert row["root"] == "cap:root-1"
    assert row["actor"] == "admin:ops"
    assert row["reason_class"] == "compromise"
    assert row["kind"] == "capability"
    assert row["iat"] == 1520
    assert row["prior_use_receipts"] == ["r-use-1", "r-use-2"]
    assert row["prior_agents"] == ["agent:rev-user"]
    assert row["post_denial_receipts"] == ["r-deny-1", "r-deny-2"]


# ---------------------------------------------------------------------------
# Clean store -> zero signals, honest counts
# ---------------------------------------------------------------------------


def _clean_chain(path: Path) -> Path:
    """A quiet store: one tool, one stable definition digest, one root
    capability, steady allows. Nothing drifts."""
    lines: list[str] = []
    for i in range(6):
        lines.append(
            _line(
                _gate(
                    2000 + i,
                    "allow",
                    agent_id="agent:steady",
                    tool_definition=_definition(_DIGEST_A),
                    authorization=_auth("cap:root-steady", None),
                ),
                f"r-clean-{i}",
            )
        )
    return _write_chain(path, lines)


def test_clean_store_emits_zero_signals(tmp_path):
    chain = _clean_chain(tmp_path / "receipts.jsonl")
    report = collect_drift_signals(chain)

    assert report["signals"] == []
    assert report["signal_counts"] == {
        "definition-drift": 0,
        "authority-widening": 0,
        "authority-narrowing": 0,
        "deny-rate-delta": 0,
        "revocation-cascade": 0,
    }
    assert report["receipts_scanned"] == 6
    assert report["gate_receipts"] == 6
    assert report["unparsable_lines"] == 0
    assert report["verdict"].startswith("no drift signals over 6 receipts scanned")


def test_clean_real_gateway_chain_emits_zero_signals(tmp_path):
    """The reader parses gateway-minted receipts, not only synthetic ones:
    the I1 incident chain (two real allows) is a clean store."""
    from tests.test_counterfactual import _incident

    chain, _store = _incident(tmp_path)
    report = collect_drift_signals(chain)

    assert report["signals"] == []
    assert report["gate_receipts"] >= 2
    assert report["unparsable_lines"] == 0


def test_empty_store_directory_is_an_honest_zero(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    report = collect_drift_signals(store)

    assert report["source_kind"] == "store"
    assert report["receipts_scanned"] == 0
    assert report["signals"] == []
    assert "no drift signals" in report["verdict"]


# ---------------------------------------------------------------------------
# Honest states: a signal that cannot cite its receipts is not emitted
# ---------------------------------------------------------------------------


def test_single_digest_occurrence_is_not_drift(tmp_path):
    lines = [
        _line(_gate(1000, "allow", tool_definition=_definition(_DIGEST_A)), "r-one"),
    ]
    chain = _write_chain(tmp_path / "receipts.jsonl", lines)
    report = collect_drift_signals(chain)
    assert _signals_of(report, "definition-drift") == []


def test_same_width_capability_rotation_is_not_a_signal(tmp_path):
    """A switch between two attenuated children is rotation, not widening
    or narrowing: the agent's authority width did not change."""
    lines = [
        _line(_gate(1000, "allow", authorization=_auth("cap:child-a", "cap:root-1")), "r-rot-1"),
        _line(_gate(1010, "allow", authorization=_auth("cap:child-b", "cap:root-1")), "r-rot-2"),
    ]
    chain = _write_chain(tmp_path / "receipts.jsonl", lines)
    report = collect_drift_signals(chain)
    assert _signals_of(report, "authority-widening") == []
    assert _signals_of(report, "authority-narrowing") == []


def test_deny_rate_below_the_window_floor_is_not_a_signal(tmp_path):
    """Three allows then three denies is a delta of 1.0, but each half
    carries fewer than the default four receipts: not enough evidence to
    call drift, so nothing is emitted."""
    lines = [
        _line(_gate(1000, "allow", agent_id="agent:small"), "r-s-0"),
        _line(_gate(1001, "allow", agent_id="agent:small"), "r-s-1"),
        _line(_gate(1002, "allow", agent_id="agent:small"), "r-s-2"),
        _line(_gate(1003, "deny", agent_id="agent:small"), "r-s-3"),
        _line(_gate(1004, "deny", agent_id="agent:small"), "r-s-4"),
        _line(_gate(1005, "deny", agent_id="agent:small"), "r-s-5"),
    ]
    chain = _write_chain(tmp_path / "receipts.jsonl", lines)
    report = collect_drift_signals(chain)
    assert _signals_of(report, "deny-rate-delta") == []

    # the floor is a parameter: lower it and the same store does drift
    report_lower = collect_drift_signals(chain, min_window=3)
    row = _signals_of(report_lower, "deny-rate-delta")[0]
    assert row["delta"] == 1.0
    assert len(row["window_first"]["receipts"]) == 3


def test_revocation_of_never_used_authority_is_not_a_cascade(tmp_path):
    lines = [
        _line(_revocation_v12(["cap:unused"], iat=1000), "r-revoke"),
        _line(
            _gate(
                1010, "allow", agent_id="agent:other", authorization=_auth("cap:elsewhere", None)
            ),
            "r-after",
        ),
    ]
    chain = _write_chain(tmp_path / "receipts.jsonl", lines)
    report = collect_drift_signals(chain)

    assert _signals_of(report, "revocation-cascade") == []
    assert report["revocation_receipts"] == 1


def test_receipt_without_a_hash_cannot_be_cited_so_no_signal(tmp_path):
    """An envelope with no receipt_hash cannot back a citation, so a
    definition change resting on it is not emitted. The receipt still
    counts as scanned (honest), but no row cites it."""
    header = _b64({"alg": "EdDSA"})
    payload = _gate(1000, "allow", tool_definition=_definition(_DIGEST_A))
    unhased = json.dumps({"jws": f"{header}.{_b64(payload)}.sig"})
    lines = [
        unhased,
        _line(_gate(1010, "allow", tool_definition=_definition(_DIGEST_B)), "r-cited"),
    ]
    chain = _write_chain(tmp_path / "receipts.jsonl", lines)
    report = collect_drift_signals(chain)

    assert _signals_of(report, "definition-drift") == []
    assert report["receipts_scanned"] == 2


# ---------------------------------------------------------------------------
# Bounded disclosure over the report
# ---------------------------------------------------------------------------


def test_no_content_value_ever_enters_the_report(tmp_path):
    """Denial reasons can quote constraint values, so they never enter the
    report. The seeded reason carries an account value; it must appear
    nowhere in the serialized body, and no row may carry a content-like
    field name at any depth."""
    lines = [
        _line(
            _gate(
                1000,
                "deny",
                agent_id="agent:leaky",
                reason="account=ACC-999 is outside the allowlist",
            ),
            "r-deny-leak",
        ),
        _line(_gate(1010, "allow", agent_id="agent:leaky"), "r-allow-leak"),
        _line(_gate(1020, "deny", agent_id="agent:leaky"), "r-deny-2"),
        _line(_gate(1030, "allow", agent_id="agent:leaky"), "r-allow-2"),
        _line(_gate(1040, "deny", agent_id="agent:leaky"), "r-deny-3"),
        _line(_gate(1050, "deny", agent_id="agent:leaky"), "r-deny-4"),
        _line(_gate(1060, "deny", agent_id="agent:leaky"), "r-deny-5"),
    ]
    chain = _write_chain(tmp_path / "receipts.jsonl", lines)
    report = collect_drift_signals(chain)
    blob = json.dumps(report)

    assert "ACC-999" not in blob
    assert "allowlist" not in blob

    # the report is a bounded-disclosure surface: no content-like field
    # name anywhere in any row, at any depth
    stack: list[object] = list(report["signals"])
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                assert key not in _FORBIDDEN_FIELD_NAMES
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)


# ---------------------------------------------------------------------------
# Byte shapes: omit-when-absent, determinism
# ---------------------------------------------------------------------------


def test_optional_fields_are_omitted_not_nulled(tmp_path):
    """The v1.0 revocation shape carries no version/kind/reason_class, and
    the row omits them entirely (byte shape: omit-when-absent, never a
    null placeholder)."""
    lines = [
        _line(
            _gate(1000, "allow", agent_id="agent:old", authorization=_auth("cap:old-root", None)),
            "r-old-use",
        ),
        _line(_revocation_v10(["cap:old-root"], iat=1010), "r-old-revoke"),
        _line(_gate(1020, "deny", agent_id="agent:old"), "r-old-deny"),
    ]
    chain = _write_chain(tmp_path / "receipts.jsonl", lines)
    report = collect_drift_signals(chain)
    row = _signals_of(report, "revocation-cascade")[0]

    assert "reason_class" not in row
    assert "kind" not in row
    assert row["root"] == "cap:old-root"
    assert row["prior_use_receipts"] == ["r-old-use"]
    assert row["post_denial_receipts"] == ["r-old-deny"]


def test_definition_drift_without_manifest_omits_the_field(tmp_path):
    defn = _definition(_DIGEST_A, manifest="")
    defn.pop("definition_manifest")
    lines = [
        _line(_gate(1000, "allow", tool_definition=defn), "r-m-1"),
        _line(_gate(1010, "allow", tool_definition=_definition(_DIGEST_B, manifest="")), "r-m-2"),
    ]
    chain = _write_chain(tmp_path / "receipts.jsonl", lines)
    report = collect_drift_signals(chain)
    row = _signals_of(report, "definition-drift")[0]

    assert "manifest" not in row


def test_report_is_deterministic(tmp_path):
    chain = _seeded_drift_chain(tmp_path / "receipts.jsonl")
    first = collect_drift_signals(chain)
    second = collect_drift_signals(chain)
    assert json.dumps(first, indent=2) == json.dumps(second, indent=2)


# ---------------------------------------------------------------------------
# Segmented store directories
# ---------------------------------------------------------------------------


def test_segmented_store_reads_segments_in_order(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    seg_one = [
        _line(_gate(1000, "allow", tool_definition=_definition(_DIGEST_A)), "r-seg-1"),
    ]
    seg_two = [
        _line(_gate(1010, "allow", tool_definition=_definition(_DIGEST_B)), "r-seg-2"),
    ]
    (store / "seg-000001.jsonl").write_text("\n".join(seg_one) + "\n", encoding="utf-8")
    (store / "seg-000002.jsonl").write_text("\n".join(seg_two) + "\n", encoding="utf-8")
    # sidecar metadata never enters the receipt stream
    (store / "seg-000001.jsonl.meta").write_text('{"receipt_count": 1}\n', encoding="utf-8")

    report = collect_drift_signals(store)

    assert report["source_kind"] == "store"
    assert report["receipts_scanned"] == 2
    row = _signals_of(report, "definition-drift")[0]
    assert row["from_receipt"] == "r-seg-1"
    assert row["to_receipt"] == "r-seg-2"


def test_missing_source_is_a_named_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        collect_drift_signals(tmp_path / "does-not-exist.jsonl")


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def _run_cli(capsys, *argv: str) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_drift_writes_the_report(tmp_path, capsys):
    chain = _seeded_drift_chain(tmp_path / "receipts.jsonl")
    out = tmp_path / "drift-report.json"

    code, out_text, err_text = _run_cli(capsys, "analytics", "drift", str(chain), "--out", str(out))

    assert code == 0
    assert err_text == ""
    assert "drift report written to" in out_text
    report = json.loads(out.read_text(encoding="utf-8"))
    assert len(report["signals"]) == 5


def test_cli_drift_prints_json_to_stdout(tmp_path, capsys):
    chain = _clean_chain(tmp_path / "receipts.jsonl")
    code, out_text, err_text = _run_cli(capsys, "analytics", "drift", str(chain))
    assert code == 0
    report = json.loads(out_text)
    assert report["signals"] == []


def test_cli_drift_missing_source_exits_one(tmp_path, capsys):
    code, out_text, err_text = _run_cli(capsys, "analytics", "drift", str(tmp_path / "nope.jsonl"))
    assert code == 1
    assert "error:" in err_text


def test_cli_analytics_without_subcommand_exits_two(capsys):
    code, _out, err_text = _run_cli(capsys, "analytics")
    assert code == 2
    assert "subcommand" in err_text


def test_cli_drift_window_floor_is_a_flag(tmp_path, capsys):
    """The deny-rate window floor is a CLI knob so the report's evidence
    bar is operator-visible, never a hidden constant."""
    lines = [
        _line(_gate(1000, "allow", agent_id="agent:a"), "r-w-0"),
        _line(_gate(1001, "allow", agent_id="agent:a"), "r-w-1"),
        _line(_gate(1002, "allow", agent_id="agent:a"), "r-w-2"),
        _line(_gate(1003, "deny", agent_id="agent:a"), "r-w-3"),
        _line(_gate(1004, "deny", agent_id="agent:a"), "r-w-4"),
        _line(_gate(1005, "deny", agent_id="agent:a"), "r-w-5"),
    ]
    chain = _write_chain(tmp_path / "receipts.jsonl", lines)

    default_report = json.loads(_run_cli(capsys, "analytics", "drift", str(chain))[1])
    assert _signals_of(default_report, "deny-rate-delta") == []

    lowered_report = json.loads(
        _run_cli(capsys, "analytics", "drift", str(chain), "--min-window", "3")[1]
    )
    assert len(_signals_of(lowered_report, "deny-rate-delta")) == 1
