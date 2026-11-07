"""Containment receipt-stream head anchor (round-3 RED-029 / AV-12 fix).

The receipt stream is append-only by convention; RED-029 showed an
attacker with write access can erase receipt evidence undetected. The
SCITT-style head anchor (N2 machinery pattern) makes deletion /
truncation / rewrite detectable under its own name:

- ``receipt_stream_gap`` is raised on the next operator/containment action;
- ``status()`` surfaces ``receipt_integrity`` / ``receipt_stream_erased``.

Honest limit (documented, not claimed away): detection runs at the next
operator/containment action or status read — the detection-lag window.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from raucle.containment import (
    ContainmentConfig,
    ContainmentError,
    ContainmentManager,
    verify_receipt_stream_anchor,
)


def _config(tmp_path: pathlib.Path) -> ContainmentConfig:
    policies = tmp_path / "policies.yaml"
    if not policies.exists():
        policies.write_text("version: 1\nissuer: r3\npolicies:\n")
    return ContainmentConfig(
        policy_file=str(policies),
        revocations_file=str(tmp_path / "revocations.jsonl"),
        delegations_file=str(tmp_path / "delegations.jsonl"),
        receipts_path=str(tmp_path / "containment-receipts.jsonl"),
        state_dir=str(tmp_path / "state"),
        actor="operator",
    )


def _read_receipts(path: str | pathlib.Path) -> list[dict]:
    return [
        json.loads(line) for line in pathlib.Path(path).read_text().splitlines() if line.strip()
    ]


def test_every_emit_updates_the_head_anchor(tmp_path):
    cfg = _config(tmp_path)
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="global", reason="anchor-1")
    receipts = pathlib.Path(cfg.receipts_path)
    anchor = pathlib.Path(cfg.receipts_path + ".head")
    assert anchor.exists(), "the head anchor sidecar is written per emit"
    state = json.loads(anchor.read_text())
    assert state["count"] == len(_read_receipts(receipts))
    expected = state["stream_head"]
    head = "0" * 64
    for rec in _read_receipts(receipts):
        import hashlib

        head = hashlib.sha256((head + rec["receipt_hash"]).encode("ascii")).hexdigest()
    assert head == expected


def test_stream_deletion_is_detected_by_name_on_status(tmp_path):
    cfg = _config(tmp_path)
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="global", reason="anchor-2")
    pathlib.Path(cfg.receipts_path).unlink()
    status = mgr.status()
    assert status.get("held") is True, "hold state persists independently of the stream"
    assert status.get("receipt_integrity") is False
    assert status.get("receipt_stream_integrity") == "receipt_stream_gap"
    assert status.get("receipt_stream_erased") is True


def test_next_containment_action_refuses_the_gap_by_name(tmp_path):
    cfg = _config(tmp_path)
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="global", reason="anchor-3")
    pathlib.Path(cfg.receipts_path).unlink()
    with pytest.raises(ContainmentError, match=r"receipt_stream_gap|fail-closed") as excinfo:
        mgr.resume(reason="anchor-3-resume")
    # Composition note (rebase onto #201/#204/#210): with the stream FILE
    # deleted outright, the hold-authority machinery's earlier fail-closed
    # refusal ("receipt stream ... unavailable; fail-closed") fires before
    # the head-anchor check — the action is still refused by name either
    # way. The anchor machinery's distinct detection (truncation / rewrite
    # with the file present) is covered by the tests below.
    assert "receipt_stream_gap" in str(excinfo.value) or "fail-closed" in str(excinfo.value)


def test_truncation_and_middle_rewrite_are_detected(tmp_path):
    cfg = _config(tmp_path)
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="global", reason="anchor-4a")
    receipts = pathlib.Path(cfg.receipts_path)
    original = receipts.read_text()
    # truncation: count mismatch against the anchored head
    receipts.write_text("".join(original.splitlines(keepends=True)[:-1]))
    assert verify_receipt_stream_anchor(cfg.receipts_path)["receipt_stream_gap"] == (
        "truncated_or_rewritten"
    )
    # the next operator action refuses the gap by name (or, composed with
    # the #201/#210 hold machinery which loads the receipted hold first, by
    # its earlier fail-closed refusal binding the truncated hold receipt)
    with pytest.raises(ContainmentError, match=r"receipt_stream_gap|fail-closed"):
        mgr.resume(reason="anchor-4a-again")
    # a legitimate action over a restored stream re-anchors with the new receipt
    receipts.write_text(original)
    mgr.resume(reason="anchor-4a-restored")
    assert verify_receipt_stream_anchor(cfg.receipts_path)["receipt_stream_gap"] == "none"
    # middle substitution changes the folded head even with the same count
    rows = receipts.read_text().splitlines()
    rows[len(rows) // 2] = json.dumps({"receipt_hash": "f" * 64, "jws": "tampered"})
    receipts.write_text("\n".join(rows) + "\n")
    integrity = verify_receipt_stream_anchor(cfg.receipts_path)
    assert integrity["receipt_stream_gap"] == "truncated_or_rewritten"


def test_intact_stream_reports_intact_and_the_action_proceeds(tmp_path):
    cfg = _config(tmp_path)
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="global", reason="anchor-5")
    integrity = verify_receipt_stream_anchor(cfg.receipts_path)
    assert integrity["anchored"] is True and integrity["receipt_stream_gap"] == "none"
    status = mgr.status()
    assert status.get("receipt_integrity") is True
    assert status.get("receipt_stream_integrity") == "intact"


def test_unanchored_legacy_stream_is_reported_honestly(tmp_path):
    cfg = _config(tmp_path)
    legacy = tmp_path / "legacy-receipts.jsonl"
    legacy.write_text(json.dumps({"receipt_hash": "a" * 64, "jws": "legacy"}) + "\n")
    integrity = verify_receipt_stream_anchor(str(legacy))
    assert integrity["anchored"] is False, "no anchor exists: never a silent pass"
    assert integrity["receipt_stream_gap"] == "none"
    # legacy (pre-anchor) stream exists before the first emit: it is adopted
    # (anchored) on that emit and protected afterwards
    old = pathlib.Path(cfg.receipts_path)
    old.write_text(json.dumps({"receipt_hash": "a" * 64, "jws": "legacy"}) + "\n")
    assert not pathlib.Path(cfg.receipts_path + ".head").exists()
    mgr = ContainmentManager(cfg)
    mgr.hold(scope="global", reason="adopt-legacy")
    assert pathlib.Path(cfg.receipts_path + ".head").exists()
    # rewriting a historical receipt line no longer folds to the anchored head
    rows = old.read_text().splitlines()
    rows[0] = rows[0].replace("a" * 64, "b" * 64)
    old.write_text("\n".join(rows) + "\n")
    verify = verify_receipt_stream_anchor(cfg.receipts_path)
    assert verify["receipt_stream_gap"] == "truncated_or_rewritten"
    with pytest.raises(ContainmentError, match="receipt_stream_gap"):
        mgr.resume(reason="tamper-refused")
