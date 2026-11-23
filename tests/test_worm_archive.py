"""H3: the WORM receipt archive (design docs/designs/worm-archive.md).

The design's contract, pinned test by test:

* Append-only refusal (design section 2): every key is written once; a
  rewrite at the same key is refused and is provably not the original
  because content addresses (SHA-256) ride in the object metadata and in
  the segment's parent linkage.
* Chained integrity (design section 2): the write log is a hash chain in
  a non-WORM metadata store that is rebuildable from the bucket;
  verification RECOMPUTES every object digest from the bytes on disk and
  never trusts a recorded hash.
* Disposal receipt binding (design section 3): the signed x_destruction
  receipt, the escrow reference and the re-anchored surviving chain are
  archived at disposal time; the destruction receipt's retention floor is
  the surviving chain's horizon; the WORM archive never deletes.
* Retention interplay (design section 3): the chain's archive horizon
  (latest x_gate.retention_until, G1's value) becomes the WORM
  RetainUntilDate, floored at the operator's configured minimum, the
  bucket default locks unstamped objects, retention extends but never
  shortens, and deletion needs both expiry and a cleared legal hold.
* Byte-shape pins: archived copies are byte-identical to the published
  artefacts; the pack's WORM leg never rewrites a member.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from raucle.audit import Ed25519Signer, HashChainSink
from raucle.records import build_destruction
from raucle.worm import (
    LocalWormStore,
    WormArchive,
    WormDeletionRefusedError,
    WormKeyExistsError,
    WormRetentionShortenedError,
    WormVersionMismatchError,
    chain_horizon,
)

MIN_DAYS = 30
#: Fixed epochs so retention math is assertable: mid-2026 base iat, and a
#: far horizon (2033) that always beats the operator floor.
IAT = 1782998400
HORIZON_2033 = 2003750400


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _mint_ledger_segment(
    tmp_path, *, rows: int = 3, retention_days: int = 0, name: str = "seg"
) -> Path:
    """A closed receipt-store segment in the gate's envelope shape: one
    Ed25519-signed {receipt_hash, jws} line per row, x_gate.retention_until
    stamped when retention_days > 0 (same shape as the G1/G3 fixtures)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from raucle.provenance import _canonical_json, _sha256_hex

    path = tmp_path / f"{name}.jsonl"
    ed = Ed25519PrivateKey.generate()
    pub = ed.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = _sha256_hex(pub)[:16]
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(rows):
            payload = {
                "iss": "raucle-gateway",
                "typ": "provenance-receipt/v1",
                "iat": IAT + i,
                "agent_id": "raucle:gateway",
                "agent_key_id": kid,
                "operation": "guardrail_scan",
                "parents": [],
                "taint": ["gate:observed"],
                "input_hash": _sha256_hex(f"args{i}".encode()),
                "ruleset_hash": _sha256_hex(b"policy"),
                "guardrail_verdict": "ALLOW",
                "x_gate": {
                    "decision": "ALLOW",
                    "reason": "policy allow",
                    "tool": "export_records",
                    "agent_id": "agent:svc",
                    "source": "",
                    "destination": "",
                    "policy": "",
                    "rule_id": "r1",
                    "acting_for": "",
                    "latency_us": 100,
                    "trace_id": "",
                    "approval_id": "",
                    "retention_until": (IAT + retention_days * 86400 if retention_days else 0),
                },
            }
            header = {
                "alg": "EdDSA",
                "typ": "provenance-receipt/v1",
                "kid": kid,
                "crit": ["raucle/v1"],
                "raucle/v1": "provenance",
            }
            signing_input = (
                f"{_b64u(_canonical_json(header))}.{_b64u(_canonical_json(payload))}".encode()
            )
            jws = f"{signing_input.decode('ascii')}.{_b64u(ed.sign(signing_input))}"
            receipt_hash = "sha256:" + _sha256_hex(jws.encode("ascii"))
            fh.write(json.dumps({"receipt_hash": receipt_hash, "jws": jws}) + "\n")
    return path


AUDIT_ROWS = [
    {
        "timestamp": "2026-10-01T09:00:00+00:00",
        "decision": "ALLOW",
        "tool": "export_records",
        "agent_id": "agent:svc",
        "retention_until": IAT,
    },
    {
        "timestamp": "2026-10-01T10:00:00+00:00",
        "decision": "DENY",
        "tool": "export_records",
        "agent_id": "agent:svc",
        "retention_until": IAT,
    },
    {
        "timestamp": "2026-10-02T09:00:00+00:00",
        "decision": "ALLOW",
        "tool": "export_records",
        "agent_id": "agent:svc",
        "retention_until": HORIZON_2033,
    },
    {
        "timestamp": "2026-10-02T11:00:00+00:00",
        "decision": "DENY",
        "tool": "export_records",
        "agent_id": "agent:svc",
        "retention_until": HORIZON_2033,
    },
]


def _audit_chain(tmp_path, rows=AUDIT_ROWS, name="audit") -> tuple[Path, Ed25519Signer]:
    path = tmp_path / f"{name}.jsonl"
    signer = Ed25519Signer.generate()
    with HashChainSink(path, signer=signer, checkpoint_every=2) as sink:
        for row in rows:
            sink.append(row)
    return path, signer


def _operator_key(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem


def _worm(tmp_path, *, min_retention_days: int = MIN_DAYS, name="raucle-archive-test"):
    store = LocalWormStore(tmp_path / name)
    return WormArchive(
        store,
        tenant="t",
        min_retention_days=min_retention_days,
        index_path=tmp_path / "index.jsonl",
    )


SPAN = {"first": "2026-10-05T09:00:00+00:00", "last": "2026-10-05T11:00:00+00:00"}


def _archive_segment(
    archive, path, *, seg_no=1, chain_slug="main", ledger_position=42, horizon=None, now=None
):
    return archive.archive_chain_segment(
        path,
        chain_slug=chain_slug,
        seg_no=seg_no,
        span=SPAN,
        ledger_position=ledger_position,
        horizon=horizon,
        now=now,
    )


# ---------------------------------------------------------------------------
# Append-only refusal and the key scheme
# ---------------------------------------------------------------------------


def test_segment_key_layout_and_write_metadata(tmp_path):
    """Design section 2: the key is
    chain/<tenant>/<year>/<month>/<chain-slug>/seg-<n>.jsonl and every write
    carries artifact type, chain slug, span, SHA-256, retention category
    and the ledger position it was cut from."""
    seg = _mint_ledger_segment(tmp_path, name="seg1")
    archive = _worm(tmp_path)
    record = _archive_segment(archive, seg)

    assert record["key"] == "chain/t/2026/10/main/seg-000001.jsonl"
    assert record["retention_category"] == "receipt_chain"
    assert record["artifact_type"] == "chain_segment"
    assert record["chain_slug"] == "main"
    assert record["span"] == SPAN
    assert record["ledger_position"] == 42
    import hashlib

    assert record["sha256"] == "sha256:" + hashlib.sha256(seg.read_bytes()).hexdigest()


def test_append_only_refuses_a_rewrite(tmp_path):
    """A key is written once. Different bytes at the same key are refused
    and the original on disk is untouched."""
    seg = _mint_ledger_segment(tmp_path, name="seg1")
    other = _mint_ledger_segment(tmp_path, rows=4, name="other")
    archive = _worm(tmp_path)
    record = _archive_segment(archive, seg)

    with pytest.raises(WormKeyExistsError) as exc:
        _archive_segment(archive, other)
    # provably not the original: the refusal names both content addresses
    assert record["sha256"] in str(exc.value)
    assert archive.store.get(record["key"], record["version_id"]) == seg.read_bytes()
    assert len(archive.inventory()) == 1


def test_identical_retry_is_idempotent(tmp_path):
    """Re-archiving the byte-identical segment is an idempotent retry: same
    version id, no second write in the log."""
    seg = _mint_ledger_segment(tmp_path, name="seg1")
    archive = _worm(tmp_path)
    first = _archive_segment(archive, seg)
    second = _archive_segment(archive, seg)

    assert second["idempotent"] is True
    assert second["version_id"] == first["version_id"]
    assert len(archive.inventory()) == 1
    assert archive.verify()["valid"] is True


def test_keys_never_escape_the_bucket(tmp_path):
    """The containment gate: a key with .. segments, backslashes or an
    absolute path is refused before any byte is written."""
    archive = _worm(tmp_path)
    data = b"{}"
    for bad in ("../escape.jsonl", "/abs/seg.jsonl", "chain\\t\\seg.jsonl", "a//b.jsonl"):
        with pytest.raises(ValueError, match="key"):
            archive.store.put(bad, data, retain_until=0)


# ---------------------------------------------------------------------------
# Chained integrity
# ---------------------------------------------------------------------------


def test_verify_recomputes_digests_never_trusting_recorded_hashes(tmp_path):
    """A payload edited after the fact keeps its recorded hash, so
    verification must RECOMPUTE each object's digest from the bytes on disk
    and name the object that diverges."""
    seg = _mint_ledger_segment(tmp_path, name="seg1")
    archive = _worm(tmp_path)
    record = _archive_segment(archive, seg)

    # bypass the API: edit the object in place
    target = Path(archive.store.root) / record["key"]
    target.write_bytes(seg.read_bytes() + b"tampered\n")

    report = archive.verify()
    assert report["valid"] is False
    assert report["objects_valid"] is False
    assert any(record["key"] in e for e in report["errors"])


def test_index_tamper_breaks_the_write_chain(tmp_path):
    """The write log is a hash chain: editing a recorded field without
    recomputing the entry hash fails verification with a named error."""
    seg = _mint_ledger_segment(tmp_path, name="seg1")
    archive = _worm(tmp_path)
    _archive_segment(archive, seg)

    lines = archive.index_path.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["ledger_position"] = 999  # the forgery: not what was written
    lines[0] = json.dumps(entry)
    archive.index_path.write_text("\n".join(lines) + "\n")

    report = archive.verify()
    assert report["valid"] is False
    assert report["index_chain_valid"] is False
    assert report["errors"]


def test_segment_parent_linkage_carries_the_content_address(tmp_path):
    """Design section 2: the content address rides in the segment's parent
    linkage, so seg 2 cites seg 1's digest and a rewritten seg 1 is
    provably not the original seg 2 was chained to."""
    seg1 = _mint_ledger_segment(tmp_path, name="seg1")
    seg2 = _mint_ledger_segment(tmp_path, rows=4, name="seg2")
    archive = _worm(tmp_path)
    first = _archive_segment(archive, seg1, seg_no=1)
    second = _archive_segment(archive, seg2, seg_no=2)

    assert second["parent_sha256"] == first["sha256"]
    assert first["parent_sha256"] == ""


def test_index_is_rebuildable_from_the_bucket(tmp_path):
    """Design section 2: the index lives in a non-WORM metadata store and
    is rebuildable from the bucket. Losing it loses nothing: the rebuilt
    write chain is the same chain."""
    seg1 = _mint_ledger_segment(tmp_path, name="seg1")
    seg2 = _mint_ledger_segment(tmp_path, rows=4, name="seg2")
    archive = _worm(tmp_path)
    _archive_segment(archive, seg1, seg_no=1)
    _archive_segment(archive, seg2, seg_no=2)
    original_hashes = [e["entry_hash"] for e in archive.inventory()]

    archive.index_path.unlink()
    count = archive.rebuild_index()

    assert count == 2
    assert [e["entry_hash"] for e in archive.inventory()] == original_hashes
    assert archive.verify()["valid"] is True


def test_reads_pin_a_version_id(tmp_path):
    """Design section 2: the read contract always pins a version ID, never
    latest. The version id is the content address, and a mismatched pin is
    refused with a named error."""
    seg = _mint_ledger_segment(tmp_path, name="seg1")
    archive = _worm(tmp_path)
    record = _archive_segment(archive, seg)

    assert record["version_id"] == record["sha256"]
    assert archive.store.get(record["key"], record["version_id"]) == seg.read_bytes()
    with pytest.raises(WormVersionMismatchError):
        archive.store.get(record["key"], "sha256:" + "00" * 32)


def test_reconcile_diffs_ledger_against_archive(tmp_path):
    """Design section 4: the runbook's reconciliation - diff the ledger's
    chain inventory against the archive object inventory, expect empty."""
    seg1 = _mint_ledger_segment(tmp_path, name="seg1")
    seg2 = _mint_ledger_segment(tmp_path, rows=4, name="seg2")
    archive = _worm(tmp_path)
    d1 = _archive_segment(archive, seg1, seg_no=1)["sha256"]
    d2 = _archive_segment(archive, seg2, seg_no=2)["sha256"]

    assert archive.reconcile([d1, d2]) == {
        "missing_from_archive": [],
        "not_in_ledger": [],
    }
    diff = archive.reconcile([d1])
    assert diff["not_in_ledger"] == [d2]
    diff = archive.reconcile([d1, d2, "sha256:" + "ff" * 32])
    assert diff["missing_from_archive"] == ["sha256:" + "ff" * 32]


# ---------------------------------------------------------------------------
# Retention interplay (G3/G1)
# ---------------------------------------------------------------------------


def test_horizon_derived_from_retention_stamps(tmp_path):
    """The chain's archive horizon (latest x_gate.retention_until) becomes
    the RetainUntilDate when it beats the operator floor."""
    seg = _mint_ledger_segment(tmp_path, retention_days=2555, name="seg1")
    assert chain_horizon(seg) == IAT + 2555 * 86400

    archive = _worm(tmp_path)
    record = _archive_segment(archive, seg)
    assert record["retain_until"] == IAT + 2555 * 86400


def test_operator_floor_applies_without_stamps(tmp_path):
    """No retention schedule in the chain: the object is still locked, at
    the operator's configured minimum."""
    seg = _mint_ledger_segment(tmp_path, name="seg1")
    assert chain_horizon(seg) == 0

    archive = _worm(tmp_path)
    record = _archive_segment(archive, seg, now=IAT)
    assert record["retain_until"] == IAT + MIN_DAYS * 86400


def test_floor_wins_when_the_horizon_is_shorter(tmp_path):
    """The horizon is floored at the operator minimum in both directions:
    a horizon inside the floor is raised to the floor."""
    seg = _mint_ledger_segment(tmp_path, name="seg1")
    archive = _worm(tmp_path)
    record = _archive_segment(archive, seg, horizon=IAT + 10 * 86400, now=IAT)
    assert record["retain_until"] == IAT + MIN_DAYS * 86400


def test_bucket_default_locks_objects_without_retention(tmp_path):
    """Design section 2: the bucket default retention (compliance mode)
    locks an object that arrives without explicit retention, satisfying
    the 24-hour control-application guidance."""
    seg = _mint_ledger_segment(tmp_path, name="seg1")
    store = LocalWormStore(tmp_path / "raucle-archive-test")
    archive = WormArchive(
        store, tenant="t", min_retention_days=0, index_path=tmp_path / "index.jsonl"
    )
    record = _archive_segment(archive, seg, now=IAT)
    assert record["retain_until"] == IAT + 24 * 3600


def test_retention_extends_but_never_shortens(tmp_path):
    """Object Lock allows extending a compliance-mode period, never
    shortening: exactly the permitted direction, enforced both ways."""
    seg = _mint_ledger_segment(tmp_path, retention_days=2555, name="seg1")
    archive = _worm(tmp_path)
    record = _archive_segment(archive, seg)

    archive.store.extend_retention(record["key"], new_until=record["retain_until"] + 86400)
    assert archive.store.head(record["key"])["retain_until"] == record["retain_until"] + 86400

    with pytest.raises(WormRetentionShortenedError):
        archive.store.extend_retention(record["key"], new_until=record["retain_until"])


def test_store_deletion_needs_expiry_and_a_cleared_hold(tmp_path):
    """Design section 1: deletion requires both the retention period
    expired and the hold cleared. The store primitive enforces both gates;
    the archive writer exposes no delete surface at all."""
    seg = _mint_ledger_segment(tmp_path, name="seg1")
    archive = _worm(tmp_path)
    record = _archive_segment(archive, seg, now=IAT)
    far_future = IAT + 10 * 365 * 86400

    with pytest.raises(WormDeletionRefusedError, match="retention"):
        archive.store.delete(record["key"], now=IAT + 1)

    archive.apply_legal_hold([record["key"]], actor="officer", reason="freeze", authority="FCA")
    with pytest.raises(WormDeletionRefusedError, match="hold"):
        archive.store.delete(record["key"], now=far_future)

    archive.release_legal_hold([record["key"]], actor="officer", reason="thaw")
    archive.store.delete(record["key"], now=far_future)
    assert not hasattr(WormArchive, "delete")


# ---------------------------------------------------------------------------
# Disposal receipt binding (G3)
# ---------------------------------------------------------------------------


def test_destruction_receipt_binds_the_surviving_chain(tmp_path):
    """Design section 3: the destruction receipt, the escrow reference and
    the re-anchored surviving chain are archived at disposal time; the
    destruction receipt's retention floor is the surviving chain's
    horizon; the archived receipt still verifies offline."""
    chain, _signer = _audit_chain(tmp_path)
    operator_pem = _operator_key(tmp_path)
    out = tmp_path / "disposal"
    manifest = build_destruction(
        chain,
        from_ts="2026-10-01T00:00:00+00:00",
        to_ts="2026-10-01T23:59:59+00:00",
        reason="annual review",
        actor="records-officer:craig",
        operator_key_pem=operator_pem,
        out_dir=out,
    )
    receipt_id = json.loads((out / "destruction.json").read_text())["receipt_hash"]

    archive = _worm(tmp_path)
    record = archive.archive_destruction(
        out, receipt_id=receipt_id, surviving_chain_path=out / "retained-chain.jsonl"
    )

    # the destruction receipt, written once at disposal time
    assert record["key"] == f"destruction/t/{receipt_id}/receipt.json"
    assert record["retention_category"] == "destruction_receipt"
    # the escrow reference rides in the archived record's metadata
    assert record["escrow_reference"]["record_count"] == manifest["record_count"]
    assert record["escrow_reference"]["span_digest"] == manifest["span_digest"]
    # the re-anchored surviving chain is archived beside it
    retained_key = f"destruction/t/{receipt_id}/retained-chain.jsonl"
    assert (
        archive.store.get(retained_key, archive.store.head(retained_key)["version_id"])
        == (out / "retained-chain.jsonl").read_bytes()
    )
    # retention floor: the horizon of the re-anchored surviving chain
    assert record["retain_until"] == HORIZON_2033

    # the archived copy is byte-identical and still verifies offline
    archived = archive.store.get(record["key"], record["version_id"])
    assert archived == (out / "destruction.json").read_bytes()
    from raucle.records import verify_destruction

    probe = tmp_path / "probe-destruction.json"
    probe.write_bytes(archived)
    report = verify_destruction(probe, escrow_path=out / "removed-records.jsonl")
    assert report["valid"] is True


def test_destruction_floor_applies_when_survivor_has_no_schedule(tmp_path):
    """A surviving chain with no retention stamps still locks the
    destruction receipt, at the operator floor."""
    chain, _signer = _audit_chain(
        tmp_path,
        rows=[{k: v for k, v in row.items() if k != "retention_until"} for row in AUDIT_ROWS],
    )
    operator_pem = _operator_key(tmp_path)
    out = tmp_path / "disposal"
    build_destruction(
        chain,
        from_ts="2026-10-01T00:00:00+00:00",
        to_ts="2026-10-01T23:59:59+00:00",
        reason="annual review",
        actor="records-officer:craig",
        operator_key_pem=operator_pem,
        out_dir=out,
    )
    receipt_id = json.loads((out / "destruction.json").read_text())["receipt_hash"]

    archive = _worm(tmp_path)
    record = archive.archive_destruction(
        out, receipt_id=receipt_id, surviving_chain_path=out / "retained-chain.jsonl", now=IAT
    )
    assert record["retain_until"] == IAT + MIN_DAYS * 86400


# ---------------------------------------------------------------------------
# The pack's WORM leg (design section 2: written once per pack publication)
# ---------------------------------------------------------------------------


def _build_pack(tmp_path) -> tuple[Path, dict]:
    from raucle.compliance_pack import build_pack

    chain, signer = _audit_chain(tmp_path, name="pack-chain")
    from cryptography.hazmat.primitives import serialization

    pub_pem = signer._private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pack_dir = tmp_path / "pack"
    manifest = build_pack(
        chain,
        framework="eu-ai-act",
        out_dir=pack_dir,
        verify_key_pem=pub_pem,
        operator_key_pem=_operator_key(tmp_path),
    )
    return pack_dir, manifest


def test_pack_publication_archives_byte_identical_bundle(tmp_path):
    """Design section 2: pack bundles plus the manifest, written once per
    pack publication; every member is byte-identical to the published
    bundle and retention is the same horizon as the chains they attest."""
    pack_dir, manifest = _build_pack(tmp_path)
    assert manifest["verifier_result"] == "valid"

    archive = _worm(tmp_path)
    record = archive.archive_pack(
        pack_dir, pack_id="p1", pack_manifest=manifest, horizon=HORIZON_2033
    )

    assert record["retention_category"] == "pack_bundle"
    assert record["retain_until"] == HORIZON_2033
    for member in sorted(pack_dir.iterdir()):
        if not member.is_file():
            continue
        key = f"pack/t/p1/{member.name}"
        version = archive.store.head(key)["version_id"]
        assert archive.store.get(key, version) == member.read_bytes()

    manifest_key = "pack/t/p1/manifest.json"
    archived_manifest = json.loads(
        archive.store.get(manifest_key, archive.store.head(manifest_key)["version_id"])
    )
    assert archived_manifest["pack_hash"] == manifest["pack_hash"]
    assert {m["name"] for m in archived_manifest["members"]} >= {
        "report.md",
        "coverage.json",
        "extracts.jsonl",
        "retention.json",
        "certificate.json",
    }

    # byte-identical republication is an idempotent retry
    again = archive.archive_pack(
        pack_dir, pack_id="p1", pack_manifest=manifest, horizon=HORIZON_2033
    )
    assert again["idempotent"] is True

    # a different bundle under the same pack id is refused (written once)
    (pack_dir / "report.md").write_text("rewritten report\n")
    with pytest.raises(WormKeyExistsError):
        archive.archive_pack(pack_dir, pack_id="p1", pack_manifest=manifest)


# ---------------------------------------------------------------------------
# Anchors and legal hold
# ---------------------------------------------------------------------------


def test_anchor_written_once_with_the_longest_covered_horizon(tmp_path):
    """Design section 2: anchors live at
    anchor/<tenant>/<chain-slug>/<horizon-date>.json, written once per
    anchoring run, retention the longest of the horizons they cover."""
    anchor = tmp_path / "anchor.json"
    anchor.write_text(
        json.dumps({"chain_slug": "main", "digest": "sha256:" + "ab" * 32, "mode": "internal"})
        + "\n"
    )
    archive = _worm(tmp_path)
    record = archive.archive_anchor(
        anchor, chain_slug="main", horizon_date="2027-04-07", horizon=HORIZON_2033
    )

    assert record["key"] == "anchor/t/main/2027-04-07.json"
    assert record["retention_category"] == "anchor"
    assert record["retain_until"] == HORIZON_2033

    # a second anchoring run for the same horizon date is a new artefact at
    # the same key: refused, because the key is written once
    anchor.write_text(json.dumps({"chain_slug": "main", "digest": "sha256:" + "cd" * 32}) + "\n")
    with pytest.raises(WormKeyExistsError):
        archive.archive_anchor(
            anchor, chain_slug="main", horizon_date="2027-04-07", horizon=HORIZON_2033
        )


def test_legal_hold_archives_its_own_decision(tmp_path):
    """Design section 3: a legal hold is an operator-plane event (who,
    when, why, authority), applied to the affected objects, and the
    decision itself is archived so the hold's provenance is on WORM too."""
    seg = _mint_ledger_segment(tmp_path, retention_days=2555, name="seg1")
    archive = _worm(tmp_path)
    record = _archive_segment(archive, seg)

    hold = archive.apply_legal_hold(
        [record["key"]], actor="records-officer:craig", reason="regulator freeze", authority="FCA"
    )

    assert archive.store.head(record["key"])["legal_hold"] is True
    decision = json.loads(archive.store.get(hold["key"], hold["version_id"]))
    assert decision["who"] == "records-officer:craig"
    assert decision["why"] == "regulator freeze"
    assert decision["authority"] == "FCA"
    assert decision["keys"] == [record["key"]]
    # the hold decision outlives what it holds
    assert hold["retain_until"] >= record["retain_until"]

    archive.release_legal_hold([record["key"]], actor="records-officer:craig", reason="thawed")
    assert archive.store.head(record["key"])["legal_hold"] is False
    assert archive.verify()["valid"] is True


def test_legal_hold_refuses_unknown_keys(tmp_path):
    archive = _worm(tmp_path)
    with pytest.raises(ValueError, match="unknown key"):
        archive.apply_legal_hold(
            ["chain/t/2026/10/main/seg-000001.jsonl"],
            actor="officer",
            reason="freeze",
            authority="FCA",
        )
