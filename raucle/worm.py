"""H3: the WORM receipt archive (design: docs/designs/worm-archive.md).

An append-only, hash-chained archive writer for receipt artefacts, with the
design's retention and disposal semantics wired to the records lifecycle
(G3, `raucle.records`). The archive is a PROJECTION, not a fork: the
operator's ledger remains the primary record, artefacts land at the
design's four moments (segment close, pack publication, disposal,
anchoring), and nothing in normal gate or mint operation requires the
archive (design section 6). The verifier never needs the archive online:
verification trusts signatures and hashes, and the archive's job is only
to preserve the raw objects so an export's inputs are provably pristine.

The storage seam: the design's primitive is S3 Object Lock in compliance
mode. `LocalWormStore` implements the same semantics in software (single
write per key, retention that extends but never shortens, deletion gated
on both expiry and a cleared legal hold, content-addressed version pins)
so CI can exercise every refusal path; a deployment swaps in an S3 Object
Lock backend behind the same operations. The non-WORM index (the write
log) is a hash chain in a sidecar file, rebuildable from the bucket alone
(design section 2: rebuildability is what keeps an accidental or
malicious rewrite detectable and correctable).

Key families follow the design's scheme: chain/<tenant>/<year>/<month>/
<chain-slug>/seg-<n>.jsonl, pack/<tenant>/<pack-id>/..., destruction/
<tenant>/<receipt-id>/..., anchor/<tenant>/<chain-slug>/<horizon-date>.json.
Legal hold decisions are archived too (design section 3: "the receipt of
the hold decision is itself archived"); the design names no key for them,
so they live under hold/<tenant>/<decision-id>/receipt.json, following
the destruction family's shape.

Retention is derived, not hand-tuned (design section 2): the chain's
archive horizon (the latest x_gate.retention_until any receipt claims,
G1's value) becomes the WORM RetainUntilDate, floored at the operator's
configured minimum; the bucket default locks objects that arrive with no
schedule at all. The WORM archive never deletes: disposal (G3) removes
records from the operator ledger, and the destruction receipt, the escrow
reference and the re-anchored surviving chain are what the archive keeps,
with the destruction receipt floored at the surviving chain's horizon.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

_HASH_PREFIX = "sha256:"

#: The bucket default retention (design section 2): an object that
#: arrives without an explicit retention period is still locked, which
#: satisfies the 24-hour control-application guidance.
DEFAULT_BUCKET_RETENTION_SECONDS = 24 * 3600


class WormKeyExistsError(ValueError):
    """A key is written once; different bytes at the same key are refused."""


class WormRetentionShortenedError(ValueError):
    """Compliance-mode retention extends, never shortens."""


class WormDeletionRefusedError(ValueError):
    """Deletion needs both the retention period expired and the hold cleared."""


class WormVersionMismatchError(ValueError):
    """The read contract pins a version ID, never latest."""


def _digest(data: bytes) -> str:
    return _HASH_PREFIX + hashlib.sha256(data).hexdigest()


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _int_stamp(value: Any) -> int:
    """Retention claims are integers, 0 meaning no schedule; a malformed
    claim fails the walk rather than being read as zero (the G3 rule)."""
    if value is None or value == "":
        return 0
    return int(value)


def _validate_key(key: str) -> str:
    """The containment gate for every object key: no empty segments, no
    traversal, no absolute paths, no backslashes. The bucket is the root."""
    if not isinstance(key, str) or not key:
        raise ValueError("archive key is empty")
    if key.startswith("/") or "\\" in key:
        raise ValueError(f"archive key rejected: {key!r}")
    for part in key.split("/"):
        if part in ("", ".", ".."):
            raise ValueError(f"archive key rejected: {key!r}")
    return key


def _decode_jws_payload(jws: str) -> dict[str, Any]:
    """Decode a receipt JWS payload (the middle segment), the same shape
    `raucle.records.verify_destruction` reads. Malformed material raises:
    the archive fails closed rather than archiving around a bad receipt."""
    import base64

    seg = jws.split(".")
    if len(seg) < 3:
        raise ValueError("destruction receipt carries no JWS")
    payload = json.loads(base64.urlsafe_b64decode(seg[1] + "=" * (-len(seg[1]) % 4)))
    if not isinstance(payload, dict):
        raise ValueError("destruction receipt payload is not an object")
    return payload


def chain_horizon(chain_path: str | Path) -> int:
    """The chain's archive horizon: the latest retention stamp any record
    in the chain claims (G1's `retimestamp_plan` value, generalised by H3
    into the WORM retention value). Walks both on-disk shapes: receipt
    ledger lines ({receipt_hash, jws}, the stamp in x_gate) and audit
    chain rows (the stamp on the event). Zero when nothing claims a
    schedule."""
    horizon = 0
    for line in Path(chain_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        jws = rec.get("jws")
        if isinstance(jws, str) and jws.count(".") >= 2:
            payload = _decode_jws_payload(jws)
            gate = payload.get("x_gate") or {}
            horizon = max(horizon, _int_stamp(gate.get("retention_until")))
            continue
        event = rec.get("event")
        if not isinstance(event, dict):
            event = rec
        horizon = max(horizon, _int_stamp(event.get("retention_until")))
    return horizon


class LocalWormStore:
    """The WORM bucket as a local directory: one data file per key, one
    .meta sidecar beside it carrying the write record, the effective
    retention and the legal hold state. The sidecar is the bucket's own
    metadata; the write log (the hash-chained index) lives outside the
    bucket in a non-WORM store and is rebuildable from these sidecars.

    Compliance-mode semantics enforced in software: a key is written once
    (byte-identical retries are idempotent, anything else is refused),
    retention extends but never shortens, and deletion requires both the
    retention period expired and the hold cleared.
    """

    def __init__(
        self, root: str | Path, *, default_retention_seconds: int = DEFAULT_BUCKET_RETENTION_SECONDS
    ) -> None:
        self.root = Path(root)
        self.default_retention_seconds = int(default_retention_seconds)

    # -- path helpers ------------------------------------------------------

    def _data_path(self, key: str) -> Path:
        root = self.root.resolve()
        target = (self.root / key).resolve()
        if not target.is_relative_to(root):
            raise ValueError(f"archive key escapes the bucket: {key!r}")
        return target

    def _meta_path(self, key: str) -> Path:
        return Path(f"{self._data_path(key)}.meta")

    # -- writes ------------------------------------------------------------

    def put(
        self,
        key: str,
        data: bytes,
        *,
        retain_until: int = 0,
        metadata: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Write once. An existing key accepts only the byte-identical
        content (an idempotent retry, optionally extending retention, the
        permitted direction); anything else raises WormKeyExistsError
        naming both content addresses, so a rewrite is provably not the
        original. A write without explicit retention locks at the bucket
        default."""
        key = _validate_key(key)
        now = int(time.time()) if now is None else int(now)
        sha = _digest(data)
        effective = int(retain_until) if retain_until else now + self.default_retention_seconds

        data_path = self._data_path(key)
        meta_path = self._meta_path(key)
        if data_path.exists() or meta_path.exists():
            existing = self.head(key)
            if existing["sha256"] == sha:
                if effective > existing["retain_until"]:
                    self.extend_retention(key, new_until=effective)
                    existing = self.head(key)
                return {**existing, "idempotent": True}
            raise WormKeyExistsError(
                f"archive key {key!r} already holds version {existing['version_id']} "
                f"({existing['sha256']}); the new content ({sha}) is provably not "
                f"the original: append-only, written once"
            )

        record = {
            "key": key,
            "version_id": sha,
            "sha256": sha,
            "retain_until": effective,
            "written_at": now,
            **(metadata or {}),
        }
        data_path.parent.mkdir(parents=True, exist_ok=True)
        with open(data_path, "wb") as fh:
            fh.write(data)
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "record": record,
                    "retain_until_effective": effective,
                    "legal_hold": False,
                },
                fh,
                indent=2,
                sort_keys=True,
            )
            fh.write("\n")
        return {**record, "idempotent": False}

    # -- reads -------------------------------------------------------------

    def _sidecar(self, key: str) -> dict[str, Any]:
        meta_path = self._meta_path(_validate_key(key))
        if not meta_path.is_file():
            raise FileNotFoundError(f"no archived object at key {key!r}")
        return json.loads(meta_path.read_text(encoding="utf-8"))

    def head(self, key: str) -> dict[str, Any]:
        """The live view of one object: the write record plus the current
        effective retention and hold state. `retain_until` is the value in
        force now; `retain_until_written` is what the write carried."""
        sidecar = self._sidecar(key)
        rec = dict(sidecar["record"])
        rec["retain_until_written"] = rec.pop("retain_until")
        rec["retain_until"] = int(sidecar["retain_until_effective"])
        rec["legal_hold"] = bool(sidecar["legal_hold"])
        return rec

    def get(self, key: str, version_id: str | None = None) -> bytes:
        """Read by pinned version. A version pin that does not match the
        stored content address is refused (the read contract pins a
        version ID, never latest)."""
        info = self.head(key)
        if version_id is not None and version_id != info["version_id"]:
            raise WormVersionMismatchError(
                f"version pin {version_id} does not match archived version "
                f"{info['version_id']} at key {key!r}"
            )
        return self._data_path(key).read_bytes()

    def list_objects(self) -> list[dict[str, Any]]:
        """Every object's live view, ordered by write sequence."""
        root = self.root.resolve()
        objects = []
        for meta_path in self.root.rglob("*.meta"):
            key = str(meta_path.resolve().relative_to(root))[: -len(".meta")]
            objects.append(self.head(key))
        return sorted(objects, key=lambda o: int(o.get("seq", 0)))

    def object_records(self) -> list[dict[str, Any]]:
        """Every sidecar's raw write record (the rebuild input), in write
        sequence order."""
        records = []
        for meta_path in self.root.rglob("*.meta"):
            sidecar = json.loads(meta_path.read_text(encoding="utf-8"))
            records.append(sidecar["record"])
        return sorted(records, key=lambda r: int(r.get("seq", 0)))

    # -- retention and hold ------------------------------------------------

    def extend_retention(self, key: str, *, new_until: int) -> dict[str, Any]:
        """Object Lock allows extending a compliance-mode period, never
        shortening: exactly the permitted direction."""
        sidecar = self._sidecar(key)
        effective = int(sidecar["retain_until_effective"])
        if int(new_until) < effective:
            raise WormRetentionShortenedError(
                f"compliance-mode retention extends but never shortens: key {key!r} "
                f"is locked until {effective}, refusing {int(new_until)}"
            )
        sidecar["retain_until_effective"] = int(new_until)
        with open(self._meta_path(key), "w", encoding="utf-8") as fh:
            json.dump(sidecar, fh, indent=2, sort_keys=True)
            fh.write("\n")
        return self.head(key)

    def set_legal_hold(self, key: str, *, held: bool) -> None:
        sidecar = self._sidecar(key)
        sidecar["legal_hold"] = bool(held)
        with open(self._meta_path(key), "w", encoding="utf-8") as fh:
            json.dump(sidecar, fh, indent=2, sort_keys=True)
            fh.write("\n")

    def delete(self, key: str, *, now: int | None = None) -> None:
        """The store primitive (S3 shape): deletion requires both the
        retention period expired and the hold cleared. The archive writer
        above this layer never deletes; disposal keeps its receipts."""
        now = int(time.time()) if now is None else int(now)
        info = self.head(key)
        if now < info["retain_until"]:
            raise WormDeletionRefusedError(
                f"retention has not expired at key {key!r}: locked until "
                f"{info['retain_until']}, now {now}"
            )
        if info["legal_hold"]:
            raise WormDeletionRefusedError(
                f"legal hold in place at key {key!r}: clear the hold before deletion"
            )
        self._data_path(key).unlink()
        self._meta_path(key).unlink()


class WormArchive:
    """The append-only, hash-chained archive writer (the projection).

    Every write lands through one path: derive the retention (horizon
    floored at the operator minimum), put the object once, append a
    hash-chained entry to the non-WORM write log. The log carries what
    the design requires on every archive write: artifact type, chain
    slug, span, SHA-256, retention category and the ledger position the
    artefact was cut from, plus the content-addressed version pin.
    """

    def __init__(
        self,
        store: LocalWormStore,
        *,
        tenant: str,
        min_retention_days: int = 0,
        index_path: str | Path,
    ) -> None:
        self.store = store
        self.tenant = _validate_key(str(tenant))
        self.min_retention_days = int(min_retention_days)
        self.index_path = Path(index_path)

    # -- the one write path -------------------------------------------------

    def _floor(self, now: int) -> int:
        return now + self.min_retention_days * 86400

    def _put(
        self,
        key: str,
        data: bytes,
        *,
        artifact_type: str,
        retention_category: str,
        chain_slug: str = "",
        span: dict[str, Any] | None = None,
        ledger_position: Any = 0,
        horizon: int = 0,
        extra: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        now = int(time.time()) if now is None else int(now)
        retain_until = int(horizon or 0)
        if self.min_retention_days > 0:
            retain_until = max(retain_until, self._floor(now))
        entries = self._entries()
        seq = len(entries) + 1
        record = {
            "artifact_type": artifact_type,
            "retention_category": retention_category,
            "chain_slug": chain_slug,
            "span": span,
            "ledger_position": ledger_position,
            "seq": seq,
            **(extra or {}),
        }
        rec = self.store.put(key, data, retain_until=retain_until, metadata=record, now=now)
        if rec.get("idempotent"):
            return rec
        # the write log entry is the write record itself (what the sidecar
        # holds), so a rebuilt index reproduces the same chain; the
        # idempotent flag is a per-call answer, not part of the record
        entry = {k: v for k, v in rec.items() if k != "idempotent"}
        entry["prev_hash"] = entries[-1]["entry_hash"] if entries else ""
        entry["entry_hash"] = _digest(_canon({k: v for k, v in entry.items() if k != "entry_hash"}))
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.index_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return rec

    # -- the design's four write moments ------------------------------------

    def archive_chain_segment(
        self,
        segment_path: str | Path,
        *,
        chain_slug: str,
        seg_no: int,
        span: dict[str, Any],
        ledger_position: Any,
        horizon: int | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Moment 1: the closed segment goes to the archive on rotation,
        self-contained JSONL at chain/<tenant>/<year>/<month>/<slug>/
        seg-<n>.jsonl. The horizon defaults to the chain's own (latest
        x_gate.retention_until); the content address of the previous
        segment in the family rides in as the parent linkage."""
        path = Path(segment_path)
        year, month = _span_year_month(span)
        if horizon is None:
            horizon = chain_horizon(path)
        key = f"chain/{self.tenant}/{year}/{month}/{chain_slug}/seg-{int(seg_no):06d}.jsonl"
        return self._put(
            key,
            path.read_bytes(),
            artifact_type="chain_segment",
            retention_category="receipt_chain",
            chain_slug=chain_slug,
            span=span,
            ledger_position=ledger_position,
            horizon=horizon,
            extra={"parent_sha256": self._last_segment_digest(chain_slug)},
            now=now,
        )

    def archive_pack(
        self,
        pack_dir: str | Path,
        *,
        pack_id: str,
        pack_manifest: dict[str, Any] | None = None,
        horizon: int | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Moment 2: on evidence-pack publication, the bundle and its
        manifest, written once per publication. Every member lands
        byte-identical; the archive-side manifest pins each member's
        content address and version. Retention is the same horizon as
        the chains the pack attests."""
        pdir = Path(pack_dir)
        if not pdir.is_dir():
            raise ValueError(f"pack bundle directory not found: {pdir}")
        members = sorted(m for m in pdir.iterdir() if m.is_file())
        if not members:
            raise ValueError(f"pack bundle directory holds no members: {pdir}")
        ledger_position = str(pack_manifest.get("chain_digest", "")) if pack_manifest else ""
        member_records = []
        for member in members:
            rec = self._put(
                f"pack/{self.tenant}/{pack_id}/{member.name}",
                member.read_bytes(),
                artifact_type="pack_bundle",
                retention_category="pack_bundle",
                ledger_position=ledger_position,
                horizon=horizon or 0,
                now=now,
            )
            member_records.append(
                {
                    "name": member.name,
                    "sha256": rec["sha256"],
                    "version_id": rec["version_id"],
                    "bytes": member.stat().st_size,
                }
            )
        manifest_body = {
            "pack_id": pack_id,
            "members": member_records,
            "pack_hash": pack_manifest.get("pack_hash") if pack_manifest else None,
            "verifier_result": pack_manifest.get("verifier_result") if pack_manifest else None,
        }
        manifest_bytes = json.dumps(manifest_body, indent=2, sort_keys=True).encode() + b"\n"
        return self._put(
            f"pack/{self.tenant}/{pack_id}/manifest.json",
            manifest_bytes,
            artifact_type="pack_manifest",
            retention_category="pack_bundle",
            ledger_position=ledger_position,
            horizon=horizon or 0,
            extra={"pack_id": pack_id},
            now=now,
        )

    def archive_destruction(
        self,
        destruction_dir: str | Path,
        *,
        receipt_id: str,
        surviving_chain_path: str | Path | None = None,
        surviving_chain_horizon: int | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Moment 3: on destruction, the signed x_destruction receipt
        (after disposition), the escrow reference and the re-anchored
        surviving chain. The WORM archive never deletes; the destruction
        receipt's retention floor is the horizon of the re-anchored
        surviving chain."""
        ddir = Path(destruction_dir)
        receipt_file = ddir / "destruction.json"
        escrow_file = ddir / "removed-records.jsonl"
        retained_file = ddir / "retained-chain.jsonl"
        for f in (receipt_file, escrow_file, retained_file):
            if not f.is_file():
                raise ValueError(f"destruction output incomplete: {f.name} is missing")
        block = _decode_jws_payload(
            json.loads(receipt_file.read_text(encoding="utf-8"))["jws"]
        ).get("x_destruction", {})
        if not isinstance(block, dict) or not block:
            raise ValueError("destruction receipt carries no x_destruction block")

        horizon = 0
        if surviving_chain_path is not None:
            horizon = max(horizon, chain_horizon(surviving_chain_path))
        if surviving_chain_horizon:
            horizon = max(horizon, int(surviving_chain_horizon))
        escrow_reference = {
            "sha256": _digest(escrow_file.read_bytes()),
            "record_count": block.get("record_count"),
            "span_digest": block.get("span_digest"),
            "first_hash": block.get("first_hash"),
            "last_hash": block.get("last_hash"),
        }
        rec = self._put(
            f"destruction/{self.tenant}/{receipt_id}/receipt.json",
            receipt_file.read_bytes(),
            artifact_type="destruction_receipt",
            retention_category="destruction_receipt",
            ledger_position=block.get("retained_count", 0) or 0,
            horizon=horizon,
            extra={"destruction": block, "escrow_reference": escrow_reference},
            now=now,
        )
        self._put(
            f"destruction/{self.tenant}/{receipt_id}/retained-chain.jsonl",
            retained_file.read_bytes(),
            artifact_type="surviving_chain",
            retention_category="destruction_receipt",
            ledger_position=block.get("retained_count", 0) or 0,
            horizon=horizon,
            now=now,
        )
        return rec

    def archive_anchor(
        self,
        anchor_path: str | Path,
        *,
        chain_slug: str,
        horizon_date: str,
        horizon: int | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Moment 4: the G1 anchor artefact, written once per anchoring
        run at anchor/<tenant>/<chain-slug>/<horizon-date>.json. Retention
        is the longest of the horizons the anchor covers."""
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(horizon_date)):
            raise ValueError(f"horizon date is not an ISO date: {horizon_date!r}")
        return self._put(
            f"anchor/{self.tenant}/{chain_slug}/{horizon_date}.json",
            Path(anchor_path).read_bytes(),
            artifact_type="anchor",
            retention_category="anchor",
            chain_slug=chain_slug,
            horizon=horizon or 0,
            extra={"horizon_date": str(horizon_date)},
            now=now,
        )

    # -- legal hold (design section 3) ---------------------------------------

    def apply_legal_hold(
        self,
        keys: list[str],
        *,
        actor: str,
        reason: str,
        authority: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        """A legal hold is an operator-plane event (who, when, why,
        authority), applied to the affected objects; the decision itself
        is archived so the hold's provenance is on WORM too. The decision
        record is written before the hold is applied (receipt first,
        commit second)."""
        for key in keys:
            self._require_key(key)
        return self._hold_decision(
            keys,
            event="legal_hold",
            actor=actor,
            reason=reason,
            authority=authority,
            held=True,
            now=now,
        )

    def release_legal_hold(
        self,
        keys: list[str],
        *,
        actor: str,
        reason: str,
        authority: str = "",
        now: int | None = None,
    ) -> dict[str, Any]:
        for key in keys:
            self._require_key(key)
        return self._hold_decision(
            keys,
            event="legal_hold_release",
            actor=actor,
            reason=reason,
            authority=authority,
            held=False,
            now=now,
        )

    def _hold_decision(
        self,
        keys: list[str],
        *,
        event: str,
        actor: str,
        reason: str,
        authority: str,
        held: bool,
        now: int | None = None,
    ) -> dict[str, Any]:
        now = int(time.time()) if now is None else int(now)
        # the decision must outlive what it holds: its retention is at
        # least the longest effective retention among the affected objects
        horizon = max((int(self.store.head(k)["retain_until"]) for k in keys), default=0)
        seq = len(self._entries()) + 1
        decision_id = f"{'hold' if held else 'release'}-{seq:06d}"
        decision = {
            "event": event,
            "who": actor,
            "when": now,
            "why": reason,
            "authority": authority,
            "keys": list(keys),
            "requested_holds": {k: held for k in keys},
        }
        rec = self._put(
            f"hold/{self.tenant}/{decision_id}/receipt.json",
            _canon(decision) + b"\n",
            artifact_type="hold_decision",
            retention_category="hold_decision",
            horizon=horizon,
            extra={"decision_id": decision_id, "decision_event": event},
            now=now,
        )
        for key in keys:
            self.store.set_legal_hold(key, held=held)
        return rec

    def _require_key(self, key: str) -> dict[str, Any]:
        try:
            return self.store.head(key)
        except FileNotFoundError as exc:
            raise ValueError(f"unknown key: {key!r}") from exc

    # -- integrity, rebuild, reconciliation ----------------------------------

    def _entries(self) -> list[dict[str, Any]]:
        if not self.index_path.is_file():
            return []
        entries = []
        for line in self.index_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(json.loads(line))
        return entries

    def inventory(self) -> list[dict[str, Any]]:
        """The write log: every archived write, in order, with its version
        pin and content address."""
        return self._entries()

    def verify(self) -> dict[str, Any]:
        """Chained integrity, honestly: recompute every entry hash and
        link (the write chain), then RE-COMPUTE every object's digest from
        the bytes on disk and compare against the recorded address. A
        payload edited after the fact keeps its recorded hash, so recorded
        values are never trusted on their own."""
        errors: list[str] = []
        index_errors: list[str] = []
        entries: list[dict[str, Any]] = []
        prev_hash = ""
        if self.index_path.is_file():
            for lineno, line in enumerate(
                self.index_path.read_text(encoding="utf-8").splitlines(), 1
            ):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    index_errors.append(f"index line {lineno} is not JSON")
                    continue
                if entry.get("prev_hash") != prev_hash:
                    index_errors.append(
                        f"index entry {entry.get('seq', lineno)} does not chain to its parent"
                    )
                body = {k: v for k, v in entry.items() if k != "entry_hash"}
                if _digest(_canon(body)) != entry.get("entry_hash"):
                    index_errors.append(
                        f"index entry {entry.get('seq', lineno)} hash mismatch: the recorded "
                        f"fields were not what was written"
                    )
                prev_hash = str(entry.get("entry_hash", ""))
                entries.append(entry)
        objects_errors: list[str] = []
        for entry in entries:
            key = str(entry.get("key", ""))
            try:
                data = self.store.get(key, str(entry.get("version_id", "")))
            except FileNotFoundError:
                objects_errors.append(f"object missing at key {key!r}")
                continue
            except WormVersionMismatchError as exc:
                objects_errors.append(str(exc))
                continue
            actual = _digest(data)
            if actual != entry.get("sha256"):
                objects_errors.append(
                    f"object {key!r} content digest mismatch: recorded "
                    f"{entry.get('sha256')}, recomputed {actual}"
                )
        errors = index_errors + objects_errors
        return {
            "valid": not errors,
            "index_chain_valid": not index_errors,
            "objects_valid": not objects_errors,
            "entries": len(entries),
            "errors": errors,
        }

    def rebuild_index(self) -> int:
        """The repair contract (design section 2): the write log is
        rebuildable from the bucket alone. Recomputes the chain from the
        sidecar records in write order and rewrites the index file."""
        records = self.store.object_records()
        entries = []
        for record in records:
            entry = dict(record)
            entry["prev_hash"] = entries[-1]["entry_hash"] if entries else ""
            entry["entry_hash"] = _digest(
                _canon({k: v for k, v in entry.items() if k != "entry_hash"})
            )
            entries.append(entry)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.index_path, "w", encoding="utf-8") as fh:
            for entry in entries:
                fh.write(json.dumps(entry) + "\n")
        return len(entries)

    def reconcile(self, ledger_digests: list[str]) -> dict[str, list[str]]:
        """The runbook's reconciliation (design section 4): diff the
        ledger's chain inventory against the archive's chain-segment
        inventory and expect empty. Digest spellings are normalised (both
        the bare and sha256:-prefixed forms name the same content)."""

        def norm(digest: str) -> str:
            return str(digest).removeprefix(_HASH_PREFIX)

        archived = {
            norm(str(e.get("sha256", "")))
            for e in self._entries()
            if e.get("artifact_type") == "chain_segment"
        }
        ledger = {norm(d) for d in ledger_digests}
        missing = [d for d in ledger_digests if norm(d) not in archived]
        extra = [f"{_HASH_PREFIX}{d}" for d in sorted(archived - ledger)]
        return {"missing_from_archive": missing, "not_in_ledger": extra}

    def _last_segment_digest(self, chain_slug: str) -> str:
        last = ""
        last_seq = -1
        for entry in self._entries():
            if (
                entry.get("artifact_type") == "chain_segment"
                and entry.get("chain_slug") == chain_slug
                and int(entry.get("seq", 0)) > last_seq
            ):
                last_seq = int(entry.get("seq", 0))
                last = str(entry.get("sha256", ""))
        return last


def _span_year_month(span: dict[str, Any]) -> tuple[str, str]:
    """The key's year and month derive from the span the design requires
    on every archive write; a span that is not an ISO-ordered pair fails
    the write rather than guessing a layout."""
    if not isinstance(span, dict) or "first" not in span or "last" not in span:
        raise ValueError("segment span must carry first and last timestamps")
    match = re.match(r"^(\d{4})-(\d{2})-", str(span["first"]))
    if not match:
        raise ValueError(f"segment span first timestamp is not an ISO date: {span['first']!r}")
    year, month = match.group(1), match.group(2)
    if not 1 <= int(month) <= 12:
        raise ValueError(f"segment span month is out of range: {month}")
    return year, month
