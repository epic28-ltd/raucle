"""Operator-facing chain rotation and the gateway boot memory preflight (J1).

The 18 Nov demo incident root cause: the gateway boot maps the whole audit
chain and the receipt-store index into memory, measured at roughly twice
their on-disk bytes in RSS, so an unbounded store eventually meets a bounded
box and the process is OOM-killed at boot, repeatedly, under restart:always.
The live fix rotated the stores by hand; this module is the product form of
that fix (gap a).

Two surfaces, ONE shared truth:

* :func:`resolve_boot_stores` names the unbounded stores a boot maps:
  the audit chain file, the persisted connection audit log, the receipt
  store (segment dir or flat file) and the receipt index. The preflight
  stats exactly these files; the rotation archives exactly these files.
  If the two ever disagreed the operator would rotate the wrong thing
  while the boot still refused.
* :func:`boot_memory_preflight` runs at gateway boot BEFORE any store is
  loaded and refuses with a NAMED error (:class:`BootMemoryCeilingExceeded`,
  naming ``raucle rotate-chain``) when the documented RSS projection exceeds
  the ceiling. Never a silent ballooning boot.
* :func:`rotate_chain` is the receipted operator action behind
  ``raucle rotate-chain``: it archives the current stores under the same
  directory with a ``.archived-<date>`` suffix (NEVER deletes), refuses
  idempotent-safe when today's archive already exists, records the rotation
  as a signed receipt whose ``x_rotation`` extension carries what rotated,
  the archived file digests, the operator identity and the timestamps, and
  verifies the fresh store boots on the same env-bonded paths.

The chain of record gains a NEW LINK describing the boundary: prior links
are never rewritten, and the archived chains stay verifiable offline inside
their archives (the archive is a rename, byte for byte).
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from raucle.errors import BootMemoryCeilingExceeded, RotationRefusedError

if TYPE_CHECKING:
    from raucle.gateway import GatewayConfig

logger = logging.getLogger(__name__)

#: The operator command the preflight names as the escape route.
ROTATE_COMMAND = "raucle rotate-chain"

#: Env var that pins the boot memory ceiling in MB (0/unset = derive the
#: default from detected memory minus headroom).
ENV_BOOT_MEM_CEILING_MB = "RAUCLE_BOOT_MEM_CEILING_MB"

#: Documented RSS projection multiplier. Measured on the demo box (18 Nov):
#: a boot over a 12.2 GB audit chain plus a 15 GB receipt index reached
#: 23.4 GB RSS, so the boot-time cost of the mapped stores lands at roughly
#: TWICE their on-disk bytes (per-record Python string overhead in the
#: chain's in-memory leaf list plus the SQLite index cache). The preflight
#: plans with 2.0 as a deliberately conservative factor: it refuses early
#: rather than precisely at the wall.
BOOT_MEM_RSS_MULTIPLIER = 2.0

#: Default headroom: a quarter of the detected memory, never below 2 GB.
_HEADROOM_FRACTION = 4
_HEADROOM_MIN_MB = 2048

_MB = 1024 * 1024

# Receipt vocabulary constants, mirroring the gateway's own (single source
# of truth stays in raucle.gateway; duplicating the literals here keeps this
# module import-cycle-free from the gateway that calls it at boot).
_RECEIPT_TYP = "provenance-receipt/v1"
_RECEIPT_CRIT = "raucle/v1"
_GATE_AGENT_ID = "agent:gate"


# ---------------------------------------------------------------------------
# The shared truth: which stores does a gateway boot map?
# ---------------------------------------------------------------------------


def _file_entry(kind: str, path: Path) -> dict[str, Any]:
    """A single-file store entry (existence, files, total bytes)."""
    exists = path.is_file()
    return {
        "kind": kind,
        "path": str(path),
        "exists": exists,
        "files": [str(path)] if exists else [],
        "bytes": path.stat().st_size if exists else 0,
    }


def _dir_entry(kind: str, path: Path) -> dict[str, Any]:
    """A directory store entry: every file inside counts (a directory
    rename carries them all, so they are statted and archived together)."""
    exists = path.is_dir()
    files = sorted(str(p) for p in path.rglob("*") if p.is_file()) if exists else []
    total = 0
    if exists:
        for name in files:
            total += Path(name).stat().st_size
    return {"kind": kind, "path": str(path), "exists": exists, "files": files, "bytes": total}


def resolve_boot_stores(config: GatewayConfig) -> list[dict[str, Any]]:
    """The unbounded stores a gateway boot maps, in one place.

    The boot memory preflight stats exactly these entries and
    ``raucle rotate-chain`` archives exactly these entries, so the refusal
    and the remedy can never name different files. The implicit index that
    lives INSIDE the segment dir is not a separate entry: the directory
    rename carries it, and statting it twice would double the projection.
    """
    entries: list[dict[str, Any]] = [_file_entry("audit_chain", Path(config.audit_chain))]
    if config.audit_persist:
        entries.append(_file_entry("audit_log", Path(config.audit_log_file)))
    if config.receipt_store_dir:
        entries.append(_dir_entry("receipt_store", Path(config.receipt_store_dir)))
        index_path = (
            Path(config.receipt_index_path)
            if config.receipt_index_path
            else Path(config.receipt_store_dir) / "index.sqlite"
        )
        if index_path.parent != Path(config.receipt_store_dir):
            entries.append(_file_entry("receipt_index", index_path))
    else:
        entries.append(_file_entry("receipt_store", Path(config.receipt_store)))
        if config.receipt_index_path:
            entries.append(_file_entry("receipt_index", Path(config.receipt_index_path)))
    return entries


# ---------------------------------------------------------------------------
# Boot memory preflight
# ---------------------------------------------------------------------------


def detected_total_memory_mb() -> int | None:
    """Total physical memory in MB, or None when it cannot be detected."""
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024  # kB -> MB
    except (OSError, ValueError, IndexError):
        pass
    try:
        total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        return max(0, total // _MB)
    except (ValueError, OSError, AttributeError):
        return None


def default_boot_ceiling_mb(detected_total_mb: int) -> int:
    """The default ceiling: detected memory minus headroom.

    Headroom is a quarter of the box, never below 2 GB, so the gateway never
    plans to consume the machine it runs on.
    """
    headroom = max(_HEADROOM_MIN_MB, detected_total_mb // _HEADROOM_FRACTION)
    return max(1, detected_total_mb - headroom)


def _effective_ceiling_mb(config: GatewayConfig) -> int:
    if config.boot_mem_ceiling_mb > 0:
        return int(config.boot_mem_ceiling_mb)
    detected = detected_total_memory_mb()
    if detected is None:
        return 0
    return default_boot_ceiling_mb(detected)


def boot_memory_preflight(config: GatewayConfig) -> dict[str, Any]:
    """Stat the boot stores BEFORE loading and refuse over the ceiling.

    Returns the projection report (also useful to the panel/status). Raises
    :class:`BootMemoryCeilingExceeded` with a message naming the projected
    size, the ceiling and the rotate command, BEFORE any store is opened,
    so a bounded box never meets an unbounded store inside a ballooning
    boot. When the ceiling cannot be derived (memory undetectable and env
    unset) the preflight degrades to a loud warning, never a silent guess.
    """
    stores = resolve_boot_stores(config)
    on_disk = sum(entry["bytes"] for entry in stores)
    projected_mb = math.ceil(on_disk * BOOT_MEM_RSS_MULTIPLIER / _MB)
    ceiling_mb = _effective_ceiling_mb(config)
    report: dict[str, Any] = {
        "projected_mb": projected_mb,
        "on_disk_bytes": on_disk,
        "multiplier": BOOT_MEM_RSS_MULTIPLIER,
        "ceiling_mb": ceiling_mb,
        "stores": stores,
    }
    if ceiling_mb <= 0:
        logger.warning(
            "boot memory ceiling could not be derived (memory undetectable, "
            "%s unset): preflight reports the projection but cannot enforce "
            "a ceiling; set %s explicitly",
            ENV_BOOT_MEM_CEILING_MB,
            ENV_BOOT_MEM_CEILING_MB,
        )
        return report
    if projected_mb > ceiling_mb:
        raise BootMemoryCeilingExceeded(
            f"boot memory ceiling exceeded: the boot stores project to "
            f"{projected_mb} MB RSS ({on_disk // _MB} MB on disk x "
            f"{BOOT_MEM_RSS_MULTIPLIER} documented multiplier), over the "
            f"{ceiling_mb} MB ceiling ({ENV_BOOT_MEM_CEILING_MB}, or detected "
            f"memory minus headroom). The gateway refuses to boot rather "
            f"than be OOM-killed. Archive the stores with "
            f"'{ROTATE_COMMAND}' (it never deletes; prior links stay "
            f"verifiable offline inside the archives), then start the gateway."
        )
    logger.info(
        "boot memory preflight: projected %d MB RSS under the %d MB ceiling",
        projected_mb,
        ceiling_mb,
    )
    return report


# ---------------------------------------------------------------------------
# Chain rotation
# ---------------------------------------------------------------------------


def _utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def archive_name(path: str | Path, date: str | None = None) -> Path:
    """The dated archive path for *path*, in the same directory.

    ``gateway-audit.jsonl`` -> ``gateway-audit.jsonl.archived-2026-11-18``.
    The archive is a rename: same parent directory, dated suffix, never a
    delete and never a cross-device move.
    """
    resolved = Path(path)
    return resolved.with_name(resolved.name + f".archived-{date or _utc_today()}")


def _digest_file(path: Path) -> dict[str, Any]:
    """SHA-256 and size of one file (streamed, never fully in memory)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def _store_tail_receipt_hash(config: GatewayConfig) -> str | None:
    """The receipt chain of record's tail receipt hash, bounded-cost.

    The rotation receipt parents it, so the fresh chain's first link cites
    exactly where the archived chain ended (a new link, never a rewrite).
    Reads the tail only: a 15 GB store costs one bounded reverse read.
    """
    if config.receipt_store_dir:
        if not Path(config.receipt_store_dir).is_dir():
            return None
        from raucle.receipt_store import SegmentedReceiptStore

        store = SegmentedReceiptStore(base_dir=config.receipt_store_dir)
        for record in store.recent(limit=1):
            return str(record.get("receipt_hash", "")) or None
        return None
    path = Path(config.receipt_store)
    if not path.is_file():
        return None
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - (1 << 16)))
        tail = fh.read().decode("utf-8", "replace")
    for line in reversed(tail.strip().splitlines()):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get("receipt_hash"):
            return str(record["receipt_hash"])
    return None


def _gate_signer(config: GatewayConfig) -> Any:
    """Load or create the persistent gateway signing key.

    Mirrors the gateway boot path (``_load_or_create_local_signer``): the key
    persists beside the receipt store, is created 0600 on first use, and a
    corrupt key file fails closed because regenerating would orphan every
    receipt the previous key signed. Rotation receipts verify with the same
    public key as gate receipts.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from raucle.audit import Ed25519Signer

    if config.signer_key_path:
        key_path = Path(config.signer_key_path)
    else:
        key_path = Path(config.receipt_store).parent / "gateway-signing-key.pem"
    if key_path.exists():
        try:
            private_key = serialization.load_pem_private_key(key_path.read_bytes(), None)
        except Exception:
            logger.exception("gateway signing key %s is corrupt; refusing", key_path)
            raise ValueError(f"corrupt gateway signing key {key_path}") from None
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError(f"gateway signing key {key_path} is not an Ed25519 key")
        return Ed25519Signer(private_key)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
        fh.flush()
        os.fsync(fh.fileno())
    return Ed25519Signer(private_key)


def _mint_rotation_receipt(
    config: GatewayConfig,
    *,
    operator: str,
    reason: str,
    archived_on: str,
    archived_at: str,
    rotated: list[dict[str, Any]],
    parents: list[str],
) -> dict[str, str]:
    """Sign the rotation receipt and append it to the FRESH store.

    Same GUARDRAIL_SCAN-shaped provenance receipt as the gate's authority
    receipts (verifiable through the standard chain verifier), with an
    ``x_rotation`` extension binding what rotated, the archived file
    digests, the operator identity and the timestamps.
    """
    from raucle.provenance import _b64url_encode, _canonical_json, _sha256_hex

    signer = _gate_signer(config)
    extension = {
        "kind": "chain_rotation",
        "operator": operator,
        "reason": reason,
        "archived_on": archived_on,
        "archived_at": archived_at,
        "rotate_command": ROTATE_COMMAND,
        "stores": rotated,
    }
    payload: dict[str, Any] = {
        "iss": "raucle-gateway",
        "typ": _RECEIPT_TYP,
        "iat": int(time.time()),
        "agent_id": _GATE_AGENT_ID,
        "agent_key_id": signer.key_id(),
        "operation": "guardrail_scan",
        "parents": parents,
        "taint": ["gate:observed"],
        "input_hash": _sha256_hex(_canonical_json(extension)),
        "ruleset_hash": _sha256_hex(_canonical_json(extension)),
        "guardrail_verdict": "allowed",
        "x_rotation": extension,
    }
    header = {
        "alg": "EdDSA",
        "typ": _RECEIPT_TYP,
        "kid": signer.key_id(),
        "crit": [_RECEIPT_CRIT],
        _RECEIPT_CRIT: "provenance",
    }
    signing_input = (
        _b64url_encode(_canonical_json(header)) + "." + _b64url_encode(_canonical_json(payload))
    ).encode("ascii")
    signature = signer.sign(signing_input)
    jws = signing_input.decode("ascii") + "." + _b64url_encode(signature)
    receipt_hash = "sha256:" + _sha256_hex(jws.encode("ascii"))
    line = json.dumps({"receipt_hash": receipt_hash, "jws": jws}, ensure_ascii=False)

    if config.receipt_store_dir:
        from raucle.receipt_store import SegmentedReceiptStore

        store = SegmentedReceiptStore(base_dir=config.receipt_store_dir)
        store.append_line(line)
        receipt_path = str(
            Path(config.receipt_store_dir) / (store.active_segment or "seg-000000.jsonl")
        )
    else:
        path = Path(config.receipt_store)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        receipt_path = str(path)
    return {"receipt_hash": receipt_hash, "path": receipt_path}


def _verify_fresh_boot(config: GatewayConfig) -> dict[str, Any]:
    """Prove the fresh stores boot on the same env-bonded paths.

    Exercises the boot path itself, bounded because the fresh stores are
    empty or hold only the rotation receipt: the fresh audit chain opens a
    SIGNED genesis header under the gate key (the same open the deployment
    intake performs), the fresh segment store opens, and a fresh receipt
    index rebuilds from the store and projects the rotation receipt.
    """
    from raucle.audit import HashChainSink

    boot: dict[str, Any] = {}
    signer = _gate_signer(config)
    sink = HashChainSink(Path(config.audit_chain), signer=signer, checkpoint_every=0)
    boot["audit_chain"] = str(config.audit_chain)
    boot["audit_chain_genesis"] = sink.tail_hash == "0" * 64 or sink.event_count == 0
    sink.close()

    if config.receipt_store_dir:
        from raucle.receipt_store import SegmentedReceiptStore

        store = SegmentedReceiptStore(base_dir=config.receipt_store_dir)
        boot["receipt_store"] = str(config.receipt_store_dir)
        boot["receipt_count"] = store.total_receipt_count()
        index_path = (
            Path(config.receipt_index_path)
            if config.receipt_index_path
            else Path(config.receipt_store_dir) / "index.sqlite"
        )
        from raucle.receipt_index import ReceiptIndex

        index = ReceiptIndex(sqlite_path=index_path)
        try:
            boot["receipt_index_count"] = index.rebuild_from_store(store)
        finally:
            index.close()
    else:
        boot["receipt_store"] = str(config.receipt_store)
        boot["receipt_count"] = sum(
            1
            for line in Path(config.receipt_store).read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    return boot


def rotate_chain(config: GatewayConfig, *, operator: str = "", reason: str = "") -> dict[str, Any]:
    """The receipted operator rotation behind ``raucle rotate-chain``.

    For a running or a stopped gateway this archives the boot stores
    (audit chain, persisted connection log, receipt store and its index)
    under the same directory with a ``.archived-<date>`` suffix. It NEVER
    deletes, refuses all-or-nothing when today's archive already exists
    (idempotent-safe), records the boundary as a signed rotation receipt in
    the FRESH chain of record, and verifies the fresh store boots on the
    same env-bonded paths. Prior links are never rewritten: the archives
    stay verifiable offline.

    Crash window, stated honestly: the receipt is minted AFTER the renames.
    A crash between the two leaves the archives in place and no boundary
    receipt; the same-day refusal then tells the operator to inspect, so
    the state is visible rather than ambiguous.
    """
    operator = operator.strip() or os.environ.get("RAUCLE_OPERATOR", "").strip()
    if not operator:
        raise RotationRefusedError(
            "rotation refused: no operator identity. Pass --operator or set "
            "RAUCLE_OPERATOR; the rotation receipt must attribute the action "
            "to a named operator."
        )
    stores = [entry for entry in resolve_boot_stores(config) if entry["exists"]]
    if not stores:
        raise RotationRefusedError(
            f"nothing to rotate: none of the configured stores exist (audit "
            f"chain {config.audit_chain}, receipt store "
            f"{config.receipt_store_dir or config.receipt_store})."
        )
    archived_on = _utc_today()
    # Idempotent-safe: refuse BEFORE touching anything when today's archive
    # already exists. A same-day re-run must never overwrite or duplicate.
    for entry in stores:
        target = archive_name(entry["path"], archived_on)
        if target.exists():
            raise RotationRefusedError(
                f"rotation refused: {target} already exists (an archive from "
                f"{archived_on} is present); a same-day archive must never be "
                f"overwritten. Inspect or move it, or rotate after midnight UTC."
            )

    # Digest before renaming: the receipt's evidence is complete before any
    # file moves, and a failure here leaves the stores untouched.
    tail_receipt = _store_tail_receipt_hash(config)
    rotated: list[dict[str, Any]] = []
    for entry in stores:
        files = [_digest_file(Path(name)) for name in entry["files"]]
        rotated.append(
            {
                "kind": entry["kind"],
                "path": entry["path"],
                "archived_path": str(archive_name(entry["path"], archived_on)),
                "files": files,
                "bytes": entry["bytes"],
            }
        )
    for entry in stores:
        os.rename(entry["path"], archive_name(entry["path"], archived_on))
        logger.info(
            "rotate-chain archived %s (%d bytes) to %s",
            entry["path"],
            entry["bytes"],
            archive_name(entry["path"], archived_on),
        )

    receipt = _mint_rotation_receipt(
        config,
        operator=operator,
        reason=reason,
        archived_on=archived_on,
        archived_at=datetime.now(timezone.utc).isoformat(),
        rotated=rotated,
        parents=[tail_receipt] if tail_receipt else [],
    )
    boot = _verify_fresh_boot(config)
    logger.info(
        "rotate-chain complete: receipt %s, fresh boot verified (%s)",
        receipt["receipt_hash"],
        boot.get("receipt_store"),
    )
    return {
        "archived_on": archived_on,
        "rotated": rotated,
        "receipt_hash": receipt["receipt_hash"],
        "receipt_path": receipt["path"],
        "boot": boot,
    }
