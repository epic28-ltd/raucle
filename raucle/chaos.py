"""S5 (EPIC S5): gate chaos mode — named fault injection, default-off.

``RAUCLE_CHAOS=1`` (read via :func:`raucle._env.env`) injects three named
faults into the gate's evidence writes, so the fault-handling contract is
exercised the way chaos engineering intends: by breaking the seam in a
controlled, NAMED way and proving the offline checks catch every one.

Faults:

- ``drop_receipt`` — a receipt is withheld from the receipt store while
  the caller still receives its hash: the receipt is claimed but absent,
  and :func:`offline_flags` names it ("drop_receipt").
- ``delay_index_write`` — the receipt-index write is deferred until
  :meth:`ChaosFaultController.drain_pending_index_writes` flushes it: the
  chain runs ahead of its disposable projection and
  :func:`offline_flags` names the gap ("delay_index_write").
- ``misorder_chain`` — :class:`ChaosAuditSink` withholds the next audit
  record and writes it AFTER its successor: the chain file's index
  sequence is violated and the offline chain verifier
  (``HashChainSink.verify_chain``) reports a broken chain at the named
  index.

Blast radius, deliberately narrow:

- Chaos is OFF unless both ``RAUCLE_ENV=dev`` AND ``RAUCLE_CHAOS=1`` are
  set. A production process never carries the controller, and the
  disabled controller adds no branching cost beyond one boolean check.
- A gateway refuses to enable chaos when its auth mode is not ``off``: a
  fault-injecting evidence writer behind real authentication is a live
  risk, not a test rig.
- Every injection is recorded (fault name, target, integer epoch — no
  floats in signed payload material) and can be emitted as a NAMED FAULT
  RECEIPT: a compact JWS signed by the gate identity that names the
  fault, verifiable offline by the same discipline receipts use
  (``alg=EdDSA`` only, canonical payload, fail-closed).
"""

from __future__ import annotations

import time
from typing import Any

from raucle._env import env

#: The closed fault vocabulary.
CHAOS_FAULTS = ("drop_receipt", "delay_index_write", "misorder_chain")

#: The receipt type string for the named-fault receipt.
CHAOS_RECEIPT_TYP = "raucle/chaos-fault/v1"

_CRIT = "raucle"

#: Hash-algorithm prefix used across receipt-hash spellings.
_SHA256_PREFIX = "sha256:"


class ChaosFaultController:
    """Decides per-write whether a named fault fires, and records it.

    Each fault fires EXACTLY ONCE per controller run: a chaos run is a
    controlled experiment, not a persistent corruption, and the named
    fault receipts are then a finite, verifiable inventory of what was
    injected.
    """

    def __init__(self, faults: set[str]):
        unknown = faults - set(CHAOS_FAULTS)
        if unknown:
            raise ValueError(
                f"unknown chaos faults {sorted(unknown)}; use one of {list(CHAOS_FAULTS)}"
            )
        self._faults_remaining: set[str] = set(faults)
        self.injections: list[dict[str, Any]] = []
        self.pending_index_writes: list[dict[str, Any]] = []

    @classmethod
    def from_env(cls, *, gate_auth: str | None = None) -> ChaosFaultController:
        """Build from ``RAUCLE_ENV`` + ``RAUCLE_CHAOS`` via the env loader.

        Returns a DISABLED controller when chaos is off (no env vars, the
        default). Raises ValueError when chaos is requested but refused:
        outside a DEV build, or on a gate whose auth mode is not ``off``.
        """
        requested = (env("CHAOS") or "").strip().lower() in ("1", "true", "yes", "on")
        if not requested:
            return cls(faults={str(f) for f in ()})
        profile = (env("ENV") or "prod").strip().lower()
        if profile != "dev":
            raise ValueError(
                f"RAUCLE_CHAOS refused: RAUCLE_ENV is {profile!r}, not 'dev'; "
                "chaos fault injection never runs outside DEV builds"
            )
        if gate_auth is not None and gate_auth != "off":
            raise ValueError(
                f"RAUCLE_CHAOS refused: RAUCLE_GATE_AUTH is {gate_auth!r}, not 'off'; "
                "a fault-injecting evidence writer behind real authentication is refused"
            )
        faults = env("CHAOS_FAULTS")
        names = (
            {f.strip() for f in faults.split(",") if f.strip()}
            if faults
            else {str(f) for f in CHAOS_FAULTS}
        )
        return cls(faults=names)  # type: ignore[arg-type]

    def fault_active(self, fault: str, target: str = "") -> bool:
        """Whether *fault* fires for this write (once per run), and records it."""
        if fault not in self._faults_remaining:
            return False
        self._faults_remaining.discard(fault)
        self.injections.append({"fault": fault, "target": target, "iat": int(time.time())})
        return True

    def mark_injected(self, fault: str, target: str = "") -> None:
        """Record an injection made through a custom seam (sink subclass)."""
        self._faults_remaining.discard(fault)
        self.injections.append({"fault": fault, "target": target, "iat": int(time.time())})

    def drain_pending_index_writes(self, index: Any) -> int:
        """Flush deferred index writes; returns how many were drained."""
        drained = 0
        while self.pending_index_writes:
            record = self.pending_index_writes.pop()
            index.index_receipt(record)
            drained += 1
        return drained

    def fault_receipts(self, signer: Any, *, key_id: str) -> list[dict[str, Any]]:
        """A NAMED FAULT RECEIPT for every injection (signed compact JWS)."""
        return [
            emit_fault_receipt(
                signer, key_id=key_id, fault=i["fault"], target=i["target"], iat=i["iat"]
            )
            for i in self.injections
        ]


def emit_fault_receipt(
    signer: Any,
    *,
    key_id: str,
    fault: str,
    target: str = "",
    iat: int | None = None,
) -> dict[str, Any]:
    """Sign a chaos-fault receipt naming the injected fault.

    *signer* is an Ed25519 private-key object (``.sign(bytes)``); a
    :class:`raucle.audit.Ed25519Signer` or an
    :class:`raucle.provenance.AgentIdentity` qualifies.
    """
    from raucle.provenance import _b64url_encode, _canonical_json, _sha256_hex

    if fault not in CHAOS_FAULTS:
        raise ValueError(f"unknown chaos fault {fault!r}; use one of {list(CHAOS_FAULTS)}")
    header = {
        "alg": "EdDSA",
        "typ": CHAOS_RECEIPT_TYP,
        "kid": key_id,
        "crit": [_CRIT],
        _CRIT: "chaos-fault",
    }
    payload = {
        "typ": CHAOS_RECEIPT_TYP,
        "fault": str(fault),
        "target_hash": str(target),
        "iat": int(iat if iat is not None else int(time.time())),
        "key_id": key_id,
    }
    signing_input = (
        _b64url_encode(_canonical_json(header)) + "." + _b64url_encode(_canonical_json(payload))
    ).encode("ascii")
    sig = signer.sign(signing_input)
    jws = signing_input.decode("ascii") + "." + _b64url_encode(sig)
    return {
        "typ": CHAOS_RECEIPT_TYP,
        "jws": jws,
        "receipt_hash": _SHA256_PREFIX + _sha256_hex(jws.encode("ascii")),
    }


def verify_fault_receipt(envelope: dict[str, Any], *, public_key_pem: bytes) -> tuple[bool, str]:
    """Offline verification of a chaos-fault receipt. Fail-closed."""
    import base64
    import json

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    def _decode(segment: str) -> dict[str, Any]:
        padded = segment + "==" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))

    jws = envelope.get("jws", "") if isinstance(envelope, dict) else ""
    if not isinstance(jws, str) or jws.count(".") != 2:
        return False, "envelope carries no compact JWS"
    header_b64, payload_b64, sig_b64 = jws.split(".")
    try:
        header = _decode(header_b64)
        payload = _decode(payload_b64)
    except ValueError as exc:  # JSONDecodeError is a ValueError
        return False, f"undecodable JWS segment: {exc}"
    if header.get("alg") != "EdDSA":
        return False, f"expected alg=EdDSA, found {header.get('alg')!r}"
    if payload.get("typ") != CHAOS_RECEIPT_TYP or payload.get("fault") not in CHAOS_FAULTS:
        return False, "payload is not a chaos-fault receipt naming a known fault"
    try:
        key = load_pem_public_key(public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            return False, f"public key is not Ed25519 (got {type(key).__name__})"
        key.verify(_b64decode_raw(sig_b64), f"{header_b64}.{payload_b64}".encode("ascii"))
    except Exception:  # noqa: BLE001 - fail-closed: non-verifying signature is an error
        return False, "signature does not verify under the supplied public key"
    return True, ""


def _b64decode_raw(segment: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(segment + "==" * (-len(segment) % 4))


def _store_hashes(store_path: str | Any) -> dict[str, str]:
    """Map both spellings of every stored receipt hash to its raw store line."""
    import json
    from pathlib import Path

    stored: dict[str, str] = {}
    text = Path(store_path).read_text(encoding="utf-8")
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        rec = json.loads(line)
        rh = rec.get("receipt_hash", "")
        # hash spellings differ by producer: record both spellings
        for spelling in (rh, rh.removeprefix(_SHA256_PREFIX)):
            if spelling:
                stored[spelling] = line
    return stored


def _drop_receipt_flags(stored: dict[str, str], claimed_hashes: list[str] | None) -> list[str]:
    """Name every receipt the caller CLAIMS but the store never recorded."""
    return [
        f"drop_receipt: receipt {claimed} claimed by the caller but absent from the store"
        for claimed in claimed_hashes or []
        if claimed not in stored and claimed.removeprefix(_SHA256_PREFIX) not in stored
    ]


def _delay_index_flags(stored: dict[str, str], index: Any) -> list[str]:
    """Name receipts the store holds but the index projection lacks.

    Any read failure of the index is honest (no flag invented): an empty
    list means ``the index could not be reconciled``, not ``the index is
    clean``.
    """
    has_rows: set[str] = set()
    try:
        conn = index._conn  # noqa: SLF001 - offline reconciliation is in-package
        for (rh,) in conn.execute("SELECT receipt_hash FROM receipts"):
            has_rows.add(rh)
            has_rows.add(rh.removeprefix(_SHA256_PREFIX))
    except Exception:  # noqa: BLE001 - any read failure is honest (no flag invented)
        return []
    return [
        f"delay_index_write: receipt {rh} is in the store but absent from the index"
        for rh in sorted(stored)
        if rh.removeprefix(_SHA256_PREFIX) not in has_rows and rh not in has_rows
    ]


def offline_flags(
    store_path: str | Any,
    *,
    index: Any = None,
    claimed_hashes: list[str] | None = None,
) -> list[str]:
    """The offline reconciliation the chaos runs assert against.

    Flags, NAMED:
    - ``drop_receipt``: a receipt hash the caller CLAIMS but the store
      never recorded,
    - ``delay_index_write``: a receipt the store recorded but the index
      projection lacks.
    """
    stored = _store_hashes(store_path)
    flags = _drop_receipt_flags(stored, claimed_hashes)
    if index is not None:
        flags.extend(_delay_index_flags(stored, index))
    return flags


class ChaosAuditSink:
    """A HashChainSink facade that can mis-order chain entries under chaos.

    Wraps a real ``HashChainSink``. Under ``misorder_chain`` the NEXT
    record after the fault fires is WITHHELD (the sink keeps its internal
    state correct - prev_hash, index, leaf hashes) and written only after
    its successor lands: the chain file's line order then violates the
    index sequence, and the offline verifier
    (``HashChainSink.verify_chain``) reports ``chain broken at index N``.
    The fault fires exactly once per controller run; every other append
    is delegated verbatim.
    """

    def __init__(self, sink: Any, controller: ChaosFaultController):
        self._sink = sink
        self._chaos = controller
        self._holdback: dict[str, Any] | None = None

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        # Withhold the NEXT record when the fault fires: the record after
        # it lands in the file BEFORE the withheld one - mis-ordered.
        if self._holdback is None and self._chaos.fault_active("misorder_chain"):
            record = self._sink.append(event)
            # name the target: the injection was recorded before the
            # record existed, so fill in its chain hash now
            self._chaos.injections[-1]["target"] = str(record.get("hash", ""))
            self._holdback = record
            return record
        if self._holdback is not None:
            record = self._sink.append(event)
            held = self._holdback
            self._holdback = None
            self._misorder_file(held)
            return record
        return self._sink.append(event)

    def close(self) -> None:
        """Flush sink state; a record still withheld is appended normally
        (a chaos run never LOSES evidence - it only mis-orders it while
        there is a successor to mis-order against)."""
        if self._holdback is not None:
            held = self._holdback
            self._holdback = None
            self._sink.append(held.get("event", {}))
        close = getattr(self._sink, "close", None)
        if callable(close):
            close()

    def _misorder_file(self, withheld: dict[str, Any]) -> None:
        """Rewrite the file so the withheld (earlier-index) record lands
        AFTER its successor: the line order no longer matches the index
        sequence the offline verifier checks."""
        import json
        from pathlib import Path

        fh = getattr(self._sink, "_file", None)
        if fh is None:
            return
        try:
            name = fh.name
        except (AttributeError, ValueError):
            return
        lines = Path(name).read_text(encoding="utf-8").splitlines()
        held_line = json.dumps(withheld, ensure_ascii=False)
        if held_line not in lines:
            return
        lines.remove(held_line)
        lines.append(held_line)
        with open(name, "w", encoding="utf-8") as out:
            out.write("\n".join(lines) + "\n")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._sink, name)


__all__ = [
    "CHAOS_FAULTS",
    "CHAOS_RECEIPT_TYP",
    "ChaosAuditSink",
    "ChaosFaultController",
    "emit_fault_receipt",
    "offline_flags",
    "verify_fault_receipt",
]
