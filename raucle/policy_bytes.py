"""Policy-bytes tamper detection (threat-model residual 5, mitigation M2).

The enforcement directory — the operator policy file and the revocation
registry — is trusted configuration today: filesystem write access equals
control-plane compromise with no detection at all. This module closes the
detection half of that residual: at activation the file bytes are hashed
and bound into the receipt stream, and at every gate entry the on-disk
bytes are re-hashed against the receipted digest. An out-of-band edit
takes effect at load time as before, but the gate now FAILS CLOSED with
the named ``policy_tampered`` status instead of enforcing silently
edited policy.

Contract:

- Sealing is receipted or absent. If the activation receipt cannot be
  emitted, the seal is not persisted — a receipted activation is the
  design invariant (the containment rule: a halt without its receipt is
  a bug; here, a seal without its receipt is a bug).
- Re-activation is explicit. Editing the policy is never blocked: the
  operator re-seals the new bytes (``reactivate``), which receipts the
  diverging bytes into the stream first, so an edit is auditable
  evidence, not a blocked write.
- Append-only tolerance for the revocation registry. The gate itself
  appends cascade revocations to the registry, so verification pins the
  SEALED PREFIX of the file (its exact length is recorded at sealing):
  current bytes that extend the prefix are legitimate; a file that
  shrank below the prefix, or whose prefix bytes diverge, is tampering.
- Fail-closed detection state. A corrupt or unreadable seal file reports
  ``policy_tampered``, never a silent ``policy_ok``.
- Unsealed deployments are unaffected: with no seal on disk there is no
  receipted digest to diverge from, and verification reports
  ``policy_ok`` with ``sealed=False`` (backward compatibility).

Deterministic verification: files are digest-cached on
(path, size, mtime_ns), so repeated per-call verification costs one
``stat`` while a tampering write (which changes size or mtime) is
re-hashed on the next check.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

POLICY_STATUS_OK = "policy_ok"
POLICY_STATUS_TAMPERED = "policy_tampered"

SEAL_KIND = "raucle/policy-bytes-seal/v1"

VERDICT_ACTIVATION = "policy_activation"
VERDICT_REACTIVATION = "policy_reactivation"

#: The receipt emitter contract: ``(verdict, extra) -> receipt id (str,
#: or "" when receipt emission is disabled)``. Must raise on failure.
Emitter = Callable[[str, dict[str, Any]], str]


class PolicyBytesError(Exception):
    """A named policy-bytes failure (sealing refused, corrupt seal)."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class PolicyBytesVerifier:
    """Seal and verify the enforcement-file bytes against the receipt stream.

    The seal record is a small JSON sidecar (``seal_path``) carrying the
    digest as of activation plus the receipt id that binds it. Nothing
    here verifies signatures itself: the receipt stream is the tamper-
    evident register; this module keeps the record and performs the
    deterministic byte comparison.
    """

    policy_path: str
    seal_path: str
    revocations_path: str = ""
    emitter: Emitter | None = None
    actor: str = "operator"

    _digest_cache: dict[str, tuple[int, int, str]] = field(
        default_factory=dict, init=False, repr=False
    )
    _cache_lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    # -- digest caching -----------------------------------------------------

    def _digest_file(self, path: str) -> str | None:
        """sha256 of the file's bytes, cached on (size, mtime_ns).

        Returns None when the file does not exist (the caller decides
        what missing bytes mean — a missing policy file is divergence,
        a missing revocations file is an empty prefix).
        """
        try:
            stat = os.stat(path)
        except OSError:
            return None
        key = (stat.st_size, stat.st_mtime_ns)
        with self._cache_lock:
            cached = self._digest_cache.get(path)
            if cached is not None and cached[:2] == key:
                return cached[2]
        with open(path, "rb") as fh:
            digest = _sha256_bytes(fh.read())
        with self._cache_lock:
            self._digest_cache[path] = (key[0], key[1], digest)
        return digest

    # -- seal record --------------------------------------------------------

    @property
    def seal_file(self) -> Path:
        return Path(self.seal_path)

    def has_seal(self) -> bool:
        return self.seal_file.exists()

    def _read_seal(self) -> dict[str, Any]:
        """The persisted seal record, or {} when absent.

        Corrupt JSON raises — fail-closed: an unreadable seal is a
        detection state, not a pass.
        """
        path = self.seal_file
        if not path.exists():
            return {}
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise PolicyBytesError(f"policy-bytes seal file is corrupt: {exc}") from exc
        if not isinstance(record, dict) or record.get("kind") != SEAL_KIND:
            raise PolicyBytesError(
                f"policy-bytes seal file has unknown kind "
                f"{record.get('kind') if isinstance(record, dict) else record!r}"
            )
        return record

    # -- receipting ----------------------------------------------------------

    def _receipt(self, verdict: str, extra: dict[str, Any]) -> str:
        """Emit through the injected emitter. Failure raises (the seal
        is then not persisted); "" means the deployment runs with
        receipt emission off, in which case the seal still gates
        verification but carries no receipt id."""
        if self.emitter is None:
            return ""
        try:
            return self.emitter(verdict, extra) or ""
        except PolicyBytesError:
            raise
        except Exception as exc:
            raise PolicyBytesError(
                f"{verdict} receipt emission failed; seal refused: {exc}"
            ) from exc

    def _build_record(
        self, actor: str, *, reason: str, verdict: str, require_receipt: bool
    ) -> dict[str, Any]:
        policy_path = str(self.policy_path)
        policy_digest = self._digest_file(policy_path)
        if policy_digest is None:
            raise PolicyBytesError(f"policy file '{policy_path}' does not exist; nothing to seal")
        revocations_digest = ""
        revocations_len = 0
        if self.revocations_path:
            try:
                with open(self.revocations_path, "rb") as fh:
                    rev_bytes = fh.read()
            except OSError:
                rev_bytes = b""
            revocations_digest = _sha256_bytes(rev_bytes)
            revocations_len = len(rev_bytes)
        receipt_id = self._receipt(
            verdict,
            {
                "policy_path": policy_path,
                "policy_sha256": policy_digest,
                "revocations_path": str(self.revocations_path or ""),
                "revocations_sha256_prefix": revocations_digest,
                "revocations_prefix_len": revocations_len,
                "actor": actor,
                "reason": reason,
                "sealed_at": _now_iso(),
            },
        )
        if require_receipt and self.emitter is not None and not receipt_id:
            raise PolicyBytesError(f"{verdict} receipt emission failed; seal refused")
        return {
            "kind": SEAL_KIND,
            "policy_path": policy_path,
            "policy_sha256": policy_digest,
            "revocations_path": str(self.revocations_path or ""),
            "revocations_sha256_prefix": revocations_digest,
            "revocations_prefix_len": revocations_len,
            "actor": actor,
            "reason": reason,
            "receipt_id": receipt_id,
            "sealed_at_epoch": int(time.time()),
            "sealed_at": _now_iso(),
        }

    @staticmethod
    def _persist(seal_file: Path, record: dict[str, Any]) -> None:
        seal_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(seal_file.parent), prefix=f".{seal_file.name}.")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(json.dumps(record, sort_keys=True, indent=2).encode("utf-8"))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, seal_file)
        except BaseException:
            with suppress(OSError):
                os.unlink(tmp_name)
            raise

    def _write_seal(self, record: dict[str, Any]) -> None:
        self._persist(self.seal_file, record)
        with self._cache_lock:
            self._digest_cache.clear()

    # -- activation -----------------------------------------------------------

    def seal(self, *, actor: str = "") -> dict[str, Any]:
        """Bind the current enforcement bytes into the receipt stream.

        Hash the policy file (and the revocation registry prefix when
        configured), receipt the digests, and only then persist the seal
        sidecar. Receipt failure aborts the seal fail-closed: no
        unreceipted activation.
        """
        record = self._build_record(
            actor or self.actor,
            reason="activation",
            verdict=VERDICT_ACTIVATION,
            require_receipt=True,
        )
        self._write_seal(record)
        return {
            "status": POLICY_STATUS_OK,
            "sealed": True,
            "policy_sha256": record["policy_sha256"],
            "revocations_sha256": record["revocations_sha256_prefix"],
            "receipt_id": record["receipt_id"],
        }

    def reactivate(self, *, actor: str = "", reason: str = "") -> dict[str, Any]:
        """Re-receipt bytes that diverged from the previous seal.

        The explicit flow that makes editing auditable instead of
        blocked: the diverging bytes are receipted first
        (``policy_reactivation``), then the new seal persists. Refuses
        when the current bytes hash to the sealed digest (nothing to
        reactivate) and when the seal is corrupt (an unreadable seal
        must be resolved by hand, never papered over).
        """
        self._read_seal()  # corrupt seal: raises, never silently reseals
        if self.verify()["status"] == POLICY_STATUS_OK:
            raise PolicyBytesError(
                "reactivation refused: on-disk bytes match the receipted "
                "digest; nothing diverged to re-receipt"
            )
        record = self._build_record(
            actor or self.actor,
            reason=reason or "reactivation after divergence",
            verdict=VERDICT_REACTIVATION,
            require_receipt=True,
        )
        record["reactivated_from_receipt_id"] = self._read_seal().get("receipt_id", "")
        self._write_seal(record)
        return {
            "status": POLICY_STATUS_OK,
            "sealed": True,
            "policy_sha256": record["policy_sha256"],
            "revocations_sha256": record["revocations_sha256_prefix"],
            "receipt_id": record["receipt_id"],
        }

    # -- verification ---------------------------------------------------------

    def verify(self) -> dict[str, Any]:
        """Compare the on-disk bytes against the receipted seal.

        Returns a bounded status dict. The status string is the gate's
        contract: ``policy_ok`` serves, ``policy_tampered`` denies.
        """
        if not self.has_seal():
            return {"status": POLICY_STATUS_OK, "sealed": False, "divergences": []}
        try:
            seal = self._read_seal()
        except PolicyBytesError as exc:
            return {
                "status": POLICY_STATUS_TAMPERED,
                "sealed": True,
                "divergences": [str(exc)],
            }
        divergences = self._divergences(seal)
        if divergences:
            return {
                "status": POLICY_STATUS_TAMPERED,
                "sealed": True,
                "divergences": divergences,
            }
        return {"status": POLICY_STATUS_OK, "sealed": True, "divergences": []}

    def _divergences(self, seal: dict[str, Any]) -> list[str]:
        out: list[str] = []
        policy_path = seal.get("policy_path", str(self.policy_path))
        current = self._digest_file(policy_path)
        if current is None:
            out.append(
                f"policy file '{policy_path}' has vanished since activation "
                "(receipted activation digest: "
                f"{seal.get('policy_sha256', '')[:16]}...)"
            )
        elif current != seal.get("policy_sha256"):
            out.append(
                "policy bytes diverge from the receipted activation digest: "
                f"on-disk sha256 {current} != sealed {seal.get('policy_sha256')}"
            )
        rev_path = seal.get("revocations_path", "")
        if rev_path:
            divergence = self._revocations_divergence(rev_path, seal)
            if divergence:
                out.append(divergence)
        return out

    def _revocations_divergence(self, rev_path: str, seal: dict[str, Any]) -> str:
        """The revocation registry is append-only (the gate appends
        cascade revocations), so verification pins the SEALED PREFIX:
        current bytes must extend the exact bytes receipted at
        activation."""
        sealed_len = int(seal.get("revocations_prefix_len", 0) or 0)
        try:
            size = os.path.getsize(rev_path)
        except OSError:
            size = 0
        if size < sealed_len:
            return (
                f"revocation registry '{rev_path}' shrank below the receipted "
                f"prefix ({size} < {sealed_len} bytes): earlier bytes were "
                "removed or rewritten (out-of-band edit)"
            )
        if sealed_len == 0:
            return ""
        data = self._read_prefix(rev_path, sealed_len)
        if data is None:
            return f"revocation registry '{rev_path}' is unreadable (fail-closed)"
        prefix_digest = _sha256_bytes(data)
        if prefix_digest != seal.get("revocations_sha256_prefix"):
            return (
                "revocation registry prefix diverges from the receipted "
                f"activation digest: on-disk sha256 {prefix_digest} != sealed "
                f"{seal.get('revocations_sha256_prefix')}"
            )
        return ""

    @staticmethod
    def _read_prefix(path: str, length: int) -> bytes | None:
        try:
            with open(path, "rb") as fh:
                return fh.read(length)
        except OSError:
            return None


__all__ = [
    "Emitter",
    "POLICY_STATUS_OK",
    "POLICY_STATUS_TAMPERED",
    "PolicyBytesError",
    "PolicyBytesVerifier",
    "SEAL_KIND",
    "VERDICT_ACTIVATION",
    "VERDICT_REACTIVATION",
]
