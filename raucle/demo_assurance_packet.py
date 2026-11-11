"""G3: the assurance packet demo plane (read-only).

Walks the REAL packet machinery inside this repository: the gateway's
signed receipt chain is collected the way ``receipts export`` streams it,
assembled into a self-contained audit pack by :func:`raucle.audit_pack.
build_pack`, and verified offline in-process by
:func:`raucle.audit_pack.verify_pack`. Everything on screen comes from
those real pack bytes - member digests, the sha-pinned manifest inputs,
and the pack's own offline verdict. No pack member, hash or verdict is
narrated from anywhere but the built and verified PACK.json.

Boundary, stated in the payload itself: this is the gateway's own
evidence plane - receipts, hashes, signature families and the signed
manifest. The framework crosswalk export (``grc_evidence_graph/v1``)
that renders control mappings over a packet lives in the separate
raucle agent-assurance product; this screen does not reproduce it and
names no framework controls.

The pack index and manifest are signed with an EPHEMERAL Ed25519 key
generated in memory for each build: no signing key material is exposed,
persisted, or exported by this plane. Read-only: each build runs in a
disposable sandbox directory and writes nothing outside it.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

PACK_NOTE = (
    "Simulated demonstration on real machinery: the packet below was "
    "assembled and verified just now, in a disposable sandbox, from this "
    "deployment's own signed receipt chain - the same build the "
    "audit-pack command runs. The pack index and manifest are signed with "
    "an ephemeral key generated in memory for this build and discarded; "
    "no key material is displayed, exported or persisted."
)

PACK_BOUNDARY = (
    "Boundary: this packet is what the gateway itself produces - the "
    "signed receipt chain, the sha-pinned manifest of its inputs and the "
    "offline verification verdict. Rendering framework crosswalks and "
    "control graphs over a packet is the raucle agent-assurance "
    "product's export; that layer is not part of this screen."
)

MAX_CHAIN_RECORDS = 1000


def _demo_mode_on() -> bool:
    return os.environ.get("RAUCLE_DEMO_MODE", "").lower() in ("1", "true", "yes")


def collect_chain_lines(gateway: Any, limit: int = MAX_CHAIN_RECORDS) -> list[str]:
    """Collect the deployment's receipt chain lines, oldest-first.

    The same JSONL the receipts export streams: minimal
    ``{receipt_hash, jws}`` envelopes from the segmented store's
    segments, or the legacy flat file. Bounded: beyond the limit only
    the most recent records are kept (the pack verdict shows the
    consequence honestly rather than a curated chain).
    """
    from raucle.gateway_app import _export_paths

    lines: list[str] = []
    for path in _export_paths(gateway):
        try:
            with open(path, encoding="utf-8") as fh:
                lines.extend(line.strip() for line in fh if line.strip())
        except OSError:
            continue
    if len(lines) > limit:
        lines = lines[-limit:]
    return lines


def _ephemeral_signing_pem() -> bytes:
    """A fresh Ed25519 signing key for the pack envelope, memory-only."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def build_demo_assurance_packet(gateway: Any, *, generated_at: int | None = None) -> dict[str, Any]:
    """Assemble, sign, verify and describe one real audit pack.

    Deterministic: the manifest's ``generated_at`` is injected rather
    than read from the clock, so identical inputs give a byte-identical
    manifest body and member digests (the pack's own reproducibility
    check enforces exactly that).
    """
    import time as _time

    from raucle.audit_pack import build_pack, verify_pack
    from raucle.gateway_app import _observed_signing_families

    lines = collect_chain_lines(gateway)
    if not lines:
        return {"note": PACK_NOTE, "boundary": PACK_BOUNDARY, "receipts": 0}

    gate = gateway.gate_identity
    public_keys = {getattr(gate, "key_id", None) or gate.statement.key_id: gate.public_key_pem()}

    with tempfile.TemporaryDirectory(prefix="raucle-demo-packet-") as td:
        root = Path(td)
        chain = root / "receipts.jsonl"
        chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
        pack_dir = root / "pack"
        index = build_pack(
            chain_path=chain,
            public_keys=public_keys,
            audit_key_pem=_ephemeral_signing_pem(),
            out_dir=pack_dir,
            generated_at=int(generated_at if generated_at is not None else _time.time()),
        )
        verdict = verify_pack(pack_dir)

        index_view = {
            "kind": index["kind"],
            "tool_version": index.get("tool_version"),
            "audit_key_id": index.get("index_signature") and index.get("audit_key_id"),
            "require_pq": index.get("require_pq"),
            "members": [
                {"path": m["path"], "role": m["role"], "sha256": m["sha256"]}
                for m in index["members"]
            ],
            "member_count": len(index["members"]),
        }
        # The signed manifest's sha-pinned inputs, read from the pack bytes.
        manifest = json.loads((pack_dir / "manifest.json").read_text(encoding="utf-8"))
        body = manifest.get("body", {})
        inputs = body.get("input_hashes", {})

    result: dict[str, Any] = {
        "note": PACK_NOTE,
        "boundary": PACK_BOUNDARY,
        "pack_kind": index_view["kind"],
        "generated_at": index.get("generated_at"),
        "receipts": len(lines),
        "truncated": len(lines) == MAX_CHAIN_RECORDS and _full_count(gateway) > len(lines),
        "signing_families": _observed_signing_families(gateway),
        "index": index_view,
        "manifest": {
            "signed": True,
            "manifest_key_id": manifest.get("signer_key_id"),
            "tool_version": body.get("tool_version"),
            "chain_verdict": body.get("chain_verdict", {}),
            "summary": body.get("summary", {}),
            "input_hashes": inputs,
        },
        "offline_verdict": {
            "ok": verdict.ok,
            "integrity_ok": verdict.integrity_ok,
            "manifest_signature_ok": verdict.manifest_signature_ok,
            "chain_valid": verdict.chain_valid,
            "reproducible": verdict.reproducible,
            "index_signature_ok": verdict.index_signature_ok,
            "receipt_count": verdict.receipt_count,
            "signer_key_id": verdict.signer_key_id,
            "reasons": list(verdict.reasons),
        },
        "simulated": True,
    }
    return result


def _full_count(gateway: Any) -> int:
    store = getattr(gateway, "_receipt_store", None)
    if store is not None:
        return store.total_receipt_count()
    from raucle.gateway_app import _export_paths

    total = 0
    for path in _export_paths(gateway):
        with open(path, encoding="utf-8") as fh:
            total += sum(1 for line in fh if line.strip())
    return total


def register_demo_assurance_packet_routes(
    app: Any, check_auth: Any, check_access: Any, gateway_provider: Any
) -> None:
    """Register the read-only demo assurance packet endpoint on *app*."""

    from fastapi import Header, HTTPException

    @app.get(
        "/api/demo/assurance-packet",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_assurance_packet(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        user = check_auth(authorization, x_totp)
        check_access(user, "receipts")
        if not _demo_mode_on():
            raise HTTPException(404, "demo mode not configured")
        return build_demo_assurance_packet(gateway_provider())
