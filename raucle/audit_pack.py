"""Self-contained, offline-verifiable custody evidence pack (E2).

``audit-export`` produces a signed report but leaves the inputs a verifier needs
(the receipt chain, the public keys, the authorising capability tokens, the cited
proofs) as separate files the verifier must already possess and trust. A
**regulator** does not have those files and will not phone the cloud provider to
get them.

An *audit pack* bundles everything required to check the evidence into one
directory, with a ``PACK.json`` index that content-addresses every member. The
matched :func:`verify_pack` then verifies the whole thing **offline** — integrity
of every member, the manifest's own Ed25519 signature, the receipt chain against
the bundled public keys, and that the signed manifest is *reproducible* from the
bundled evidence — needing nothing external: no network, no AWS, no trust in the
party that produced it. This is the property a cloud provider's internal audit
log structurally cannot offer: independent, offline verifiability.

Layout::

    pack/
      PACK.json              index: every member + its sha256 + role
      chain.jsonl            the JWS provenance receipt chain
      manifest.json          the Ed25519-signed audit-export manifest
      report.html            human-readable report (same manifest, rendered)
      pubkeys/<key_id>.pem    public keys the chain verifies against
      statements/<key_id>.json  capability statements (tool/model enforcement)
      capabilities/<n>.json   authorising capability tokens (optional)
      proofs/<n>.json         cited ProofResult artifacts (optional)
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raucle._paths import validate_path

from . import __version__
from .audit_export import build_report, render_html, sign_manifest, verify_manifest
from .pq import PQUnavailable
from .provenance import (
    CapabilityStatement,
    ProvenanceVerifier,
    _canonical_json,
    _sha256_hex,
)

PACK_KIND = "raucle-audit-pack/v1"
_CHAIN_JSONL = "chain.jsonl"
INDEX_NAME = "PACK.json"


def _file_hash(path: Path) -> str:
    return "sha256:" + _sha256_hex(path.read_bytes())


_INDEX_SIG_FIELDS = ("audit_public_key_pem", "index_signature")


def _sign_index(index: dict[str, Any], audit_key_pem: bytes) -> dict[str, Any]:
    """Ed25519-sign the canonical index (its member digests included) with the
    audit key. This binds every member's sha256 into a signature, so a member can
    never be forged-and-re-indexed without the audit private key."""
    from cryptography.hazmat.primitives import serialization

    priv = serialization.load_pem_private_key(audit_key_pem, password=None)
    sig = priv.sign(_canonical_json(index))
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        **index,
        "audit_public_key_pem": pub_pem.decode("ascii"),
        "index_signature": base64.b64encode(sig).decode("ascii"),
    }


def _verify_index_signature(index: dict[str, Any]) -> tuple[bool, str | None]:
    """Verify the index's own signature against the public key embedded in it.
    Returns ``(ok, signer_key_id)``. The signer id matches the manifest's
    ``signer_key_id`` (same derivation) so the two can be cross-checked."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization

    pem = index.get("audit_public_key_pem")
    sig_b64 = index.get("index_signature")
    if not pem or not sig_b64:
        return False, None
    body = {k: v for k, v in index.items() if k not in _INDEX_SIG_FIELDS}
    try:
        pub = serialization.load_pem_public_key(pem.encode("ascii"))
        pub.verify(base64.b64decode(sig_b64), _canonical_json(body))
    except (InvalidSignature, ValueError, TypeError):
        return False, None
    return True, _sha256_hex(pem.encode("ascii"))[:16]


def build_pack(
    *,
    chain_path: str | Path,
    public_keys: dict[str, bytes],
    audit_key_pem: bytes,
    out_dir: str | Path,
    generated_at: int,
    capability_statements: dict[str, CapabilityStatement] | None = None,
    capabilities: list[dict[str, Any]] | None = None,
    proofs: list[dict[str, Any]] | None = None,
    pq_public_keys: dict[str, bytes | str] | None = None,
    require_pq: bool = False,
) -> dict[str, Any]:
    """Assemble a self-contained, offline-verifiable audit pack.

    ``generated_at`` is injected (not read from the clock) so the signed manifest
    — and therefore the pack — is deterministic and reproducible. Returns the
    written ``PACK.json`` index dict.
    """
    capability_statements = capability_statements or {}
    capabilities = capabilities or []
    proofs = proofs or []
    pq_public_keys = pq_public_keys or {}

    report = build_report(
        chain_path,
        public_keys,
        proofs,
        generated_at=generated_at,
        capabilities=capabilities,
        capability_statements=capability_statements or None,
    )
    manifest = sign_manifest(report, audit_key_pem)

    out = Path(out_dir)
    (out / "pubkeys").mkdir(parents=True, exist_ok=True)
    members: list[dict[str, Any]] = []

    def _emit(rel: str, data: bytes, role: str, **extra: Any) -> None:
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        members.append({"path": rel, "role": role, "sha256": _file_hash(dest), **extra})

    _emit(_CHAIN_JSONL, validate_path(chain_path).read_bytes(), "receipt-chain")
    _emit(
        "manifest.json",
        json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8"),
        "signed-manifest",
    )
    _emit("report.html", render_html(manifest).encode("utf-8"), "human-report")
    for key_id, pem in sorted(public_keys.items()):
        _emit(f"pubkeys/{key_id}.pem", pem, "public-key", key_id=key_id)
    for key_id, pem in sorted(pq_public_keys.items()):
        if isinstance(pem, str):
            pem = pem.encode("ascii")
        _emit(f"pq-pubkeys/{key_id}.pem", pem, "pq-public-key", key_id=key_id)
    for key_id, stmt in sorted(capability_statements.items()):
        _emit(
            f"statements/{key_id}.json",
            json.dumps(stmt.to_dict(), ensure_ascii=False).encode("utf-8"),
            "capability-statement",
            key_id=key_id,
        )
    for i, cap in enumerate(capabilities):
        _emit(
            f"capabilities/{i}.json",
            json.dumps(cap, ensure_ascii=False).encode("utf-8"),
            "capability-token",
        )
    for i, proof in enumerate(proofs):
        _emit(
            f"proofs/{i}.json",
            json.dumps(proof, ensure_ascii=False).encode("utf-8"),
            "proof",
        )

    index = {
        "kind": PACK_KIND,
        "generated_at": generated_at,
        "tool_version": __version__,
        "audit_key_id": manifest["signer_key_id"],
        "require_pq": bool(require_pq),
        "members": members,
        "verify": "raucle audit-pack verify <dir>",
    }
    # Sign the index so its member digests are themselves under signature — the
    # member set cannot be forged/re-indexed without the audit private key.
    index = _sign_index(index, audit_key_pem)
    (out / INDEX_NAME).write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")
    return index


def _resolve_member(pack: Path, rel: str) -> Path | None:
    """Resolve an index member path *inside* the pack, or ``None`` if it escapes.

    The ``PACK.json`` index is attacker-controllable, so a member ``path`` like
    ``../../etc/passwd`` or an absolute path must never make verification read
    outside the pack — that would break the self-contained / no-external-input
    guarantee. Returns the resolved path only when it stays under the pack root.
    """
    if os.path.isabs(rel) or ".." in Path(rel).parts:
        return None
    try:
        resolved = (pack / rel).resolve()
        root = pack.resolve()
    except OSError:
        return None
    if not resolved.is_relative_to(root):
        return None
    return resolved


@dataclass
class PackVerdict:
    """Outcome of an offline pack verification. ``ok`` is the AND of all checks.

    ``signer_trusted`` is ``None`` when no expected signer was pinned (the pack is
    then only proven *internally consistent*, not proven to come from a specific
    custodian), ``True``/``False`` when an anchor was supplied and matched/didn't.
    """

    ok: bool
    integrity_ok: bool
    manifest_signature_ok: bool
    chain_valid: bool
    reproducible: bool
    index_signature_ok: bool = False
    signer_key_id: str | None = None
    signer_trusted: bool | None = None
    receipt_count: int = 0
    reasons: list[str] = field(default_factory=list)


def _verify_pack_integrity(
    pack: Path, index: dict[str, Any], reasons: list[str]
) -> tuple[bool, dict[str, Path]]:
    """Check pack kind, resolve every member safely, verify hashes.

    Returns ``(integrity_ok, resolved_paths)``.
    """
    integrity_ok = True
    if index.get("kind") != PACK_KIND:
        integrity_ok = False
        reasons.append(f"unexpected pack kind {index.get('kind')!r}")

    resolved: dict[str, Path] = {}
    for m in index.get("members", []):
        safe = _resolve_member(pack, m["path"])
        if safe is None:
            integrity_ok = False
            reasons.append(f"member path escapes the pack: {m['path']!r}")
            continue
        if not safe.is_file():
            integrity_ok = False
            reasons.append(f"missing member {m['path']}")
            continue
        if _file_hash(safe) != m["sha256"]:
            integrity_ok = False
            reasons.append(f"hash mismatch for {m['path']} (tampered)")
            continue
        resolved[m["path"]] = safe
    return integrity_ok, resolved


def _verify_pack_manifest(
    resolved: dict[str, Path], index_signer: str | None, reasons: list[str]
) -> tuple[bool, dict[str, Any], str | None]:
    """Verify manifest signature and signer agreement.

    Returns ``(manifest_ok, manifest, signer_key_id)``.
    """
    manifest_member = resolved.get("manifest.json")
    signer_key_id = index_signer
    if manifest_member is None:
        reasons.append("missing or untrusted manifest.json")
        return False, {}, signer_key_id

    manifest = json.loads(manifest_member.read_text())
    manifest_signature_ok = verify_manifest(manifest)
    if not manifest_signature_ok:
        reasons.append("manifest signature did not verify")
    elif manifest.get("signer_key_id") != index_signer:
        manifest_signature_ok = False
        reasons.append(
            f"manifest signer {manifest.get('signer_key_id')!r} does not match "
            f"index signer {index_signer!r}"
        )
    return manifest_signature_ok, manifest, signer_key_id


def _load_pack_members(
    members: list[dict[str, Any]], resolved: dict[str, Path]
) -> tuple[
    dict[str, bytes],
    dict[str, bytes],
    dict[str, CapabilityStatement],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Load bundled public keys, PQ keys, capability statements, tokens, and proofs."""
    public_keys: dict[str, bytes] = {}
    pq_public_keys: dict[str, bytes] = {}
    statements: dict[str, CapabilityStatement] = {}
    capabilities: list[dict[str, Any]] = []
    proofs: list[dict[str, Any]] = []
    for m in members:
        safe = resolved.get(m["path"])
        if safe is None:
            continue
        role = m.get("role")
        if role == "public-key":
            public_keys[m["key_id"]] = safe.read_bytes()
        elif role == "pq-public-key":
            pq_public_keys[m["key_id"]] = safe.read_bytes()
        elif role == "capability-statement":
            statements[m["key_id"]] = CapabilityStatement.from_dict(json.loads(safe.read_text()))
        elif role == "capability-token":
            capabilities.append(json.loads(safe.read_text()))
        elif role == "proof":
            proofs.append(json.loads(safe.read_text()))
    return public_keys, pq_public_keys, statements, capabilities, proofs


def _verify_pack_chain(
    resolved: dict[str, Path],
    public_keys: dict[str, bytes],
    reasons: list[str],
    pq_public_keys: dict[str, bytes] | None = None,
    require_pq: bool = False,
) -> tuple[bool, int]:
    """Verify the receipt chain against bundled keys (classical + PQ).

    ``require_pq`` mirrors the pack's own declaration: packs built with
    ``require_pq=True`` record it in the index, and verification enforces
    what the pack says about itself.
    """
    pq_public_keys = pq_public_keys or {}
    chain_member = resolved.get(_CHAIN_JSONL)
    if chain_member is not None and public_keys:
        try:
            verdict = ProvenanceVerifier(
                public_keys=public_keys, pq_public_keys=pq_public_keys or None
            ).verify_chain(chain_member)
        except PQUnavailable as exc:
            reasons.append(f"pack declares PQ-signed receipts but ML-DSA is unavailable: {exc}")
            return False, 0
        if not verdict.valid:
            reasons.append("receipt chain did not verify against bundled keys")
        return verdict.valid, verdict.receipt_count
    reasons.append("missing/untrusted chain.jsonl or bundled public keys")
    return False, 0


def _verify_pack_reproducibility(
    resolved: dict[str, Path],
    manifest: dict[str, Any],
    chain_member: Path | None,
    public_keys: dict[str, bytes],
    proofs: list[dict[str, Any]],
    capabilities: list[dict[str, Any]],
    statements: dict[str, CapabilityStatement],
    index: dict[str, Any],
    reasons: list[str],
) -> bool:
    """Check that the manifest body and report.html are reproducible from the bundle."""
    if not manifest or chain_member is None or not public_keys:
        return False
    try:
        rebuilt = build_report(
            chain_member,
            public_keys,
            proofs,
            generated_at=index["generated_at"],
            capabilities=capabilities,
            capability_statements=statements or None,
        )
        body_ok = _canonical_json(rebuilt.body()) == _canonical_json(manifest["body"])
        if not body_ok:
            reasons.append("manifest body is not reproducible from bundled evidence")
        html_member = resolved.get("report.html")
        html_ok = html_member is not None and html_member.read_bytes() == render_html(
            manifest
        ).encode("utf-8")
        if not html_ok:
            reasons.append("report.html does not match the signed manifest")
        return body_ok and html_ok
    except (ValueError, OSError, KeyError) as exc:
        reasons.append(f"reproducibility rebuild failed: {exc}")
        return False


def verify_pack(pack_dir: str | Path, *, expected_signer: str | None = None) -> PackVerdict:
    """Verify an audit pack **fully offline** — no network, no external inputs.

    Checks, all of which must pass for ``ok``:

    0. **Index signature** — ``PACK.json`` is itself Ed25519-signed, so its member
       digests are under signature: no member (even one whose bytes never flow
       into the manifest body — an unused capability-token field, an unknown-role
       blob) can be forged and re-indexed without the audit private key.
    1. **Integrity** — every member's on-disk sha256 matches the ``PACK.json``
       index, every member path stays inside the pack, and the index ``kind`` is
       recognised (nothing added, dropped, altered, or pointing outside).
    2. **Manifest signature** — the manifest's Ed25519 signature verifies, and its
       signer id matches the index signer.
    3. **Chain validity** — the receipt chain verifies against the bundled public
       keys alone (the custody invariant, checked without the cloud provider).
    4. **Reproducibility** — rebuilding the report from the bundled evidence
       yields a byte-identical manifest *body* AND the bundled ``report.html``
       matches the manifest's own rendering, so neither the machine-readable nor
       the human-readable view can be doctored independently of the signature.

    Trust anchor: a self-signed manifest proves *internal consistency*, not that
    the pack came from the claimed custodian — an attacker can rebuild the whole
    pack and sign it with their own key. Pin ``expected_signer`` (the custodian's
    audit key id) to additionally require the manifest signer to match; without
    it, ``ok`` means "internally consistent" and ``signer_trusted`` is ``None``.
    """
    pack = Path(pack_dir)
    reasons: list[str] = []
    index_path = pack / INDEX_NAME
    if not index_path.is_file():
        return PackVerdict(False, False, False, False, False, reasons=[f"missing {INDEX_NAME}"])
    index = json.loads(index_path.read_text())

    # The index is itself signed, so its member digests are under signature: a
    # member cannot be forged-and-re-indexed (even a member whose bytes do not
    # flow into the manifest body, e.g. an unused capability-token field) without
    # the audit private key. `index_signer` is the authoritative custodian id.
    index_signature_ok, index_signer = _verify_index_signature(index)
    if not index_signature_ok:
        reasons.append("index (PACK.json) signature did not verify")

    # 1. Integrity: resolve each member safely and check its hash.
    integrity_ok, resolved = _verify_pack_integrity(pack, index, reasons)

    # 2. Manifest self-signature (+ optional pinned-signer trust anchor).
    manifest_signature_ok, manifest, signer_key_id = _verify_pack_manifest(
        resolved, index_signer, reasons
    )

    signer_trusted: bool | None = None
    if expected_signer is not None:
        signer_trusted = index_signature_ok and signer_key_id == expected_signer
        if not signer_trusted:
            reasons.append(
                f"custodian signer {signer_key_id!r} does not match pinned key {expected_signer!r}"
            )

    # Reload bundled public keys + capability statements (only verified members).
    members = index.get("members", [])
    (
        public_keys,
        pq_public_keys,
        statements,
        capabilities,
        proofs,
    ) = _load_pack_members(members, resolved)
    require_pq = bool(index.get("require_pq", False))

    # 3. Chain verifies against the bundled keys alone (classical + any PQ keys).
    chain_member = resolved.get(_CHAIN_JSONL)
    chain_valid, receipt_count = _verify_pack_chain(
        resolved,
        public_keys,
        reasons,
        pq_public_keys=pq_public_keys,
        require_pq=require_pq,
    )

    # 4. Reproducibility: signed manifest body AND rendered report must follow
    #    from the bundled evidence — neither view doctorable independently.
    reproducible = _verify_pack_reproducibility(
        resolved,
        manifest,
        chain_member,
        public_keys,
        proofs,
        capabilities,
        statements,
        index,
        reasons,
    )

    ok = (
        index_signature_ok
        and integrity_ok
        and manifest_signature_ok
        and chain_valid
        and reproducible
        and signer_trusted is not False
    )
    return PackVerdict(
        ok=ok,
        integrity_ok=integrity_ok,
        manifest_signature_ok=manifest_signature_ok,
        chain_valid=chain_valid,
        reproducible=reproducible,
        index_signature_ok=index_signature_ok,
        signer_key_id=signer_key_id,
        signer_trusted=signer_trusted,
        receipt_count=receipt_count,
        reasons=reasons,
    )
