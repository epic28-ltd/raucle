"""X2 slice 3: cross-org receipt verification through the Trust Registry.

The acceptance this module serves (approved X2 programme): a third party
verifies ANOTHER organisation's receipt offline, holding no prior key
material from either organisation and trusting no organisation's operator.
The one trust anchor is the **registry operator key**, pinned out of band.

Given only two artefacts - the receipt and the registry artifact - the
verifier recomputes three legs, each named:

1. **The registry leg** - the artifact is a tamper-evident, operator-signed
   append-only log (:class:`~raucle.trust_registry.TrustRegistry`). The
   chain is re-hashed, every operator signature is verified against the
   PINNED anchor key (never a key riding the artifact), and the freshness
   pins (``min_index`` / ``expected_head_hash`` / ``max_age_seconds``)
   refuse a stale-snapshot rollback that would hide a later revocation.
2. **The receipt leg** - the receipt's ``agent_key_id`` is resolved through
   the registry (unknown or revoked keys are named refusals, fail-closed)
   and the signature is verified by the same
   :class:`~raucle.provenance.ProvenanceVerifier` an auditor runs over an
   exported chain - not a parallel reimplementation.
3. **The scope leg** - when the registry's record metadata carries the
   org's published capability statement, the receipt's claims are held to
   it: identity binding, statement signature, expiry, and tool/model
   conformance. Without a published statement the leg is honestly
   **unstated**, never green.

An optional **registration leg** pairs the verdict with the hosted
transparency log (X2 slice 2): the log's inclusion proof binds the receipt
digest to a signed epoch checkpoint, so "when was it registered" is
answered with an operator-independent timestamp. The proof is verified
with :func:`~raucle.transparency.verify_log_inclusion` against a PINNED
log operator key - the key riding the proof is convenience material,
never verification input.

Fail-closed throughout: every refusal is named, and nothing partially
verified is ever reported as verified.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raucle.provenance import CapabilityStatement, ProvenanceVerifier, VerificationReport
from raucle.transparency import STATUS_LOG_INCLUDED
from raucle.trust_registry import RegistryIntegrityError, TrustRegistry

#: The envelope fields of a chain line (the x2 verifier page's contract).
_ENVELOPE_FIELDS = ("receipt_hash", "jws")


@dataclass
class CrossOrgVerdict:
    """The outcome of a cross-org verification. Every refusal reason is
    named; ``scope_verified`` is ``None`` when the registry publishes no
    capability statement for the key (the leg is unstated, not green)."""

    valid: bool = False
    reasons: list[str] = field(default_factory=list)
    registry_verified: bool = False
    issuer: str = ""
    key_id: str = ""
    revoked: bool = False
    receipt_verified: bool = False
    scope_verified: bool | None = None
    log_status: str | None = None
    registered_at: int | None = None
    checkpoint_iat: int | None = None
    head_index: int = -1
    head_hash: str = ""


def _refuse(reasons: list[str], verdict: CrossOrgVerdict | None = None) -> CrossOrgVerdict:
    v = verdict or CrossOrgVerdict()
    v.valid = False
    v.reasons.extend(reasons)
    return v


def _parse_chain_envelopes(raw: str) -> tuple[list[dict[str, Any]] | None, str]:
    """Parse the brace form of the receipt input: chain envelope lines one
    per line, blank lines ignored. Every line must be exactly a
    {receipt_hash, jws} envelope - unknown envelope fields are malleability
    and are refused the same way the chain verifier refuses them. Returns
    ``(envelopes, refusal)`` - exactly one is set."""
    envelopes: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            env = json.loads(line)
        except json.JSONDecodeError as exc:
            return None, f"chain line is not JSON: {exc}"
        if not isinstance(env, dict) or set(env) != set(_ENVELOPE_FIELDS):
            return None, (
                "chain line is not a {receipt_hash, jws} envelope "
                "(unknown envelope fields are malleability)"
            )
        envelopes.append(env)
    if not envelopes:
        return None, "no receipt supplied"
    return envelopes, ""


def _bare_jws_envelope(raw: str) -> list[dict[str, Any]]:
    """Synthesise the single envelope for a bare compact JWS: the hash is
    recomputed over the exact JWS bytes, so a receipt handed over without
    its envelope still carries the digest the whole chain verifies."""
    import hashlib

    digest = "sha256:" + hashlib.sha256(raw.encode("ascii", "ignore")).hexdigest()
    return [{"receipt_hash": digest, "jws": raw}]


def _parse_receipt_text(text: str) -> tuple[list[dict[str, Any]] | None, str]:
    """Parse the receipt input: chain envelope lines (one per line, blank
    lines ignored), or a single bare compact JWS (hash recomputed over the
    exact JWS bytes). Returns ``(envelopes, refusal)`` - exactly one of
    the two is set."""
    raw = str(text).strip()
    if not raw:
        return None, "no receipt supplied"
    if raw.startswith("{"):
        return _parse_chain_envelopes(raw)
    return _bare_jws_envelope(raw), ""


def _payload_of(jws: str) -> dict[str, Any] | None:
    """Decode a compact JWS payload (JSON), or None when malformed."""
    parts = str(jws).split(".")
    if len(parts) != 3:
        return None
    try:
        import base64

        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _load_registry(
    *,
    registry_jsonl: str | None,
    registry_path: str | Path | None,
) -> TrustRegistry:
    """Load the registry artifact from pasted text or a file path. Both
    parse with the duplicate-key rejecter (a crafted entry with duplicate
    keys must not smuggle a key_id past integrity checks)."""
    if registry_jsonl is not None:
        return TrustRegistry.from_jsonl(str(registry_jsonl))
    if registry_path is not None:
        return TrustRegistry(Path(registry_path))
    raise ValueError("no registry artifact supplied (registry_jsonl or registry_path)")


def _verify_registry_leg(
    reg: TrustRegistry,
    *,
    operator_public_pem: bytes | None,
    min_index: int | None,
    expected_head_hash: str | None,
    max_age_seconds: int | None,
    now: int | None,
) -> list[str]:
    """The registry leg: signed header, chain + operator signatures against
    the pinned anchor, issuer uniqueness, freshness pins. Returns named
    refusal reasons (empty when the artifact verifies)."""
    reasons: list[str] = []
    header = reg._entries[0] if reg._entries else {}  # noqa: SLF001
    if not header.get("signed"):
        reasons.append(
            "registry artifact is unsigned: an unsigned log cannot anchor "
            "cross-org trust (publish with an operator signer)"
        )
        return reasons
    if operator_public_pem is None:
        reasons.append(
            "no registry anchor pinned: pass operator_public_pem (the registry "
            "operator's public key, obtained out of band); an artifact verified "
            "only against its own chain is not authenticated"
        )
        return reasons
    try:
        reg.verify_integrity(
            operator_public_pem=operator_public_pem,
            min_index=min_index,
            expected_head_hash=expected_head_hash,
            max_age_seconds=max_age_seconds,
            now=now,
        )
    except RegistryIntegrityError as exc:
        reasons.append(f"registry artifact refused: {exc}")
    return reasons


def _statement_from_record(
    record: Any, key_id: str
) -> tuple[CapabilityStatement | None, list[str]]:
    """Extract and bind the org's published capability statement from the
    registry record metadata. The statement must speak for the SAME key
    the registry resolved: a statement for another key is substitutable
    scope material and is a named refusal."""
    raw = (record.metadata or {}).get("capability_statement")
    if raw is None:
        return None, []
    if not isinstance(raw, dict):
        return None, ["registry metadata carries a malformed capability statement (not an object)"]
    try:
        stmt = CapabilityStatement.from_dict(raw)
    except ValueError as exc:
        return None, [f"registry metadata carries a malformed capability statement: {exc}"]
    if stmt.key_id != key_id:
        return None, [
            f"published capability statement binds key {stmt.key_id!r}, not the "
            f"registry-resolved key {key_id!r} (substitutable scope material refused)"
        ]
    if stmt.public_key_pem != record.public_key_pem:
        return None, [
            "published capability statement does not carry the registry-resolved public key"
        ]
    return stmt, []


def _verify_log_leg(
    log_proof: Any,
    *,
    log_operator_public_key_pem: str | None,
    expect_digest: str | None,
    verdict: CrossOrgVerdict,
) -> None:
    """The registration leg. A supplied proof must verify against the
    pinned log operator key; its failure denies the verdict. No proof
    leaves an honestly named residual."""
    if log_proof is None:
        verdict.reasons.append(
            "log inclusion proof not supplied: when this receipt was registered "
            "is unverified (named residual, not a failure)"
        )
        return
    if not log_operator_public_key_pem:
        verdict.reasons.append(
            "log operator key not pinned: an inclusion proof verified against "
            "its own riding key would be self-attested; pass "
            "log_operator_public_key_pem obtained out of band"
        )
        verdict.valid = False
        verdict.log_status = "LOG-UNPINNED"
        return
    from raucle.transparency import verify_log_inclusion

    result = verify_log_inclusion(
        log_proof,
        operator_public_key_pem=log_operator_public_key_pem,
        expect_digest=expect_digest,
    )
    verdict.log_status = result.status
    if result.status != STATUS_LOG_INCLUDED:
        verdict.valid = False
        verdict.reasons.extend(result.reasons)
        return
    # Registration time, surfaced from the SIGNED checkpoint (and the
    # committed entry): decode the payload only after the signature held.
    try:
        parts = str(log_proof["checkpoint_jws"]).split(".")
        import base64

        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        verdict.checkpoint_iat = int(payload.get("iat", 0))
    except (IndexError, ValueError, TypeError):
        verdict.checkpoint_iat = None
    verdict.registered_at = int(log_proof["entries"][0]["registered_at"])


def _envelope_kids(envelopes: list[dict[str, Any]]) -> tuple[list[str] | None, str]:
    """Collect every signing key named by the receipt envelopes. The
    receipt leg resolves ALL of them through the registry, so a payload
    that cannot name a key is an upfront named refusal. Returns
    ``(kids, refusal)`` - exactly one is set, the kids in sorted order."""
    kids: set[str] = set()
    for env in envelopes:
        payload = _payload_of(env["jws"])
        if payload is None:
            return None, ("a receipt is not a 3-segment compact JWS (PQ hybrids unsupported here)")
        kid = str(payload.get("agent_key_id", ""))
        if not kid:
            return None, "a receipt payload carries no agent_key_id"
        kids.add(kid)
    return sorted(kids), ""


def _resolve_registry_keys(
    reg: TrustRegistry, kids: list[str], verdict: CrossOrgVerdict
) -> tuple[dict[str, Any], dict[str, bytes], list[str] | None]:
    """Resolve every signing key through the registry: unknown and revoked
    keys are named, fail-closed refusals, never a silent skip. Returns
    ``(records, public_keys, refusal)`` - the refusal list is set only when
    the verdict must refuse; records and public keys are empty in that
    case. A revoked key marks the verdict revoked before the refusal."""
    records: dict[str, Any] = {}
    public_keys: dict[str, bytes] = {}
    for kid in kids:
        record = reg.resolve(kid)
        if record is None:
            return {}, {}, [f"agent key {kid} is not in the registry (unknown issuer)"]
        if record.revoked:
            verdict.revoked = True
            return (
                {},
                {},
                [
                    f"agent key {kid} is revoked in the registry"
                    + (f" (reason: {record.revoked_reason})" if record.revoked_reason else "")
                ],
            )
        records[kid] = record
        public_keys[kid] = record.public_key_pem.encode("ascii")
    return records, public_keys, None


def _published_statements(
    records: dict[str, Any], verdict: CrossOrgVerdict
) -> tuple[dict[str, CapabilityStatement], list[str]]:
    """Extract each resolved key's published capability statement from the
    registry record metadata. A statement must bind the SAME registry-
    resolved key (checked by :func:`_statement_from_record`): substitutable
    scope material fails the scope leg and is a named refusal, with
    scope_verified failed before the verdict refuses."""
    caps: dict[str, CapabilityStatement] = {}
    for kid, record in records.items():
        stmt, stmt_reasons = _statement_from_record(record, kid)
        if stmt_reasons:
            verdict.scope_verified = False
            return {}, stmt_reasons
        if stmt is not None:
            caps[kid] = stmt
    return caps, []


def _run_provenance_leg(
    verifier: ProvenanceVerifier, envelopes: list[dict[str, Any]]
) -> VerificationReport:
    """The receipt leg: the same :class:`ProvenanceVerifier` an auditor
    runs over an exported chain. The envelopes are written to a temporary
    file that is removed on every path, so verification never leaves
    receipt bytes behind."""
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as fh:
            tmp = Path(fh.name)
            for env in envelopes:
                fh.write(json.dumps(env) + "\n")
        return verifier.verify_chain(tmp)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def _classify_scope(
    verdict: CrossOrgVerdict,
    report: VerificationReport,
    caps: dict[str, CapabilityStatement],
    kids: list[str],
) -> None:
    """Classify the scope leg after the chain verifies. With published
    statements every receipt is held to them; with none supplied the leg
    is honestly UNSTATED (None) with a named residual - never green on
    scope and never a refusal in itself. The verdict is green exactly
    when the receipt leg is."""
    verdict.receipt_verified = bool(report.valid)
    verdict.reasons.extend(report.errors)
    if caps:
        verdict.scope_verified = bool(report.valid) and report.capability_violations == 0
    else:
        verdict.scope_verified = None
        verdict.reasons.append(
            "scope unstated: the registry publishes no capability statement for "
            f"the signing key(s) {sorted(kids)}, so what this agent was allowed "
            "to do is not pinned (the signature and hash legs still verify)"
        )
    verdict.valid = bool(report.valid)


def verify_receipt_cross_org(
    receipt_text: str,
    *,
    registry_jsonl: str | None = None,
    registry_path: str | Path | None = None,
    operator_public_pem: bytes | None = None,
    min_index: int | None = None,
    expected_head_hash: str | None = None,
    max_age_seconds: int | None = None,
    now: int | None = None,
    log_proof: dict[str, Any] | None = None,
    log_operator_public_key_pem: str | None = None,
) -> CrossOrgVerdict:
    """Verify another organisation's receipt offline through the Trust
    Registry: signature (who signed), scope (what was allowed), and,
    when an inclusion proof is supplied, registration (when it was
    registered).

    Parameters
    ----------
    receipt_text:
        The receipt material: chain envelope lines
        ``{"receipt_hash": …, "jws": …}`` (one per line, the export shape a
        third party is handed), or a bare compact JWS (the envelope hash is
        then recomputed). Every signing key named by a receipt is resolved
        through the registry.
    registry_jsonl / registry_path:
        The registry artifact, as pasted JSONL text or a file path.
    operator_public_pem:
        The pinned registry operator public key (the out-of-band anchor).
        Required: an artifact without a pinned anchor is refused.
    min_index / expected_head_hash / max_age_seconds / now:
        Freshness pins, forwarded to :meth:`TrustRegistry.verify_integrity`.
        A stale snapshot that could hide a later revocation is refused.
    log_proof / log_operator_public_key_pem:
        The transparency log's inclusion proof for this receipt's digest
        and the pinned log operator key (a separate anchor: the log is a
        separate operator from the registry).
    """
    verdict = CrossOrgVerdict()

    # -- the registry leg ---------------------------------------------------
    try:
        reg = _load_registry(registry_jsonl=registry_jsonl, registry_path=registry_path)
    except (ValueError, RegistryIntegrityError, OSError) as exc:
        return _refuse([f"registry artifact refused: {exc}"])
    registry_reasons = _verify_registry_leg(
        reg,
        operator_public_pem=operator_public_pem,
        min_index=min_index,
        expected_head_hash=expected_head_hash,
        max_age_seconds=max_age_seconds,
        now=now,
    )
    if registry_reasons:
        return _refuse(registry_reasons)
    verdict.registry_verified = True
    head = reg.head()
    verdict.head_index = head["index"]
    verdict.head_hash = head["hash"]

    # -- the receipt leg: resolve every signing key through the registry ----
    envelopes, refusal = _parse_receipt_text(receipt_text)
    if envelopes is None:
        return _refuse([refusal], verdict)
    kids, kid_refusal = _envelope_kids(envelopes)
    if kids is None:
        return _refuse([kid_refusal], verdict)
    records, public_keys, key_refusal = _resolve_registry_keys(reg, kids, verdict)
    if key_refusal:
        return _refuse(key_refusal, verdict)
    verdict.key_id = min(kids)
    verdict.issuer = records[verdict.key_id].issuer

    # -- the receipt leg: the same verifier an auditor runs -----------------
    caps, stmt_refusal = _published_statements(records, verdict)
    if stmt_refusal:
        return _refuse(stmt_refusal, verdict)
    report = _run_provenance_leg(
        ProvenanceVerifier(public_keys=public_keys, capabilities=caps or None),
        envelopes,
    )
    _classify_scope(verdict, report, caps, kids)

    # -- the registration leg (when a proof is supplied) ---------------------
    # The registration leg binds the chain's LEAF receipt (the last
    # envelope, the newest one a third party is handed); the contract is
    # documented in docs/spec/x2-cross-org-v0.1.md.
    _verify_log_leg(
        log_proof,
        log_operator_public_key_pem=log_operator_public_key_pem,
        expect_digest=str(envelopes[-1]["receipt_hash"]),
        verdict=verdict,
    )
    return verdict


__all__ = [
    "CrossOrgVerdict",
    "verify_receipt_cross_org",
]
