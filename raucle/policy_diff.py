"""S2 (EPIC S2): the receipt-bound bilateral policy diff.

The counterfactual replay (:func:`raucle.counterfactual.replay_counterfactual`)
answers the incident-review question, but its report is just JSON: a
counterparty who receives it has no way to know it was not retyped. This
module turns that report into a SIGNED, receipt-bound diff document:

- the document binds the chain head (the last ``receipt_hash`` in the
  incident chain), the SHA-256 digests of BOTH policy files (original and
  alternative), and the replay's full bounded summary and actions;
- the reviewing operator's Ed25519 key signs the whole document (compact
  JWS, same canonical-json discipline as receipts, ``alg=EdDSA`` only);
- verification is OFFLINE and fail-closed: given only the public key and
  the referenced material (chain file, both policy files, input store),
  :func:`verify_policy_diff_document` re-checks the signature, the
  document hash, every binding, and RE-RUNS the replay and requires the
  result to match byte-for-byte (bounded fields). Any divergence is a
  named verification error — nothing is inferred.

"Bilateral" shape: the two sides are the reviewing operator (who signs the
verdict) and the counterparty (who re-derives it independently). Neither
needs the other's private key; the signature binds verdict to evidence.

Bounded disclosure is inherited from the replay report: no denial reasons,
no argument values — the document carries only ids, digests and decisions.

No floats in signed payload material: timestamps are integer epochs (the
canonical JSON layer rejects floats by design).
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from raucle.provenance import _canonical_json

#: The document type string carried in the JWS header and payload root.
POLICY_DIFF_TYP = "raucle/policy-diff/v1"

_HEADER_CRIT = "raucle"

#: The summary/actions keys that must match on the re-run replay.
_BOUND_REPLAY_KEYS = (
    "actions_replayed",
    "actions_unreplayable",
    "allowed_under_original",
    "prevented_by_alternative",
    "still_allowed_by_alternative",
    "denies_under_both",
    "prevented_proven",
    "prevented_refuted",
    "prevented_undecided",
    "actions",
)


def _payload_for(
    report: dict[str, Any],
    *,
    chain_head: str,
    original_policy_sha256: str,
    alternative_policy_sha256: str,
    key_id: str,
    generated_at: int,
) -> dict[str, Any]:
    """Build the signed payload root (document + bindings)."""
    document = {
        "chain_head": chain_head,
        "original_policy_sha256": original_policy_sha256,
        "alternative_policy_sha256": alternative_policy_sha256,
        "summary": {k: report[k] for k in _BOUND_REPLAY_KEYS},
    }
    return {
        "typ": POLICY_DIFF_TYP,
        "kind": "policy-diff",
        "iat": int(generated_at),
        "key_id": key_id,
        "doc_hash": _sha256_hex(_canonical_json(document)),
        "document": document,
    }


def _sha256_hex(data: bytes) -> str:
    # local copy: the receipts module spells this the same way and the
    # digest must be byte-identical across formats
    return hashlib.sha256(data).hexdigest()


def _canonical(payload: dict[str, Any]) -> bytes:
    from raucle.provenance import _canonical_json  # deferred: import cycle

    return _canonical_json(payload)


def chain_head_from_file(chain_path: str | Path) -> str:
    """The last ``receipt_hash`` line in a receipt chain ("" when empty)."""
    head = ""
    with open(chain_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                head = json.loads(line).get("receipt_hash", "") or head
            except json.JSONDecodeError:
                continue
    return head


def _file_sha256(path: str) -> str:
    with open(path, "rb") as fh:
        return _sha256_hex(fh.read())


def sign_policy_diff_document(
    signer: Any,
    *,
    key_id: str,
    report: dict[str, Any],
    chain_path: str,
    original_policy_path: str,
    alternative_policy_path: str,
    generated_at: int | None = None,
) -> dict[str, Any]:
    """Sign a counterfactual report into a receipt-bound diff document.

    *signer* is an Ed25519 private-key object with ``.sign(bytes)`` (an
    :class:`raucle.provenance.AgentIdentity` qualifies). Returns the
    envelope ``{"typ", "jws", "receipt_hash"}`` — the same outer shape a
    receipt chain line uses (``receipt_hash`` = sha256 of the JWS, the
    chain reference the document binds), so the document can be archived
    beside the chain it cites.
    """
    from raucle.provenance import _b64url_encode

    if generated_at is None:
        import time

        generated_at = int(time.time())

    document = _payload_for(
        report,
        chain_head=chain_head_from_file(chain_path),
        original_policy_sha256=_file_sha256(original_policy_path),
        alternative_policy_sha256=_file_sha256(alternative_policy_path),
        key_id=key_id,
        generated_at=generated_at,
    )
    header = {
        "alg": "EdDSA",
        "typ": POLICY_DIFF_TYP,
        "kid": key_id,
        "crit": [_HEADER_CRIT],
        _HEADER_CRIT: "policy-diff",
    }
    signing_input = (
        _b64url_encode(_canonical(header)) + "." + _b64url_encode(_canonical(document))
    ).encode("ascii")
    sig = signer.sign(signing_input)
    jws = signing_input.decode("ascii") + "." + _b64url_encode(sig)
    return {
        "typ": POLICY_DIFF_TYP,
        "jws": jws,
        "receipt_hash": "sha256:" + _sha256_hex(jws.encode("ascii")),
    }


def verify_policy_diff_document(
    envelope: dict[str, Any],
    *,
    public_key_pem: bytes,
    chain_path: str,
    original_policy_path: str,
    alternative_policy_path: str,
    input_store_path: str,
) -> tuple[bool, list[str]]:
    """Offline, fail-closed verification of a signed policy-diff document.

    Given only the public key and the referenced material, re-derives
    everything: signature, document hash, chain-head and both policy-file
    digests, and a byte-for-byte re-run of the counterfactual replay.
    Returns ``(True, [])`` or ``(False, [named errors])`` — never a
    partial pass.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    from raucle.counterfactual import replay_counterfactual

    errors: list[str] = []
    jws = envelope.get("jws", "") if isinstance(envelope, dict) else ""
    if not isinstance(jws, str) or jws.count(".") != 2:
        return False, ["envelope carries no compact JWS"]
    header_b64, payload_b64, sig_b64 = jws.split(".")

    try:
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "==" * (-len(header_b64) % 4)))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==" * (-len(payload_b64) % 4)))
    except (ValueError, json.JSONDecodeError) as exc:  # JSONDecodeError is a ValueError
        return False, [f"undecodable JWS segment: {exc}"]

    if header.get("alg") != "EdDSA":
        errors.append(f"expected alg=EdDSA, found {str(header.get('alg'))!r}")
    if header.get("typ") != POLICY_DIFF_TYP:
        errors.append(f"expected typ {POLICY_DIFF_TYP!r}, found {str(header.get('typ'))!r}")
    if payload.get("typ") != POLICY_DIFF_TYP or payload.get("kind") != "policy-diff":
        errors.append("payload is not a policy-diff document")

    document = payload.get("document")
    if not isinstance(document, dict):
        errors.append("payload carries no document")
        return False, errors

    # signature check (fail-closed: a non-verifying key is a named error)
    try:
        key = load_pem_public_key(public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            errors.append(f"public key is not Ed25519 (got {type(key).__name__})")
        else:
            key.verify(
                base64.urlsafe_b64decode(sig_b64 + "==" * (-len(sig_b64) % 4)),
                f"{header_b64}.{payload_b64}".encode("ascii"),
            )
    except Exception:  # noqa: BLE001 - fail-closed: non-verifying signature is an error
        errors.append("signature does not verify under the supplied public key")

    # document hash binding: the digest lives at the payload root, over the
    # document body (a record never hashes itself WITH its recorded field)
    recorded = payload.pop("doc_hash", None)
    doc_hash = _sha256_hex(_canonical(document))
    if recorded != doc_hash:
        errors.append("doc_hash does not match the document payload")

    # external bindings
    head = chain_head_from_file(chain_path)
    if str(document.get("chain_head")) != head:
        errors.append(
            f"chain_head binding does not match the chain file "
            f"({document.get('chain_head')!r} vs {head!r})"
        )
    for name, path in (
        ("original_policy_sha256", original_policy_path),
        ("alternative_policy_sha256", alternative_policy_path),
    ):
        digest = _file_sha256(path)
        if str(document.get(name)) != digest:
            errors.append(f"{name} binding does not match {path}")

    # re-run the replay and require an exact match on bounded fields
    if not errors:
        try:
            fresh = replay_counterfactual(
                chain_path,
                input_store_path=input_store_path,
                alternative_policy_path=alternative_policy_path,
            )
        except Exception as exc:  # noqa: BLE001 - re-run failure is a named error
            errors.append(f"replay re-run failed: {exc}")
        else:
            bound = document.get("summary", {})
            for k in _BOUND_REPLAY_KEYS:
                if bound.get(k) != fresh.get(k):
                    errors.append(f"replayed {k} does not match the document")

    return (not errors), errors
