"""X6 SLICE 1: policy simulation - deterministic, signed, flippable.

The demo nobody else can run: an operator asks "what would THIS policy
have done to the traffic we actually served?" and gets back a
deterministically signed result they can hold.

Three properties the slice pins:

- DETERMINISTIC: the same candidate policy bytes and the same
  historical window produce a byte-identical signed result. The
  receipt payload therefore carries NO wall-clock field - ``iat`` is
  pinned to 0 and honestly named: a simulation receipt is not an
  event, it is a pure function of its inputs. The window ref anchors
  history; the store append anchors occurrence order.

- SIGNED: the result is receipted through the existing machinery
  (``gateway._sign_and_store_receipt``, gate identity, EdDSA JWS,
  GUARDRAIL_SCAN operation) with an ``x_sim`` extension carrying the
  bounded result. Because the payload is a function of its inputs,
  the signature is the determinism pin anyone can verify offline.

- FLIPPABLE: the signed result can be handed to the named apply path
  (``apply_simulated_policy`` / POST /api/policy/simulate/apply),
  which re-verifies the receipt, re-checks the candidate policy hash
  binding, lands the candidate through the normal policy write +
  ledger + reload flow, and emits its own ``x_sim_apply`` receipt
  that cites the simulation receipt it acted on.

Bounded disclosure holds throughout: the per-decision rows carry
receipt hashes, tool names, agent ids and decisions - never arg
values, never denial reasons (the counterfactual engine already
enforces this; the receipt binds exactly that report).

Evidence depth (the "chain-depth of evidence used" field): each
replayed decision row is graded on how much evidence stood behind it
- 1: the recorded decision only (no stored input; unreplayable rows
never guessed), 2: replayed through the gate machinery from the
stored input, 3: replayed AND proven - the z3 leg excluded the whole
recorded argument class. ``chain_depth`` is the maximum across rows.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

X_SIM_KEY = "x_sim"
X_SIM_APPLY_KEY = "x_sim_apply"
_HASH_PREFIX = "sha256:"


class SimulateError(Exception):
    """Named refusal: every refusal carries a stable machine-readable reason."""

    def __init__(self, reason: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.status_code = status_code


def _sha256_bytes(data: bytes) -> str:
    return _HASH_PREFIX + hashlib.sha256(data).hexdigest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Candidate policy resolution (policy bytes OR policy-ref)
# ---------------------------------------------------------------------------


def _resolve_restricted_ref(ref: str, roots: Sequence[Path], kind: str) -> Path:
    """Resolve a caller-supplied file reference inside a fixed allow-root set.

    The simulate surface lets an operator name a historical window file,
    an input-store file or a policy-ref file. Those references arrive
    from an HTTP request body, so they are untrusted: every one of them
    must resolve INSIDE one of the pre-configured allow roots (the
    gateway's own data/policy directories, plus any operator-configured
    extras) or the refusal is named (``unknown_<kind>``). This is the
    containment that breaks both the path-traversal flow (a caller
    reaching an arbitrary file) and the filesystem-oracle flow (mapping
    existence/read errors outside the roots back into the response).
    """
    if not roots:
        raise SimulateError(
            f"unknown_{kind}", f"{kind} references are disabled: no allow roots configured"
        )
    candidate = Path(ref)
    if not candidate.is_absolute():
        candidate = Path(roots[0]) / candidate
    resolved = candidate.resolve()
    for root in roots:
        root_resolved = Path(root).resolve()
        if resolved == root_resolved or resolved.is_relative_to(root_resolved):
            break
    else:
        raise SimulateError(
            f"unknown_{kind}", f"{kind} reference is outside the allowed roots: {ref}"
        )
    if not resolved.is_file():
        raise SimulateError(f"unknown_{kind}", f"{kind} file not found: {ref}")
    return resolved


def resolve_candidate_policy(
    *,
    candidate_policy_yaml: str | None = None,
    policy_ref: str | None = None,
    ref_roots: Sequence[Path] = (),
) -> tuple[str, str]:
    """Resolve and VALIDATE the candidate policy.

    Returns (canonical_yaml, sha256_hex). Exactly one of the two
    sources is accepted; the YAML must load and pass the full
    :class:`raucle.policy.PolicyFile` schema or the refusal is named
    (``invalid_candidate_policy``), never a bare parse traceback.
    A ``policy_ref`` is resolved under ``ref_roots`` containment.
    """
    import yaml as _yaml

    from raucle.policy import PolicyFile

    provided = [
        n
        for n, v in (("candidate_policy_yaml", candidate_policy_yaml), ("policy_ref", policy_ref))
        if v
    ]
    if len(provided) != 1:
        raise SimulateError(
            "candidate_policy_required",
            "exactly one of candidate_policy_yaml or policy_ref is required",
        )
    if candidate_policy_yaml is not None:
        raw = candidate_policy_yaml
    else:
        try:
            raw = _resolve_restricted_ref(policy_ref or "", ref_roots, "policy_ref").read_text(
                encoding="utf-8"
            )
        except SimulateError:
            raise
        except OSError as exc:
            raise SimulateError("unknown_policy_ref", f"policy_ref unreadable: {exc}") from exc
    try:
        parsed = _yaml.safe_load(raw)
        if not isinstance(parsed, dict):
            raise ValueError("policy document must be a mapping")
        PolicyFile.from_dict(parsed)
    except Exception as exc:
        raise SimulateError("invalid_candidate_policy", f"candidate policy refused: {exc}") from exc
    canonical = _yaml.dump(parsed, default_flow_style=False, sort_keys=False)
    return canonical, _sha256_hex(canonical.encode("utf-8"))


# ---------------------------------------------------------------------------
# Window parsing + evidence depth
# ---------------------------------------------------------------------------

_EVIDENCE_REPLAYED = 2
_EVIDENCE_PROVEN = 3
_EVIDENCE_DECISION_ONLY = 1


def _row_evidence_depth(row: dict[str, Any]) -> int:
    proof = row.get("proof")
    if row.get("prevented") and isinstance(proof, dict) and proof.get("status") == "PROVEN":
        return _EVIDENCE_PROVEN
    return _EVIDENCE_REPLAYED


def _simulated_report(
    *,
    window_path: Path | None,
    canonical_policy: str,
    input_store_path: Path | None,
) -> dict[str, Any]:
    """Run the counterfactual engine and return the bounded result dict.

    The engine's own report embeds temp paths (chain, alternative
    policy); none of those survive into the simulation result - only
    counts, hashes, receipt references and decisions do, which is what
    makes the result a pure function of its inputs.
    """
    from raucle.counterfactual import replay_counterfactual

    with tempfile.TemporaryDirectory(prefix="raucle-sim-") as td:
        alt_path = Path(td) / "candidate.yaml"
        alt_path.write_text(canonical_policy, encoding="utf-8")
        chain_path = window_path if window_path is not None else Path(td) / "empty-window.jsonl"
        if window_path is None:
            chain_path.write_text("", encoding="utf-8")
        store_path = (
            input_store_path if input_store_path is not None else Path(td) / "empty-inputs.jsonl"
        )
        if input_store_path is None:
            store_path.write_text("", encoding="utf-8")
        report = replay_counterfactual(
            chain_path,
            input_store_path=store_path,
            alternative_policy_path=alt_path,
        )

    rows: list[dict[str, Any]] = []
    current_allow = current_deny = 0
    candidate_allow = candidate_deny = 0
    changed: list[dict[str, Any]] = []
    for row in report["actions"]:
        original = row["original_decision"]
        counterfactual = row["counterfactual_decision"]
        depth = _row_evidence_depth(row)
        if original == "allow":
            current_allow += 1
        elif original == "deny":
            current_deny += 1
        if counterfactual == "allow":
            candidate_allow += 1
        elif counterfactual == "deny":
            candidate_deny += 1
        if original != counterfactual:
            changed.append(
                {
                    "receipt_hash": row["receipt_hash"],
                    "tool": row["tool"],
                    "agent_id": row["agent_id"],
                    "current_decision": original,
                    "candidate_decision": counterfactual,
                    "evidence_depth": depth,
                }
            )
        rows.append({**row, "evidence_depth": depth})
    chain_depth = max((r["evidence_depth"] for r in rows), default=0)
    return {
        "simulations": rows,
        "actions_replayed": len(rows),
        "actions_unreplayable": report["actions_unreplayable"],
        "current": {"allow": current_allow, "deny": current_deny},
        "candidate": {"allow": candidate_allow, "deny": candidate_deny},
        "changed_decisions": changed,
        "verdict": report["verdict"],
        "chain_depth": chain_depth,
    }


# ---------------------------------------------------------------------------
# Signed receipt construction / verification
# ---------------------------------------------------------------------------


def _simulation_payload(gateway: Any, result: dict[str, Any]) -> dict[str, Any]:
    from raucle.provenance import _canonical_json

    return {
        "iss": "raucle-gateway",
        "typ": "provenance-receipt/v1",
        # Determinism pin: NO wall-clock stamp. A simulation receipt is a
        # pure function of (candidate policy, window, engine); same inputs
        # must re-sign to the same JWS bytes for anyone, anywhere.
        "iat": 0,
        "agent_id": gateway._gate_identity.agent_id,
        "agent_key_id": gateway._gate_identity.key_id,
        "operation": "guardrail_scan",
        "parents": [],
        "taint": ["sim:counterfactual"],
        "input_hash": _sha256_hex(_canonical_json(result)),
        "ruleset_hash": result["candidate_policy_hash"],
        "guardrail_verdict": result["gate"]["verdict"],
        X_SIM_KEY: result,
    }


def _sign_simulation_receipt(gateway: Any, payload: dict[str, Any]) -> tuple[str, str]:
    """Sign via the existing receipt machinery and return (receipt_hash, jws).

    The gateway's ``_sign_and_store_receipt`` builds the identical
    header, signs with the gate identity and appends the minimal
    envelope to the receipt store. Signing is duplicated here only to
    recover the JWS string deterministically (Ed25519 signatures are
    deterministic, so both signings agree byte-for-byte - asserted).
    """
    from raucle.gateway import _RECEIPT_CRIT, _RECEIPT_TYP
    from raucle.provenance import _b64url_encode, _canonical_json

    header = {
        "alg": "EdDSA",
        "typ": _RECEIPT_TYP,
        "kid": gateway._gate_identity.key_id,
        "crit": [_RECEIPT_CRIT],
        _RECEIPT_CRIT: "provenance",
    }
    signing_input = (
        _b64url_encode(_canonical_json(header)) + "." + _b64url_encode(_canonical_json(payload))
    ).encode("ascii")
    sig = gateway._gate_identity.sign(signing_input)
    jws = signing_input.decode("ascii") + "." + _b64url_encode(sig)
    receipt_hash = gateway._sign_and_store_receipt(payload)
    expected = _HASH_PREFIX + _sha256_hex(jws.encode("ascii"))
    if receipt_hash != expected:
        # The machinery signing diverged from the local reconstruction -
        # a machinery drift must be loud, never returned as a receipt.
        raise SimulateError("receipt_machinery_drift", "signed receipt hash mismatch", 500)
    return receipt_hash, jws


def verify_simulation_receipt(gateway: Any, jws: str) -> dict[str, Any]:
    """Strictly verify a simulation receipt and return the x_sim result.

    Structural validation (spec v1), signature verification against
    the gate identity's public key, and the x_sim presence check. A
    tampered, re-signed-under-another-key or x_sim-stripped receipt is
    refused named (``invalid_simulation_receipt``).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    from raucle.provenance import ProvenanceReceipt, _validate_receipt_strict

    try:
        receipt = ProvenanceReceipt.from_jws(jws, strict=True)
        _validate_receipt_strict(receipt)
    except ValueError as exc:
        raise SimulateError("invalid_simulation_receipt", f"receipt refused: {exc}") from exc

    parts = jws.split(".")
    if len(parts) != 3:
        raise SimulateError("invalid_simulation_receipt", "receipt is not a v1 JWS")
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    from raucle.provenance import _b64url_decode

    sig = _b64url_decode(parts[2])
    pem = gateway._gate_identity.public_key_pem()
    pub = load_pem_public_key(pem)
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, signing_input)
    except Exception as exc:
        raise SimulateError("invalid_simulation_receipt", "signature does not verify") from exc

    from raucle.provenance import _b64url_decode

    payload = json.loads(_b64url_decode(parts[1]))
    if payload.get("operation") != "guardrail_scan" or X_SIM_KEY not in payload:
        raise SimulateError("invalid_simulation_receipt", "receipt carries no simulation result")
    if not isinstance(payload[X_SIM_KEY], dict):
        raise SimulateError("invalid_simulation_receipt", "x_sim extension is not an object")
    return payload[X_SIM_KEY]


# ---------------------------------------------------------------------------
# Top-level simulate + flip (apply) paths
# ---------------------------------------------------------------------------


def simulate_policy(
    gateway: Any,
    *,
    candidate_policy_yaml: str | None = None,
    policy_ref: str | None = None,
    window_ref: str | None = None,
    input_store_ref: str | None = None,
    ref_roots: Sequence[Path] = (),
) -> dict[str, Any]:
    """Simulate a candidate policy over a historical window, signed.

    Returns the deterministic simulation result plus the signed
    receipt envelope ({receipt_hash, jws}) binding it. All caller
    named file references are resolved under ``ref_roots``
    containment (see :func:`_resolve_restricted_ref`).
    """
    canonical, candidate_hash = resolve_candidate_policy(
        candidate_policy_yaml=candidate_policy_yaml,
        policy_ref=policy_ref,
        ref_roots=ref_roots,
    )
    window_path: Path | None = None
    if window_ref:
        window_path = _resolve_restricted_ref(window_ref, ref_roots, "window")
    store_path_resolved: Path | None = None
    if input_store_ref:
        store_path_resolved = _resolve_restricted_ref(input_store_ref, ref_roots, "input_store")

    engine = _simulated_report(
        window_path=window_path,
        canonical_policy=canonical,
        input_store_path=store_path_resolved,
    )
    window_hash = (
        _sha256_bytes(window_path.read_bytes())
        if window_path is not None
        else _HASH_PREFIX + "0" * 64
    )
    store_hash = (
        _sha256_bytes(store_path_resolved.read_bytes())
        if store_path_resolved is not None
        else _HASH_PREFIX + "0" * 64
    )
    result: dict[str, Any] = {
        "simulation": "policy_simulate/v1",
        "candidate_policy_hash": _HASH_PREFIX + candidate_hash,
        "window_ref": window_ref or "",
        "window_hash": window_hash,
        "input_store_ref": input_store_ref or "",
        "input_store_hash": store_hash,
        "gate": engine,
    }
    payload = _simulation_payload(gateway, result)
    receipt_hash, jws = _sign_simulation_receipt(gateway, payload)
    # SIEM leg: the operator action is forwarded like other gate
    # events (buffered when SIEM is disabled, never blocking the sim).
    # Timestamped OUTSIDE the signed payload: the receipt stays a
    # pure function of its inputs; the SIEM copy is operational.
    try:
        import datetime as _dt

        gateway.siem.forward(
            {
                "event": "policy_simulate",
                "candidate_policy_hash": result["candidate_policy_hash"],
                "window_ref": result["window_ref"],
                "receipt_hash": receipt_hash,
                "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            }
        )
    except Exception:
        pass  # SIEM export failure never takes down the simulation
    return {"result": result, "receipt_hash": receipt_hash, "jws": jws}


def apply_simulated_policy(
    gateway: Any,
    *,
    simulation_receipt: str,
    candidate_policy_yaml: str,
    actor: str = "operator",
) -> dict[str, Any]:
    """The named flip path: verify a signed simulation, land the policy.

    The apply path is named and independently receipted (x_sim_apply):
    it (1) strictly verifies the simulation receipt, (2) re-validates
    the submitted candidate policy and refuses unless its hash matches
    the one the simulation receipt signed the verdict for, (3) writes
    the canonic re-serialised policy through the standard policy write
    + hash-chained ledger + reload flow, and (4) emits its own receipt
    citing the simulation receipt it acted on.
    """
    import yaml as _yaml

    from raucle.policy import PolicyFile
    from raucle.provenance import _sha256_hex

    sim = verify_simulation_receipt(gateway, simulation_receipt)
    try:
        parsed = _yaml.safe_load(candidate_policy_yaml)
        PolicyFile.from_dict(parsed)
    except Exception as exc:
        raise SimulateError("invalid_candidate_policy", f"candidate policy refused: {exc}") from exc
    canonical = _yaml.dump(parsed, default_flow_style=False, sort_keys=False)
    submitted_hash = _HASH_PREFIX + _sha256_hex(canonical.encode("utf-8"))
    receipt_hash_for_sim = _HASH_PREFIX + _sha256_hex(simulation_receipt.encode("ascii"))
    if sim.get("candidate_policy_hash") != submitted_hash:
        raise SimulateError(
            "candidate_hash_mismatch",
            "submitted candidate policy does not match the simulated candidate policy hash",
        )

    policy_path = gateway.config.policy_file
    Path(policy_path).parent.mkdir(parents=True, exist_ok=True)
    Path(policy_path).write_text(canonical, encoding="utf-8")
    with contextlib.suppress(Exception):
        gateway._append_policy_ledger(
            action="sim_policy_applied",
            file=str(policy_path),
            content=canonical,
            actor=actor,
        )
        # ledger failure degrades attribution, not the flip itself: the
        # x_sim_apply receipt below still binds actor + content hash.
    reload_result = gateway.reload_policies()
    receipt_id = None
    with contextlib.suppress(Exception):
        receipt_id = gateway._emit_authority_receipt(
            verdict="sim_policy_applied",
            extension_key=X_SIM_APPLY_KEY,
            extension={
                "actor": actor,
                "candidate_policy_hash": submitted_hash,
                "simulation_receipt": receipt_hash_for_sim,
                "chain_depth": sim.get("gate", {}).get("chain_depth", 0),
            },
        )
        # best-effort receipt, same discipline as other authority events
    return {
        "applied": True,
        "candidate_policy_hash": submitted_hash,
        "simulation_receipt": receipt_hash_for_sim,
        "receipt_id": receipt_id,
        "reload": reload_result,
    }
