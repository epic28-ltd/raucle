"""Cross-organisation agent handshake (P2) — trust resolved from the registry.

P1 (the :mod:`~raucle.trust_registry`) made issuer keys *resolvable* across
orgs. P2 is the protocol that uses it: two agents from different organisations
establish a verifiable, capability-gated call and exchange signed receipts —
**without any prior key exchange between them.** Each side resolves the other's
key from the shared Trust Registry.

The flow (org A's agent calls org B's agent):

    org A                         shared registry                      org B
    -----                         ---------------                      -----
    mint capability token  --------- publish kA -------->  (kA resolvable)
    present (token, tool, args)  ----------------------------------->  accept_call()
                                       resolve kA  <------------------    │
                                  (fail-closed if unknown/revoked)        │
                                                                gate.check(token, args)
    verify B's ack  <----------- publish kB ------------- emit signed ack receipt
    (resolve kB)                                                          │

Org B never held org A's key beforehand; it resolves ``token.key_id`` from the
registry, checks revocation, runs the capability gate, and answers with a signed
acknowledgement that org A verifies the same way (resolving B's key). The result
is a cross-org receipt pair anchored in the registry — the interop primitive for
multi-agent ecosystems.

Fail-closed throughout: an initiator key that is unknown or revoked in the
registry is rejected before the gate ever runs.
"""

from __future__ import annotations

import base64 as _base64
import datetime as _dt
import logging
import secrets as _secrets
from dataclasses import dataclass, field
from typing import Any

from raucle.audit import Ed25519Signer, _canonical_json, _sha256_hex
from raucle.capability import Capability, CapabilityGate, GateDecision
from raucle.trust_registry import TrustRegistry

logger = logging.getLogger(__name__)


def _b64(data: bytes) -> str:
    return _base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return _base64.urlsafe_b64decode(data + padding)


#: Handshake protocol identifier (carried in the ack receipt).
HANDSHAKE_VERSION = "raucle-handshake/v1"


def _now() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


@dataclass
class HandshakeRequest:
    """What an initiator (org A) presents to a responder (org B).

    Carries the capability token (which names ``key_id`` — the trust anchor the
    responder resolves from the registry), the concrete call, and the caller's
    agent id. No public key is included: the responder resolves it.
    """

    capability_token: dict[str, Any]
    tool: str
    args: dict[str, Any]
    caller_agent_id: str
    nonce: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_token": self.capability_token,
            "tool": self.tool,
            "args": self.args,
            "caller_agent_id": self.caller_agent_id,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> HandshakeRequest:
        return cls(
            capability_token=d["capability_token"],
            tool=d["tool"],
            args=d.get("args") or {},
            caller_agent_id=d.get("caller_agent_id", ""),
            nonce=d.get("nonce", ""),
        )


@dataclass
class HandshakeResult:
    """The responder's verified verdict + a signed acknowledgement receipt."""

    accepted: bool
    reason: str
    initiator_key_id: str
    ack_receipt: dict[str, Any] = field(default_factory=dict)


def build_request(
    token: Capability,
    *,
    tool: str,
    args: dict[str, Any],
    nonce: str = "",
) -> HandshakeRequest:
    """Initiator side: package a minted capability token + the concrete call.

    The token already carries ``key_id`` (the trust anchor) and is Ed25519-signed
    by the initiator's issuer, so nothing else needs signing here — the responder
    resolves and verifies it. A fresh random ``nonce`` is generated when none is
    given, so every handshake is uniquely bound (anti-replay).
    """
    return HandshakeRequest(
        capability_token=token.to_dict(),
        tool=tool,
        args=dict(args),
        caller_agent_id=token.agent_id,
        nonce=nonce or _secrets.token_hex(16),
    )


def accept_call(
    request: HandshakeRequest,
    *,
    registry: TrustRegistry,
    responder_signer: Ed25519Signer,
    responder_id: str,
    seen: set[str] | None = None,
) -> HandshakeResult:
    """Responder side (org B): resolve the initiator's key from the **registry**,
    capability-gate the call, and return a signed acknowledgement.

    Steps (fail-closed):

    1. Parse the presented token; read its ``key_id``.
    2. Resolve ``key_id`` from the shared registry. Unknown or revoked → REJECT
       (no gate runs). This is the cross-org trust decision, made with no prior
       key exchange.
    3. Build a gate anchored on the resolved key and check the call.
    4. Emit a signed ack receipt (the responder's own key, also registry-
       published) stating ACCEPT/REJECT, so the initiator can verify the outcome.
    """
    try:
        token = Capability.from_dict(request.capability_token)
    except Exception as exc:
        return _ack(
            responder_signer,
            responder_id,
            accepted=False,
            reason=f"malformed capability token: {type(exc).__name__}",
            initiator_key_id="",
            request=request,
        )

    # Responder-side replay protection (codex r6): the responder rejects a request
    # it has already accepted. Pass a persistent ``seen`` set keyed across calls;
    # the replay key binds the issuer key, token, and per-handshake nonce. A
    # missing/empty nonce is itself a replay risk, so it is refused when dedup is on.
    if seen is not None:
        if not request.nonce:
            return _ack(
                responder_signer,
                responder_id,
                accepted=False,
                reason="request has no nonce (required for replay protection)",
                initiator_key_id=token.key_id,
                request=request,
                token=token,
            )
        replay_key = f"{token.key_id}:{token.token_id}:{request.nonce}"
        if replay_key in seen:
            return _ack(
                responder_signer,
                responder_id,
                accepted=False,
                reason="replayed request (this (token, nonce) was already handled)",
                initiator_key_id=token.key_id,
                request=request,
                token=token,
            )
        seen.add(replay_key)

    key_id = token.key_id
    record = registry.resolve(key_id)  # fail-closed: None for unknown
    if record is None or record.revoked:
        revoked = record is not None and record.revoked
        reason = (
            f"initiator key_id {key_id} is revoked in the registry"
            if revoked
            else f"initiator key_id {key_id} is not in the registry (untrusted issuer)"
        )
        return _ack(
            responder_signer,
            responder_id,
            accepted=False,
            reason=reason,
            initiator_key_id=key_id,
            request=request,
            token=token,
        )

    # Anti-impersonation: the token's claimed issuer must match the registry's
    # authoritative record for this key (codex #2). A registered org cannot
    # present a token claiming to be a DIFFERENT org.
    if token.issuer != record.issuer:
        return _ack(
            responder_signer,
            responder_id,
            accepted=False,
            reason=(
                f"issuer mismatch: token claims {token.issuer!r} but key {key_id} "
                f"is registered to {record.issuer!r}"
            ),
            initiator_key_id=key_id,
            request=request,
            token=token,
        )

    gate = CapabilityGate(trusted_issuers={key_id: record.public_key_pem})
    decision: GateDecision = gate.check(
        token, tool=request.tool, args=request.args, agent_id=request.caller_agent_id
    )
    return _ack(
        responder_signer,
        responder_id,
        accepted=decision.allowed,
        reason=decision.reason or ("authorised" if decision.allowed else "denied"),
        initiator_key_id=key_id,
        request=request,
        token=token,
    )


def _ack(
    signer: Ed25519Signer,
    responder_id: str,
    *,
    accepted: bool,
    reason: str,
    initiator_key_id: str,
    request: HandshakeRequest,
    token: Capability | None = None,
) -> HandshakeResult:
    """Build and sign the responder's acknowledgement receipt.

    The signed body binds the FULL request (``request_hash``) and the
    capability ``token_id``, so a signed ACCEPT cannot be replayed into a
    different call or capability context (codex #3).
    """
    body = {
        "version": HANDSHAKE_VERSION,
        "responder": responder_id,
        "responder_key_id": _sha256_hex(signer.public_key_pem())[:16],
        "initiator_key_id": initiator_key_id,
        "caller_agent_id": request.caller_agent_id,
        "tool": request.tool,
        "args_hash": _sha256_hex(_canonical_json(request.args)),
        "request_hash": _sha256_hex(_canonical_json(request.to_dict())),
        "token_id": token.token_id if token is not None else "",
        "decision": "ACCEPT" if accepted else "REJECT",
        "reason": reason,
        "nonce": request.nonce,
        "issued_at": _now(),
    }
    sig = signer.sign(_canonical_json(body))
    receipt = {"body": body, "signature": _b64(sig)}
    return HandshakeResult(
        accepted=accepted,
        reason=reason,
        initiator_key_id=initiator_key_id,
        ack_receipt=receipt,
    )


def _validate_ack_shape(
    ack_receipt: dict[str, Any],
) -> tuple[dict[str, Any], str] | tuple[None, str]:
    """Check the ack receipt's shape and version. Returns ``(body, sig)`` or ``(None, error)``."""
    if not isinstance(ack_receipt, dict):
        return None, "malformed ack receipt (not an object)"
    body = ack_receipt.get("body")
    sig = ack_receipt.get("signature")
    if not isinstance(body, dict) or not isinstance(sig, str):
        return None, "malformed ack receipt"
    if body.get("version") != HANDSHAKE_VERSION:
        return None, f"unknown handshake version {body.get('version')!r}"
    return body, sig


def _verify_ack_signature(body: dict[str, Any], sig: str, record: Any) -> str | None:
    """Verify the ack signature against the responder's key. Returns error or None."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        loaded = serialization.load_pem_public_key(record.public_key_pem.encode())
        if not isinstance(loaded, Ed25519PublicKey):
            return "responder key is not Ed25519"
        loaded.verify(_b64d(sig), _canonical_json(body))
    except (InvalidSignature, ValueError, TypeError):
        return "ack signature did not verify against responder key"
    return None


def _check_ack_bindings(
    body: dict[str, Any],
    record: Any,
    responder_key_id: str,
    expected_responder: str | None,
    expected_nonce: str | None,
    expected_token_id: str | None,
    expected_request: HandshakeRequest | None,
    expected_decision: str | None,
) -> str | None:
    """Check anti-impersonation and anti-replay bindings. Returns error or None."""
    # Anti-impersonation (symmetric to accept_call): the signed responder NAME
    # must match the registry's authoritative record for the responder key, so a
    # registered attacker key cannot sign an ack claiming to be a DIFFERENT org
    # (codex round 4).
    if body.get("responder") != record.issuer:
        return (
            f"responder identity mismatch: ack claims {body.get('responder')!r} but key "
            f"{responder_key_id} is registered to {record.issuer!r}"
        )
    if expected_responder is not None and body.get("responder") != expected_responder:
        return f"responder is {body.get('responder')!r}, expected {expected_responder!r}"
    if expected_nonce is not None and body.get("nonce") != expected_nonce:
        return "ack nonce mismatch (possible replay)"
    if expected_token_id is not None and body.get("token_id") != expected_token_id:
        return "ack token_id mismatch (bound to a different capability)"
    if expected_request is not None:
        want = _sha256_hex(_canonical_json(expected_request.to_dict()))
        if body.get("request_hash") != want:
            return "ack request_hash mismatch (bound to a different request)"
    if expected_decision is not None and body.get("decision") != expected_decision:
        return f"decision is {body.get('decision')}, expected {expected_decision}"
    return None


def verify_ack(
    ack_receipt: dict[str, Any],
    *,
    registry: TrustRegistry,
    expected_nonce: str | None = None,
    expected_token_id: str | None = None,
    expected_request: HandshakeRequest | None = None,
    expected_decision: str | None = None,
    expected_responder: str | None = None,
    require_binding: bool = True,
) -> tuple[bool, str]:
    """Initiator side: verify the responder's ack, resolving the responder's
    key from the **same registry** (no prior key exchange with org B either).

    Returns ``(ok, reason)``. Always: the responder's key resolves to an active
    registry key and the signature verifies. Anti-replay/substitution (pass the
    ones you can): ``expected_nonce``, ``expected_token_id``, and
    ``expected_request`` (its ``request_hash`` must match the signed body) bind
    the ack to *this* handshake. ``ok=True`` means the ack is AUTHENTIC and bound
    — it does NOT by itself mean ACCEPT; pass ``expected_decision="ACCEPT"`` to
    require acceptance, or read ``body['decision']``.
    """
    body, sig = _validate_ack_shape(ack_receipt)
    if body is None:
        return False, sig

    # Replay-safe by default: a successful verify must be BOUND to this handshake.
    # The initiator always holds the request it sent, so it can always pass one of
    # these. Without a binding an authentic-but-replayed ack would pass (codex r5).
    # A reusable capability token is NOT a replay binding: an old ACCEPT for the
    # same token verifies for a new call. Require a per-handshake binding —
    # expected_request or expected_nonce — for a successful verify (codex r7).
    # expected_token_id remains an additional capability-context check below.
    if require_binding and expected_nonce is None and expected_request is None:
        return False, (
            "no anti-replay binding supplied: pass expected_request or expected_nonce "
            "(expected_token_id alone is insufficient), or require_binding=False to only "
            "check authenticity"
        )

    responder_key_id = body.get("responder_key_id", "")
    record = registry.resolve(responder_key_id)  # fail-closed
    if record is None or record.revoked:
        why = "revoked" if (record is not None and record.revoked) else "unknown"
        return False, f"responder key_id {responder_key_id} is {why} in the registry"

    sig_error = _verify_ack_signature(body, sig, record)
    if sig_error is not None:
        return False, sig_error

    binding_error = _check_ack_bindings(
        body,
        record,
        responder_key_id,
        expected_responder,
        expected_nonce,
        expected_token_id,
        expected_request,
        expected_decision,
    )
    if binding_error is not None:
        return False, binding_error

    return True, f"ack verified: {body.get('decision')}"


__all__ = [
    "HANDSHAKE_VERSION",
    "HandshakeRequest",
    "HandshakeResult",
    "build_request",
    "accept_call",
    "verify_ack",
]
