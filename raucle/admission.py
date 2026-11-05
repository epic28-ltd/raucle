"""Admission policy hooks (P1.4c, F4).

As a policy author I can refuse unattested agents at the gate: an
enrolment (or activation) whose descriptor manifest fails verification is
refused and the refusal is receipted.

Additive reuse, not a fork:

- The verification primitive is :func:`raucle.agent_registry.verify_descriptor`
  unchanged - admission is a policy lens over the P1.4a verdict, not a
  second verifier.
- Refusal receipting rides the gateway's EXISTING authority-receipt
  machinery (``_emit_authority_receipt``, the same shape as suspend /
  approval receipts): no new receipt scheme, no new signing path.
- Fail closed: every failure mode (tampered manifest hash, bad signature,
  unknown version, unknown fields, retired descriptor, unreadable key,
  unexpected error) resolves to a refusal, never to an allow. An
  unexpected exception is a refusal with the exception type named, so a
  broken verifier cannot become a bypass.

The refused ``reason`` strings carry only the verification check that
failed (mirroring :class:`~raucle.agent_registry.DescriptorError`); they
are evidence labels, not security guidance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from raucle.agent_registry import AgentDescriptor, DescriptorError, verify_descriptor

#: Enrolment lifecycle states admission admits by default. ``retired`` is
#: fail-closed: a retired descriptor never passes an admission check unless
#: the caller explicitly asks to evaluate retired records (allow_retired).
ADMITTABLE_STATUS: str = "enrolled"


@dataclass(frozen=True)
class AdmissionVerdict:
    """The admission decision (fail-closed shape, mirrors DescriptorVerdict)."""

    allowed: bool
    reason: str = ""
    descriptor: AgentDescriptor | None = None


def admission_check(
    descriptor: dict[str, Any] | AgentDescriptor,
    issuer_public_pem: bytes | str,
    *,
    allow_retired: bool = False,
) -> AdmissionVerdict:
    """Admission over one descriptor: verify offline, then check status.

    Refused (allowed=False) on: any :class:`DescriptorVerdict` failure
    (tampered body, bad signature, unknown version, unknown fields,
    malformed attestation, key mismatch), a non-``enrolled`` status
    (retired), or ANY unexpected error - the last resolves to a refusal
    with the exception type named and no detail text, fail closed.
    """
    try:
        verdict = verify_descriptor(descriptor, issuer_public_pem)
        if not verdict.valid:
            return AdmissionVerdict(
                allowed=False, reason=f"descriptor verification failed: {verdict.reason}"
            )
        parsed = verdict.descriptor
        if parsed is None:  # defensive: a valid verdict carries a descriptor
            return AdmissionVerdict(allowed=False, reason="descriptor verification failed")
        if parsed.status != ADMITTABLE_STATUS and not allow_retired:
            return AdmissionVerdict(
                allowed=False, reason=f"agent is {parsed.status or 'unstatused'}"
            )
        return AdmissionVerdict(allowed=True, descriptor=parsed)
    except DescriptorError as exc:
        return AdmissionVerdict(allowed=False, reason=f"descriptor verification failed: {exc}")
    except Exception as exc:  # noqa: BLE001 - fail closed on ANY failure
        return AdmissionVerdict(
            allowed=False, reason=f"admission check failed: {type(exc).__name__}"
        )


__all__ = ["ADMITTABLE_STATUS", "AdmissionVerdict", "admission_check"]
