"""Typed error hierarchy for raucle cryptographic and policy paths.

Exists so the cryptographic and capability-issuance code paths can fail
loudly with named exceptions distinct from generic ``ValueError`` /
``Exception``. Callers (and operators) that need to distinguish "explicit
configuration was malformed" from "input data was bad" can match on these
named types.

The defining principle: **explicitly-configured-but-broken = REFUSE;
simply-absent = WARN loudly and continue in an explicitly-marked
unsigned mode.** Never silent.
"""

from __future__ import annotations


class ConfigurationError(Exception):
    """An explicitly-set configuration value cannot be loaded or used.

    Raised when:

    * ``RAUCLE_DETECT_VERDICT_KEY_PEM`` is set but the PEM is unparseable.
    * ``RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM`` is set but invalid.
    * A :class:`raucle.verdicts.VerdictSigner` or
      :class:`raucle.audit.Ed25519Signer` is supplied with a
      private key whose public bytes cannot be extracted.

    Distinct from the safe-default-with-warning path, which logs a
    ``WARNING`` and continues in explicitly-marked unsigned mode.
    """


class PolicyUnproven(Exception):
    """Strict capability-mint mode refused to mint a token.

    Raised by :meth:`raucle.capability.CapabilityIssuer.mint` when
    the issuer was constructed with ``require_proof=True`` (or the
    ``RAUCLE_REQUIRE_PROOF=1`` env var) and one of:

    * no :class:`~raucle.prove.ProofResult` was supplied,
    * the supplied ``ProofResult.status`` is not ``"PROVEN"``,
    * the supplied ``ProofResult``'s ``grammar_hash`` or ``policy_hash``
      does not match the caller-asserted ``grammar_hash`` / ``policy_hash``
      on the capability being minted.

    Default behaviour (``require_proof=False``) is unchanged: mint still
    succeeds without a proof, and the resulting token has no proof
    binding.
    """


class BootMemoryCeilingExceeded(Exception):
    """The gateway boot's RSS projection exceeds the configured ceiling.

    Raised by the boot memory preflight (:mod:`raucle.chain_rotation`)
    BEFORE any store is loaded. The gateway boot refuses rather than
    balloon: the 18 Nov demo incident had the process OOM-killed at
    boot, repeatedly, under ``restart:always``, because the audit chain
    and the receipt-store index grow without bound while the box does
    not. The message names the projected size, the ceiling, and the
    operator's escape route (``raucle rotate-chain``).
    """


class RotationRefusedError(Exception):
    """A chain rotation refused before touching anything.

    Raised by ``raucle rotate-chain`` (:func:`raucle.chain_rotation.rotate_chain`)
    when the rotation would be unsafe or pointless:

    * an archive with today's date suffix already exists (idempotent-safe:
      a same-day re-run must never overwrite or duplicate an archive),
    * nothing to rotate (no configured store exists),
    * no operator identity (``--operator`` or ``RAUCLE_OPERATOR``).

    The refusal is all-or-nothing: no file is renamed when it raises.
    """
