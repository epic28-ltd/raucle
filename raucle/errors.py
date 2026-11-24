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


class ChainTailMalformed(Exception):
    """The bounded reverse tail read refused to recover a chain tail (L1).

    Raised by :class:`raucle.audit.HashChainSink` construction when the
    final window of a chain file is torn, unparsable or internally
    unlinked. The whole-scan resume this replaces silently skipped
    unparsable lines and chained onto whatever came next; the bounded
    resume fails closed instead and names the file, the line number, the
    byte offset and the operator path (``raucle rotate-chain``, which
    archives the broken chain verifiably and starts a fresh one).
    """


class KeyRotationRefusedError(Exception):
    """An operator-plane key rotation refused before touching anything.

    Raised by ``raucle operator rotate-keys``
    (:func:`raucle.key_rotation.rotate_keys`) when the rotation would be
    unsafe or pointless:

    * no operator key registry configured
      (``RAUCLE_OPERATOR_KEY_REGISTRY``),
    * the configured registry file is absent (fail-closed: without the
      registry, receipts minted before the rotation could not verify
      afterwards),
    * no signing key to rotate (the key store is empty),
    * the signing key is not registered, or is revoked,
    * a signed registry without the registry operator key to append with,
    * no operator identity (``--operator`` or ``RAUCLE_OPERATOR``),
    * today's retirement archive already exists (idempotent-safe).

    The refusal is all-or-nothing: no file moves, no registry entry and
    no receipt is minted when it raises.
    """


class KeyStoreRegistryMismatch(Exception):
    """The gateway boot refused: the local key store and the operator key
    registry disagree (X3 slice 3, the split-brain guard).

    Raised at boot when ``RAUCLE_OPERATOR_KEY_REGISTRY`` is configured
    and the local signing key is not the registry's vouched-for active
    entry: the registry never saw the key, or it retired or revoked it
    (a rotation whose registry update landed but whose key-store update
    did not, or a hand-restored old key). The unregistered and retired
    refusals name the reconcile
    command (``raucle operator rotate-keys``) and the restart: the boot
    never serves receipts on a key the registry does not vouch for, and
    the guard binds at construction, so a reconcile requires a restart.
    """


class ReceiptStoreSealRefused(Exception):
    """The receipt store refused to seal or resume a segment with a torn
    or corrupt record line (external review of v0.23.7).

    Raised by :class:`raucle.receipt_store.SegmentedReceiptStore` in two
    fail-closed situations:

    * sealing refuses: ``seal_now`` and the size-threshold rollover seal
      refuse a segment containing any non-blank unparsable line. The
      ``.meta`` sidecar is never written for a refused seal, the active
      file stays open and writable, and the operator decides how to
      resolve the line. Receipts keep appending into the segment.
    * resume refuses: reopening an existing writable segment after a
      restart (the lazy append path and the lazy seal path) refuses when
      the segment's tail (the last non-blank line) is unparsable.
      Appending after a torn write would chain a second record stream
      inside one file, so the resume raises at open instead.

    The message names the segment file and the offending physical line
    number. Nothing is skipped and no seal proceeds past a torn record;
    earlier behaviour counted torn lines as receipts, recorded a last
    receipt hash from a torn segment, and sealed it read-only. The
    gateway surfaces the refusal through its receipt-emission failure
    handling (the decision downgrades to a named deny): the refusal is
    recorded by the caller and never swallowed here. This differs from
    :class:`ChainTailMalformed`, which guards the receipt index's chain
    resume; this class guards the receipt store's segments and seals.
    """


class PolicySealRefused(Exception):
    """Loading refused a control-plane file whose seal does not hold (RAU-02).

    Raised by the seal-aware policy load path (the gateway's boot and
    reload, :meth:`raucle.policy.PolicyFile.load_sealed`) and by the
    gateway's file-cache seal checks for the operator registries, when
    the ``<file>.meta`` sidecar seal from
    :mod:`raucle.policy_seal` does not hold for the file's current
    bytes. The message always names the FILE and the REASON. It fires in
    exactly these situations:

    * a sidecar exists and the signature does not verify over the
      current bytes, or the sealed digest diverges from them, or the
      sidecar is corrupt, malformed, or carries unknown fields, or the
      signing key id is not among the configured verification keys -
      tamper evidence, refused in every sealing mode except ``off``;
    * the sealing mode is ``required`` and the file has NO seal at all
      (``RAUCLE_POLICY_SEALING``), naming the file and the mode.

    It never fires for the advisory-unsealed case (that boots with a
    named advisory log line), and it never fires at all when
    ``RAUCLE_POLICY_SEALING=off`` - the operator's explicit opt-out.
    The gateway surfaces the refusal as boot failure, reload error
    (previous rules keep enforcing), or a deny-path raise for the
    registries; the refusal is recorded by the caller and never
    swallowed here.
    """
