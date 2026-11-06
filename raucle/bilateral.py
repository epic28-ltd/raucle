"""x_bilateral: the executor-side outcome co-signature (spec v1.2).

The tool/execution side of a bilateral receipt signs the outcome it actually
produced — ``executed``, ``failed`` or ``rejected`` (a closed vocabulary) —
over the receipt's own ``output_hash``. The block rides INSIDE the receipt's
signed payload (attached before the agent signs), so the co-signature is
bound by the same JWS: the agent's signature, the output_hash and the
executor's claim cannot move independently of one another. Verification is
fail-closed (see :meth:`ProvenanceVerifier._verify_bilateral`): a missing or
non-verifying co-signature is a named verification failure, never inferred.

Own module so harness adapters (``raucle/integrations/qm.py`` and siblings)
import one small, dependency-light surface instead of the whole provenance
module — and so the F821 that surfaced the split cannot recur.
"""

from __future__ import annotations

import base64
from typing import Any

#: The closed outcome vocabulary. Enforced at emission (a non-vocabulary
#: outcome is refused outright) and re-checked at verification (an outcome
#: outside the set is a named verification failure).
BILATERAL_OUTCOMES = ("executed", "failed", "rejected")


def bilateral_signing_input(executor_key_id: str, outcome: str, output_hash: str) -> bytes:
    """The canonical bytes an ``x_bilateral`` executor co-signature covers.

    Exactly the closed vocabulary word, the receipt's own output_hash and
    the executor's key id, over canonical JSON — so the co-signature binds
    the outcome to the exact output the receipt records and to the key
    that vouches it (spec v1.2, bilateral-outcomes).
    """
    from raucle.provenance import _canonical_json  # deferred: import cycle

    return _canonical_json(
        {
            "executor_key_id": str(executor_key_id),
            "outcome": str(outcome),
            "output_hash": str(output_hash),
        }
    )


def sign_bilateral_outcome(
    signer: Any,
    *,
    executor_key_id: str,
    outcome: str,
    output_hash: str,
) -> dict[str, Any]:
    """Build the executor-side ``x_bilateral`` block to ride the payload root.

    *signer* is an Ed25519 private-key object (``.sign(bytes)``); an
    :class:`raucle.provenance.AgentIdentity` qualifies. The block carries
    the outcome (closed vocabulary, enforced here), the output_hash it
    binds and the base64 Ed25519 co-signature over
    :func:`bilateral_signing_input`. Attach the block to a receipt's payload
    BEFORE the agent signs: the co-signature lives inside the same signed
    payload, not in an unsigned side channel.

    Raises
    ------
    ValueError
        When *outcome* is outside the closed vocabulary.
    """
    if outcome not in BILATERAL_OUTCOMES:
        raise ValueError(
            f"unknown bilateral outcome {outcome!r}; use one of {list(BILATERAL_OUTCOMES)}"
        )
    raw = signer.sign(bilateral_signing_input(executor_key_id, outcome, output_hash))
    return {
        "outcome": outcome,
        "output_hash": output_hash,
        "executor_key_id": executor_key_id,
        "signature": base64.b64encode(raw).decode("ascii"),
    }
