"""x_bilateral: executor co-signed outcomes (spec v1.2, bilateral-outcomes).

The tool/execution side co-signs the outcome it produced — executed, failed
or rejected — INSIDE the receipt's signed payload, over the receipt's own
output_hash. The offline verifier re-checks that co-signature fail-closed:
missing, unknown-key or non-verifying executor signatures are named
verification failures, never inferred away. Receipts without the block
verify exactly as before.
"""

import json

import pytest

from raucle.bilateral import (
    BILATERAL_OUTCOMES,
    bilateral_signing_input,
    sign_bilateral_outcome,
)
from raucle.integrations.qm import QmHarnessBridge
from raucle.provenance import (
    AgentIdentity,
    Operation,
    ProvenanceReceipt,
    ProvenanceVerifier,
    hash_obj,
    hash_text,
)

ARGS = {"account": "ACC-001"}
OUTPUT = {"status": "queued", "rows": 4}


def _agents():
    return (
        AgentIdentity.generate(agent_id="agent:worker", allowed_tools=["export_records"]),
        AgentIdentity.generate(agent_id="agent:executor"),
    )


def _build(agent, *, operation=Operation.TOOL_CALL, parents=(), output_hash=None):
    receipt = ProvenanceReceipt(
        agent_id=agent.agent_id,
        agent_key_id=agent.key_id,
        operation=operation,
        parents=list(parents),
        input_hash=hash_text(json.dumps(ARGS, sort_keys=True)),
        output_hash=output_hash if output_hash is not None else hash_obj(OUTPUT),
        tool="export_records" if operation == Operation.TOOL_CALL else "",
    )
    return receipt


def _sign(agent, receipt):
    receipt.sign(agent)
    return receipt


def _write(tmp_path, *receipts):
    path = tmp_path / "chain.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for receipt in receipts:
            fh.write(
                json.dumps(
                    {"receipt_hash": receipt.receipt_hash, "jws": receipt.jws},
                )
                + "\n"
            )
    return path


def _verifier(tmp_path, agent, executors=()):
    return ProvenanceVerifier(
        public_keys={agent.key_id: agent.public_key_pem()},
        executor_keys=QmHarnessBridge.executor_keys(executors),
    )


def _bilateral(tmp_path, agent, executors=()):
    path = tmp_path / "chain.jsonl"
    return _verifier(tmp_path, agent, executors).verify_chain(path)


def test_well_formed_bilateral_cosign_verifies(tmp_path):
    """The acceptance: a receipt whose executor co-signed the outcome inside
    the signed payload verifies, and the co-signature survives the parse."""
    agent, executor = _agents()
    bridge = QmHarnessBridge(None, None)  # type: ignore[arg-type]
    root = _sign(agent, _build(agent, operation=Operation.USER_INPUT))
    receipt = _build(agent, parents=[root.receipt_hash])
    receipt.x_bilateral = bridge.bilateral_outcome(
        executor, outcome="executed", output_hash=receipt.output_hash
    )
    _sign(agent, receipt)
    _write(tmp_path, root, receipt)

    report = _bilateral(tmp_path, agent, executors=[executor])
    assert report.valid, report.errors
    assert report.errors == []

    # The co-signature rides the signed payload: parse round-trip keeps it.
    from raucle.provenance import ProvenanceReceipt as PR

    parsed = PR.from_jws(receipt.jws)
    assert parsed.x_bilateral is not None
    assert parsed.x_bilateral["outcome"] == "executed"
    assert parsed.x_bilateral["output_hash"] == hash_obj(OUTPUT)


def test_missing_executor_signature_fails_with_named_reason(tmp_path):
    """Fail-closed: an outcome claim without the executor co-signature never
    verifies and is never inferred."""
    agent, executor = _agents()
    bridge = QmHarnessBridge(None, None)  # type: ignore[arg-type]
    receipt = _build(agent)
    block = bridge.bilateral_outcome(executor, outcome="executed", output_hash=receipt.output_hash)
    block.pop("signature")
    receipt.x_bilateral = block
    _sign(agent, receipt)
    _write(tmp_path, receipt)

    report = _bilateral(tmp_path, agent, executors=[executor])
    assert not report.valid
    assert any("no executor signature" in e for e in report.errors), report.errors


def test_executor_signature_over_tampered_outcome_fails(tmp_path):
    """A co-signature over one outcome cannot vouch a different one: re-labelling
    the outcome after signature fails verification with a named error."""
    agent, executor = _agents()
    receipt = _build(agent)
    honest = sign_bilateral_outcome(
        executor,
        executor_key_id=executor.key_id,
        outcome="executed",
        output_hash=receipt.output_hash,
    )
    tampered = {**honest, "outcome": "failed"}
    receipt.x_bilateral = tampered
    _sign(agent, receipt)
    _write(tmp_path, receipt)

    report = _bilateral(tmp_path, agent, executors=[executor])
    assert not report.valid
    assert any("does not verify" in e for e in report.errors), report.errors


def test_mixed_chain_bilateral_and_legacy_receipts_verify(tmp_path):
    """A chain mixing bilateral and legacy receipts verifies end to end; the
    legacy legs are untouched by the extension (additive, no breaking change)."""
    agent, executor = _agents()
    bridge = QmHarnessBridge(None, None)  # type: ignore[arg-type]
    root = _sign(agent, _build(agent, operation=Operation.USER_INPUT))
    bilateral_receipt = _build(agent, parents=[root.receipt_hash])
    bilateral_receipt.x_bilateral = bridge.bilateral_outcome(
        executor, outcome="failed", output_hash=bilateral_receipt.output_hash
    )
    _sign(agent, bilateral_receipt)
    # A legacy child (no x_bilateral) cites the bilateral receipt.
    legacy_child = _build(
        agent, parents=[bilateral_receipt.receipt_hash], output_hash=hash_text("v2")
    )
    _sign(agent, legacy_child)
    _write(tmp_path, root, bilateral_receipt, legacy_child)

    report = _bilateral(tmp_path, agent, executors=[executor])
    assert report.valid, report.errors
    assert report.errors == []
    assert report.receipt_count == 3


def test_outcome_vocabulary_is_closed(tmp_path):
    """Only executed/failed/rejected may be co-signed: refused at emission and
    a named verification failure on the wire."""
    agent, executor = _agents()
    with pytest.raises(ValueError, match="unknown bilateral outcome"):
        sign_bilateral_outcome(
            executor,
            executor_key_id=executor.key_id,
            outcome="succeeded",
            output_hash="sha256:x",
        )

    receipt = _build(agent)
    receipt.x_bilateral = {
        "outcome": "succeeded",
        "output_hash": receipt.output_hash,
        "executor_key_id": executor.key_id,
        "signature": "bm90LXJlYWwtYnl0ZXM=",
    }
    _sign(agent, receipt)
    _write(tmp_path, receipt)
    report = _bilateral(tmp_path, agent, executors=[executor])
    assert not report.valid
    assert any("closed vocabulary" in e for e in report.errors), report.errors


def test_bilateral_object_shape_is_validated(tmp_path):
    """Schema checks: the block must be an object binding the receipt's own
    output_hash; an unbound or non-object block fails with a named error."""
    agent, executor = _agents()
    receipt = _build(agent)
    receipt.x_bilateral = "executed"
    _sign(agent, receipt)
    other = _build(agent)
    other.x_bilateral = {
        "outcome": "executed",
        "output_hash": "sha256:" + "0" * 64,
        "executor_key_id": executor.key_id,
        "signature": "bm90LXJlYWwtYnl0ZXM=",
    }
    _sign(agent, other)
    _write(tmp_path, receipt, other)

    report = _bilateral(tmp_path, agent, executors=[executor])
    assert not report.valid
    assert any("must be an object" in e for e in report.errors), report.errors
    assert any("does not bind the receipt's own output_hash" in e for e in report.errors), (
        report.errors
    )


def test_unknown_executor_key_fails_closed(tmp_path):
    """Fail-closed: a co-signature under a key the verifier was not told about
    is an unknown executor — rejected, never trusted."""
    agent, _executor, stranger = (
        AgentIdentity.generate(agent_id="agent:worker"),
        AgentIdentity.generate(agent_id="agent:exec"),
        AgentIdentity.generate(agent_id="agent:stranger"),
    )
    bridge = QmHarnessBridge(None, None)  # type: ignore[arg-type]
    receipt = _build(agent)
    receipt.x_bilateral = bridge.bilateral_outcome(
        stranger, outcome="executed", output_hash=receipt.output_hash
    )
    _sign(agent, receipt)
    _write(tmp_path, receipt)

    report = _bilateral(tmp_path, agent, executors=[_executor])
    assert not report.valid
    assert any("no executor key registered" in e for e in report.errors), report.errors


def test_verifier_without_executor_keys_fails_closed_on_bilateral(tmp_path):
    """A verifier that does not understand the bilateral extension fails the
    bilateral receipt closed — and still verifies a legacy receipt untouched."""
    agent, _executor = _agents()
    bridge = QmHarnessBridge(None, None)  # type: ignore[arg-type]
    root = _sign(agent, _build(agent, operation=Operation.USER_INPUT))
    bilateral_receipt = _build(agent, parents=[root.receipt_hash])
    bilateral_receipt.x_bilateral = bridge.bilateral_outcome(
        _executor, outcome="executed", output_hash=bilateral_receipt.output_hash
    )
    _sign(agent, bilateral_receipt)
    legacy = _build(agent, operation=Operation.USER_INPUT, output_hash=hash_text("legacy"))
    _sign(agent, legacy)
    _write(tmp_path, root, bilateral_receipt, legacy)

    report = ProvenanceVerifier(public_keys={agent.key_id: agent.public_key_pem()}).verify_chain(
        tmp_path / "chain.jsonl"
    )
    assert not report.valid
    # Only the bilateral line fails (fail-closed, named); the legacy receipts
    # contribute no error and are untouched by the extension.
    bilateral_errors = [e for e in report.errors if "x_bilateral" in e or "executor key" in e]
    assert len(report.errors) == 1
    assert report.errors == bilateral_errors
    assert any("no executor key registered" in e for e in bilateral_errors)
    assert report.receipt_count == 3


def test_binding_bytes_are_exactly_outcome_output_and_key():
    """The co-signature binds exactly the closed outcome, the output_hash and
    the executor key id — nothing more, over canonical JSON."""
    import base64

    executor = AgentIdentity.generate(agent_id="agent:exec")
    block = sign_bilateral_outcome(
        executor,
        executor_key_id=executor.key_id,
        outcome="rejected",
        output_hash="sha256:abc",
    )
    assert BILATERAL_OUTCOMES == ("executed", "failed", "rejected")
    assert block["outcome"] == "rejected"
    raw = base64.b64decode(block["signature"])
    from cryptography.hazmat.primitives import serialization

    pub = serialization.load_pem_public_key(executor.public_key_pem())
    pub.verify(raw, bilateral_signing_input(executor.key_id, "rejected", "sha256:abc"))
