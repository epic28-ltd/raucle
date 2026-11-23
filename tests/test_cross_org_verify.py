"""X2 slice 3: cross-org receipt verification through the Trust Registry.

Acceptance (approved X2 programme): a third party verifies ANOTHER org's
receipt offline, with no raucle install and no trust in either operator.
The signing org's public key is resolved through the Trust Registry
artifact (hash chain + pinned operator anchor + freshness pins), the
receipt signature is verified against that resolved key, the
registry-published capability statement supplies the scope leg (what was
allowed), and the hosted transparency log's inclusion proof supplies the
registration leg (when it was registered).

These tests pin the OSS Python verify path; the shipped browser page
(assets/verifier/x2-verifier.html) mirrors it and is exercised by the
node harness (tests/verifier_harness/x2_harness.mjs) that
tests/test_x2_verifier.py drives.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from raucle.audit import Ed25519Signer
from raucle.cross_org import verify_receipt_cross_org
from raucle.provenance import AgentIdentity, ProvenanceLogger, _canonical_json
from raucle.transparency import (
    LOG_GENESIS_PREV_HASH,
    compute_log_entry_hash,
)
from raucle.trust_registry import TrustRegistry

# ---------------------------------------------------------------------------
# Fixture builders: a real operator-signed registry + a real org-A receipt
# ---------------------------------------------------------------------------


def _operator_signer() -> Ed25519Signer:
    return Ed25519Signer.generate()


def _org_a_identity() -> AgentIdentity:
    return AgentIdentity.generate(
        agent_id="agent:org-a-billing",
        allowed_tools=["tool.ledger.get"],
    )


def _registry(
    identity: AgentIdentity,
    operator: Ed25519Signer,
    *,
    issuer: str = "org-a",
    with_statement: bool = True,
    path: Path | None = None,
) -> TrustRegistry:
    """A signed registry artifact publishing org A's agent key (+ statement)."""
    kwargs: dict = {"operator_signer": operator}
    if path is not None:
        kwargs["path"] = path
    reg = TrustRegistry(**kwargs)
    metadata: dict = {"org": issuer}
    if with_statement:
        metadata["capability_statement"] = identity.statement.to_dict()
    reg.publish(identity.public_key_pem(), issuer=issuer, metadata=metadata)
    return reg


def _receipt_chain(identity: AgentIdentity, tmp_path: Path) -> tuple[str, Path, str]:
    """Mint a real two-receipt chain under org A's key (a user_input root
    plus a permitted tool call). Returns (chain_text, chain_path, leaf_hash)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    chain = tmp_path / "chain.jsonl"
    writer = ProvenanceLogger(identity, sink_path=chain)
    root = writer.record_user_input("read ACC-1 ledger")
    leaf = writer.record_tool_call(
        parents=[root],
        tool="tool.ledger.get",
        input_args={"account": "ACC-1"},
        output={"ok": True},
    )
    writer.close()
    text = chain.read_text(encoding="utf-8").strip()
    return text, chain, leaf


# ---------------------------------------------------------------------------
# The cross-org happy path
# ---------------------------------------------------------------------------


def test_cross_org_happy_path(tmp_path):
    """Org B verifies org A's receipt from the registry artifact + anchor alone."""
    operator = _operator_signer()
    identity = _org_a_identity()
    reg = _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, receipt_hash = _receipt_chain(identity, tmp_path)

    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
        now=1_760_000_000,
        max_age_seconds=None,
    )
    assert v.valid, v.reasons
    assert v.registry_verified
    assert v.receipt_verified
    assert v.scope_verified is True
    assert v.key_id == identity.key_id
    assert v.issuer == "org-a"
    assert v.revoked is False
    assert v.head_index == reg.head()["index"]
    assert v.head_hash == reg.head()["hash"]
    assert receipt_hash.startswith("sha256:")


def test_cross_org_happy_path_from_text(tmp_path):
    """The registry artifact can arrive as pasted text (the browser shape)."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, _rh = _receipt_chain(identity, tmp_path)
    text = (tmp_path / "registry.jsonl").read_text(encoding="utf-8")

    v = verify_receipt_cross_org(
        line,
        registry_jsonl=text,
        operator_public_pem=operator.public_key_pem(),
    )
    assert v.valid, v.reasons
    assert v.issuer == "org-a"


# ---------------------------------------------------------------------------
# Named failures: registry mismatch, anchor, unsigned, freshness, revocation
# ---------------------------------------------------------------------------


def test_key_not_in_registry_fails_named(tmp_path):
    """A receipt whose signing key the registry never published is a named
    refusal: the registry is the ONLY key source in cross-org mode."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    stranger = _org_a_identity()
    line, _chain, _rh = _receipt_chain(stranger, tmp_path / "sub")

    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
    )
    assert not v.valid
    assert v.registry_verified  # the artifact itself verifies; resolution is its own leg
    joined = " ".join(v.reasons)
    assert "not in the registry" in joined
    assert v.issuer == ""


def test_wrong_operator_anchor_fails_named(tmp_path):
    """Pinning a different operator's key: the artifact does not authenticate
    against the anchor, named."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, _rh = _receipt_chain(identity, tmp_path / "sub")

    wrong_anchor = Ed25519Signer.generate().public_key_pem()
    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=wrong_anchor,
    )
    assert not v.valid
    assert not v.registry_verified
    joined = " ".join(v.reasons)
    assert "operator signature" in joined or "anchor" in joined


def test_unsigned_registry_refused_named(tmp_path):
    """An unsigned registry cannot anchor cross-org trust: refused by name."""
    identity = _org_a_identity()
    reg = TrustRegistry(path=tmp_path / "registry.jsonl")  # no operator signer
    reg.publish(identity.public_key_pem(), issuer="org-a")
    line, _chain, _rh = _receipt_chain(identity, tmp_path / "sub")

    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=Ed25519Signer.generate().public_key_pem(),
    )
    assert not v.valid
    assert not v.registry_verified
    assert "unsigned" in " ".join(v.reasons)


def test_stale_freshness_anchor_fails_named(tmp_path):
    """A stale snapshot (rollback) is caught by each freshness pin, named."""
    operator = _operator_signer()
    identity = _org_a_identity()
    reg = _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, _rh = _receipt_chain(identity, tmp_path / "sub")

    # max age: the registry head is old by now
    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
        max_age_seconds=60,
        now=reg.head()["ts"] + 3600,
    )
    assert not v.valid
    assert "stale snapshot" in " ".join(v.reasons)

    # min index: a pinned newer head refuses the older artifact
    v2 = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
        min_index=reg.head()["index"] + 1,
    )
    assert not v2.valid
    assert "stale snapshot" in " ".join(v2.reasons)

    # expected head hash: a pinned different head refuses the artifact
    v3 = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
        expected_head_hash="sha256:" + "9" * 64,
    )
    assert not v3.valid
    assert "stale snapshot" in " ".join(v3.reasons)


def test_revoked_key_fails_named(tmp_path):
    """A receipt from a key the registry has revoked is a named refusal."""
    operator = _operator_signer()
    identity = _org_a_identity()
    reg = _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, _rh = _receipt_chain(identity, tmp_path / "sub")
    reg.revoke(identity.key_id, reason="compromise")

    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
    )
    assert not v.valid
    assert v.registry_verified  # the artifact is fine; the key state is the refusal
    joined = " ".join(v.reasons)
    assert "revoked" in joined


def test_tampered_receipt_fails_named(tmp_path):
    """A doctored JWS fails the receipt leg with named reasons."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, _rh = _receipt_chain(identity, tmp_path / "sub")

    lines = line.splitlines()
    env = json.loads(lines[-1])
    parts = env["jws"].split(".")
    parts[2] = parts[2][:-2] + ("AA" if parts[2][-2:] != "AA" else "BB")
    env["jws"] = ".".join(parts)
    lines[-1] = json.dumps(env)
    v = verify_receipt_cross_org(
        "\n".join(lines),
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
    )
    assert not v.valid
    assert not v.receipt_verified
    assert v.reasons, "named reasons required"


def test_tampered_registry_fails_named(tmp_path):
    """An edited registry entry breaks the chain: named refusal."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, _rh = _receipt_chain(identity, tmp_path / "sub")

    raw = (tmp_path / "registry.jsonl").read_text(encoding="utf-8")
    forged = raw.replace('"org-a"', '"org-a "', 1)
    assert forged != raw
    v = verify_receipt_cross_org(
        line,
        registry_jsonl=forged,
        operator_public_pem=operator.public_key_pem(),
    )
    assert not v.valid
    assert not v.registry_verified


# ---------------------------------------------------------------------------
# The scope leg (what was allowed)
# ---------------------------------------------------------------------------


def _out_of_scope_receipt(identity: AgentIdentity, *, tool: str, parents: list[str]) -> str:
    """A receipt signed by the agent's real key but claiming a tool the
    statement never allowed. Built with the production receipt signer,
    bypassing only the logger's cooperative producer-side check: exactly
    the malicious-producer case the verifier must catch on its own."""
    from raucle.provenance import Operation, ProvenanceReceipt, hash_obj

    receipt = ProvenanceReceipt(
        agent_id=identity.statement.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.TOOL_CALL,
        parents=parents,
        input_hash=hash_obj({"account": "ACC-1"}),
        output_hash=hash_obj({"ok": True}),
        tool=tool,
        taint=["external_user"],
        issued_at=1_700_000_000,
    )
    receipt.sign(identity)
    return json.dumps({"receipt_hash": receipt.receipt_hash, "jws": receipt.jws})


def test_scope_violation_fails_named(tmp_path):
    """The registry-published statement is the authority: a receipt invoking
    a tool outside it fails the scope leg, named."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    tmp_sub = tmp_path / "sub"
    tmp_sub.mkdir(parents=True, exist_ok=True)
    writer = ProvenanceLogger(identity, sink_path=tmp_sub / "chain.jsonl")
    root = writer.record_user_input("read ACC-1 ledger")
    writer.close()
    root_line = (tmp_sub / "chain.jsonl").read_text(encoding="utf-8").strip()
    line = (
        root_line
        + "\n"
        + _out_of_scope_receipt(identity, tool="tool.ledger.delete", parents=[root])
    )

    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
    )
    assert not v.valid
    assert v.scope_verified is False
    joined = " ".join(v.reasons)
    assert "tool.ledger.delete" in joined or "allowed" in joined or "capability" in joined


def test_scope_unstated_when_registry_publishes_no_statement(tmp_path):
    """No published statement: the scope leg is honestly unstated, not green."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, with_statement=False, path=tmp_path / "registry.jsonl")
    line, _chain, _rh = _receipt_chain(identity, tmp_path / "sub")

    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
    )
    assert v.valid, v.reasons
    assert v.scope_verified is None
    assert any("scope" in r.lower() or "statement" in r.lower() for r in v.reasons)


def test_statement_key_binding_mismatch_fails_named(tmp_path):
    """A metadata statement that does not bind the SAME key is a named
    refusal: the scope material must not be substitutable."""
    operator = _operator_signer()
    identity = _org_a_identity()
    other = _org_a_identity()
    reg = TrustRegistry(path=tmp_path / "registry.jsonl", operator_signer=operator)
    reg.publish(
        identity.public_key_pem(),
        issuer="org-a",
        metadata={"capability_statement": other.statement.to_dict()},
    )
    line, _chain, _rh = _receipt_chain(identity, tmp_path / "sub")

    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
    )
    assert not v.valid
    assert v.scope_verified is False
    assert "statement" in " ".join(v.reasons) or "key" in " ".join(v.reasons)


# ---------------------------------------------------------------------------
# The registration leg (when it was registered): the transparency log
# ---------------------------------------------------------------------------


def _log_entry(org, sequence, prev_hash, receipt_digest, registered_at):
    entry = {
        "org": org,
        "sequence": sequence,
        "prev_hash": prev_hash,
        "receipt_digest": receipt_digest,
        "payload_digest": None,
        "registered_at": registered_at,
        "entry_hash": "",
    }
    entry["entry_hash"] = compute_log_entry_hash(entry)
    return entry


def _checkpoint(private, *, org, size, head_hash, iat):
    from raucle.provenance import _b64url_encode

    header = {
        "alg": "EdDSA",
        "typ": "transparency-epoch/v1",
        "kid": "raucle-log-test",
        "crit": ["raucle/v1"],
        "raucle/v1": "transparency",
    }
    payload = {
        "iss": "raucle-portal",
        "org": org,
        "epoch": size,
        "size": size,
        "head_hash": head_hash,
        "iat": iat,
        "nonce": "0" * 32,
    }
    signing_input = (
        _b64url_encode(_canonical_json(header)) + "." + _b64url_encode(_canonical_json(payload))
    ).encode("ascii")
    return signing_input.decode("ascii") + "." + _b64url_encode(private.sign(signing_input))


def _log_private():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    pem = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return private, pem


def _inclusion_proof(private, *, org, digest, iat=1_750_000_000):
    entry = _log_entry(org, 1, LOG_GENESIS_PREV_HASH, digest, registered_at=iat)
    checkpoint = _checkpoint(private, org=org, size=1, head_hash=entry["entry_hash"], iat=iat)
    return {
        "org": org,
        "sequence": 1,
        "entries": [entry],
        "size": 1,
        "head_hash": entry["entry_hash"],
        "checkpoint_jws": checkpoint,
        "receipt_digest": digest,
        "epoch": 1,
    }


def test_log_inclusion_leg_green(tmp_path):
    """The inclusion proof binds the receipt digest to a signed head: the
    third leg goes green and surfaces the registration time."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, receipt_hash = _receipt_chain(identity, tmp_path / "sub")
    log_private, log_pem = _log_private()
    proof = _inclusion_proof(log_private, org="org-a", digest=receipt_hash)

    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
        log_proof=proof,
        log_operator_public_key_pem=log_pem,
    )
    assert v.valid, v.reasons
    assert v.log_status == "LOG-INCLUDED"
    assert v.registered_at == 1_750_000_000


def test_log_leg_fails_named_on_doctored_proof(tmp_path):
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, receipt_hash = _receipt_chain(identity, tmp_path / "sub")
    log_private, _log_pem = _log_private()
    proof = _inclusion_proof(log_private, org="org-a", digest=receipt_hash)
    proof["entries"][0]["receipt_digest"] = "sha256:" + "1" * 64  # rewritten entry

    other_private, other_pem = _log_private()
    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
        log_proof=proof,
        log_operator_public_key_pem=other_pem,
    )
    assert not v.valid
    assert v.log_status in ("LOG-BAD-SIGNATURE", "LOG-CHAIN-BROKEN", "LOG-HEAD-MISMATCH")
    assert v.reasons


def test_log_leg_absent_is_named_residual(tmp_path):
    """Without a proof the verdict stays green but names the unverified
    registration leg, never silently green."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, _rh = _receipt_chain(identity, tmp_path / "sub")

    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
    )
    assert v.valid, v.reasons
    assert v.log_status is None
    assert v.registered_at is None
    assert any("log" in r.lower() for r in v.reasons)


def test_log_proof_without_pinned_log_key_refused(tmp_path):
    """A proof verified against its own riding key would be self-attested:
    the pinned log key is required, named."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, receipt_hash = _receipt_chain(identity, tmp_path / "sub")
    log_private, _pem = _log_private()
    proof = _inclusion_proof(log_private, org="org-a", digest=receipt_hash)

    v = verify_receipt_cross_org(
        line,
        registry_path=tmp_path / "registry.jsonl",
        operator_public_pem=operator.public_key_pem(),
        log_proof=proof,
        log_operator_public_key_pem=None,
    )
    assert not v.valid
    assert "log operator" in " ".join(v.reasons) or "pinned" in " ".join(v.reasons)


# ---------------------------------------------------------------------------
# The committed cross-org fixture (assets/verifier/fixtures/cross-org/)
# ---------------------------------------------------------------------------

FIXTURE_DIR = (
    Path(__file__).resolve().parent.parent / "assets" / "verifier" / "fixtures" / "cross-org"
)


def _fixture_inputs():
    import json as _json

    return {
        "receipt_text": (FIXTURE_DIR / "chain.jsonl").read_text(encoding="utf-8"),
        "registry_jsonl": (FIXTURE_DIR / "registry.jsonl").read_text(encoding="utf-8"),
        "operator_public_pem": (FIXTURE_DIR / "registry-operator.pem").read_bytes(),
        "log_proof": _json.loads((FIXTURE_DIR / "log-inclusion.json").read_text(encoding="utf-8")),
        "log_operator_public_key_pem": (FIXTURE_DIR / "log-operator.pem").read_text(
            encoding="ascii"
        ),
    }


def test_committed_cross_org_fixture_verifies_green():
    """The committed fixture is named-clean under the real cross-org verify
    path (the node harness then proves the BROWSER implementation agrees)."""
    v = verify_receipt_cross_org(**_fixture_inputs())
    assert v.valid, v.reasons
    assert v.registry_verified and v.receipt_verified
    assert v.scope_verified is True
    assert v.issuer == "org-a"
    assert v.log_status == "LOG-INCLUDED"
    assert v.registered_at is not None


def test_committed_fixture_tampered_registry_refuses_named():
    inputs = _fixture_inputs()
    inputs["registry_jsonl"] = inputs["registry_jsonl"].replace('"org-a"', '"org-a "', 1)
    v = verify_receipt_cross_org(**inputs)
    assert not v.valid
    assert not v.registry_verified
    assert v.reasons


def test_committed_fixture_wrong_anchor_refuses_named():
    inputs = _fixture_inputs()
    # pin the LOG operator key as the registry anchor: a different operator
    inputs["operator_public_pem"] = inputs["log_operator_public_key_pem"].encode("ascii")
    v = verify_receipt_cross_org(**inputs)
    assert not v.valid
    assert not v.registry_verified
    assert "operator signature" in " ".join(v.reasons)


def test_committed_fixture_riding_log_key_is_never_verification_input():
    """The proof carries the log operator's public key as convenience
    material; verification must use the PINNED key, and a proof re-pinned
    to the registry anchor (a different key) must refuse, not pass."""
    inputs = _fixture_inputs()
    inputs["log_operator_public_key_pem"] = inputs["operator_public_pem"].decode("ascii")
    v = verify_receipt_cross_org(**inputs)
    assert not v.valid
    assert v.log_status == "LOG-BAD-SIGNATURE"


def test_fixture_generator_round_trip_verifies(tmp_path):
    """scripts/x2_cross_org_fixtures.py builds a fresh fixture set from the
    real production paths; its output must verify green through the module
    (the fixture cannot rot without this pin going red)."""
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import x2_cross_org_fixtures

    written = x2_cross_org_fixtures.build_fixture(tmp_path)
    assert set(written) == {
        "README.md",
        "chain.jsonl",
        "log-inclusion.json",
        "log-operator.pem",
        "registry-operator.pem",
        "registry.jsonl",
    }
    import json as _json

    v = verify_receipt_cross_org(
        (tmp_path / "chain.jsonl").read_text(encoding="utf-8"),
        registry_jsonl=(tmp_path / "registry.jsonl").read_text(encoding="utf-8"),
        operator_public_pem=(tmp_path / "registry-operator.pem").read_bytes(),
        log_proof=_json.loads((tmp_path / "log-inclusion.json").read_text(encoding="utf-8")),
        log_operator_public_key_pem=(tmp_path / "log-operator.pem").read_text(encoding="ascii"),
    )
    assert v.valid, v.reasons
    assert v.log_status == "LOG-INCLUDED"


# ---------------------------------------------------------------------------
# Artifact hardening the cross-org path depends on
# ---------------------------------------------------------------------------


def test_from_jsonl_rejects_duplicate_keys():
    """A crafted registry artifact with duplicate JSON keys must be refused
    on the text-loading path too (the dup-key rejecter the file path
    already has)."""
    operator = Ed25519Signer.generate()
    reg = TrustRegistry(operator_signer=operator)
    reg.publish(operator.public_key_pem(), issuer="dup-test")
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as fh:
        fh.write("")
        tmp = Path(fh.name)
    reg2 = TrustRegistry(path=tmp, operator_signer=operator)
    reg2.publish(operator.public_key_pem(), issuer="dup-test")
    raw = tmp.read_text(encoding="utf-8")
    tmp.unlink(missing_ok=True)
    doctored = raw.replace('"issuer":"dup-test"', '"issuer":"x","issuer":"dup-test"', 1)
    assert doctored != raw
    with pytest.raises(Exception):  # noqa: B017 - named via the rejecter
        TrustRegistry.from_jsonl(doctored)


# ---------------------------------------------------------------------------
# The registry-vs-page parity pins (X2 slice 3)
# ---------------------------------------------------------------------------


ROOT = Path(__file__).resolve().parent.parent


def _node_available() -> bool:
    return shutil.which("node") is not None


def _hybrid_decorated_registry(path: Path, *, pq_key_id: str) -> str:
    """The registry artifact with its register entry additionally declaring
    operator_pq_key_id: a hybrid-declared signature the verifier cannot
    accept without the ML-DSA-65 component verifying. Those fields are
    excluded from the entry body, so the entry hash and chain stay intact
    and only the hybrid leg decides the verdict."""
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    entry = json.loads(lines[1])
    entry["operator_pq_key_id"] = pq_key_id
    lines[1] = json.dumps(entry)
    return "\n".join(lines) + "\n"


def test_hybrid_registry_entry_refuses_named(tmp_path):
    """An entry declaring operator_pq_key_id must fail closed when its
    ML-DSA-65 operator signature component cannot be verified: classical-only
    acceptance of a hybrid entry is never green."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, _rh = _receipt_chain(identity, tmp_path / "sub")
    hybrid = _hybrid_decorated_registry(tmp_path / "registry.jsonl", pq_key_id="0" * 16)

    v = verify_receipt_cross_org(
        line,
        registry_jsonl=hybrid,
        operator_public_pem=operator.public_key_pem(),
    )
    assert not v.valid
    assert not v.registry_verified
    assert "hybrid entry carries operator_pq_key_id" in " ".join(v.reasons)


@pytest.mark.skipif(not _node_available(), reason="node unavailable")
def test_page_registry_leg_refuses_hybrid_entry(tmp_path):
    """The shipped X2 page refuses the artifact the OSS registry leg refuses:
    an entry declaring operator_pq_key_id without a verifiable ML-DSA-65
    operator signature component fails closed with a named reason."""
    operator = _operator_signer()
    identity = _org_a_identity()
    _registry(identity, operator, path=tmp_path / "registry.jsonl")
    line, _chain, _rh = _receipt_chain(identity, tmp_path / "sub")
    hybrid = _hybrid_decorated_registry(tmp_path / "registry.jsonl", pq_key_id="0" * 16)
    scenarios = {
        "cases": [
            {
                "name": "hybrid registry entry without a verifiable ML-DSA-65 component",
                "chain": line,
                "registry": hybrid,
                "opts": {"operatorPem": operator.public_key_pem().decode("ascii")},
                "expect": {
                    "valid": False,
                    "registry_ok": False,
                    "reasonIncludes": ["ML-DSA-65 operator signature component"],
                },
            }
        ]
    }
    scen = tmp_path / "scenarios.json"
    scen.write_text(json.dumps(scenarios), encoding="utf-8")
    harness = ROOT / "tests" / "verifier_harness" / "x2_harness.mjs"
    r = subprocess.run(
        ["node", str(harness), str(ROOT), str(scen)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert r.returncode == 0, f"harness failed:\n{r.stdout}\n{r.stderr}"


def _mint_receipt_envelope(identity: AgentIdentity, *, parents: list[str], tool: str) -> str:
    """A production-signed receipt envelope from an identity whose logger is
    not the writer of the surrounding chain: the shape a mixed chain hands
    the verifier (one logger-minted root, one directly signed child)."""
    from raucle.provenance import Operation, ProvenanceReceipt, hash_obj

    receipt = ProvenanceReceipt(
        agent_id=identity.statement.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.TOOL_CALL,
        parents=parents,
        input_hash=hash_obj({"account": "ACC-1"}),
        output_hash=hash_obj({"ok": True}),
        tool=tool,
        taint=["external_user"],
        issued_at=1_700_000_000,
    )
    receipt.sign(identity)
    return json.dumps({"receipt_hash": receipt.receipt_hash, "jws": receipt.jws})


def _mixed_chain_scenario(tmp_path: Path, *, with_statement: bool = True) -> tuple[dict, bytes]:
    """A real registry + receipt chain where one signing key carries the
    org's published capability statement and a second key is registered but
    unstated. Returns (scenario dict for the node harness, operator anchor
    bytes for the OSS path)."""
    operator = _operator_signer()
    stated = AgentIdentity.generate(
        agent_id="agent:org-a-billing",
        allowed_tools=["tool.ledger.get"],
    )
    unstated = AgentIdentity.generate(
        agent_id="agent:org-b-analytics",
        allowed_tools=["tool.ledger.get"],
    )
    reg = TrustRegistry(path=tmp_path / "registry.jsonl", operator_signer=operator)
    reg_metadata: dict = {"org": "org-a"}
    if with_statement:
        reg_metadata["capability_statement"] = stated.statement.to_dict()
    reg.publish(stated.public_key_pem(), issuer="org-a", metadata=reg_metadata)
    reg.publish(unstated.public_key_pem(), issuer="org-b", metadata={"org": "org-b"})
    tmp_sub = tmp_path / "sub"
    tmp_sub.mkdir(parents=True, exist_ok=True)
    writer = ProvenanceLogger(stated, sink_path=tmp_sub / "chain.jsonl")
    root = writer.record_user_input("read ACC-1 ledger")
    writer.close()
    root_line = (tmp_sub / "chain.jsonl").read_text(encoding="utf-8").strip()
    child = _mint_receipt_envelope(unstated, parents=[root], tool="tool.ledger.get")
    chain_text = root_line + "\n" + child
    registry_text = (tmp_path / "registry.jsonl").read_text(encoding="utf-8")
    return {
        "name": "mixed chain with a registered-but-unstated signing key",
        "chain": chain_text,
        "registry": registry_text,
        "opts": {"operatorPem": operator.public_key_pem().decode("ascii")},
        "expect": {
            "valid": False,
            "registry_ok": True,
            "scope": False,
            "reasonIncludes": [
                "no capability statement supplied for agent_key_id=",
                "line 2: no capability statement supplied for agent_key_id=",
            ],
        },
    }, operator.public_key_pem()


def test_mixed_chain_unstated_key_refuses_named(tmp_path):
    """A mixed chain (one signing key with a published statement, one
    registered but unstated) is a refusal, never a half-green verdict: the
    receipts of the unstated key are named against the scope leg."""
    scenario, operator_public_pem = _mixed_chain_scenario(tmp_path)
    v = verify_receipt_cross_org(
        scenario["chain"],
        registry_jsonl=scenario["registry"],
        operator_public_pem=operator_public_pem,
    )
    assert not v.valid
    assert v.registry_verified
    assert v.scope_verified is False
    joined = " ".join(v.reasons)
    assert "no capability statement supplied for agent_key_id=" in joined
    assert "line 2: no capability statement supplied for agent_key_id=" in joined


@pytest.mark.skipif(not _node_available(), reason="node unavailable")
def test_page_scope_leg_refuses_mixed_chain(tmp_path):
    """The shipped X2 page holds the scope leg closed exactly like the OSS
    verifier when a mixed chain carries a registered-but-unstated signing
    key: the verdict refuses and the reason names the unstated key."""
    scenario, _operator_public_pem = _mixed_chain_scenario(tmp_path)
    scenarios = {"cases": [scenario]}
    scen = tmp_path / "scenarios.json"
    scen.write_text(json.dumps(scenarios), encoding="utf-8")
    harness = ROOT / "tests" / "verifier_harness" / "x2_harness.mjs"
    r = subprocess.run(
        ["node", str(harness), str(ROOT), str(scen)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert r.returncode == 0, f"harness failed:\n{r.stdout}\n{r.stderr}"


def test_chain_with_no_published_statements_stays_honest(tmp_path):
    """The OSS mirror on the two-key construction: when the registry
    publishes no capability statement for ANY signing key, capability
    conformance is skipped entirely (the verifier receives no statements)
    and the scope leg stays honestly unstated with the verdict green,
    like test_scope_unstated_when_registry_publishes_no_statement."""
    scenario, operator_public_pem = _mixed_chain_scenario(tmp_path, with_statement=False)
    v = verify_receipt_cross_org(
        scenario["chain"],
        registry_jsonl=scenario["registry"],
        operator_public_pem=operator_public_pem,
    )
    assert v.valid, v.reasons
    assert v.registry_verified
    assert v.scope_verified is None
    assert "scope unstated" in " ".join(v.reasons)


@pytest.mark.skipif(not _node_available(), reason="node unavailable")
def test_page_scope_leg_unstated_when_registry_publishes_nothing(tmp_path):
    """The shipped X2 page keeps the honest-unstated verdict green when the
    registry publishes no capability statement for any signing key: without
    other keys' scope material the mixed-chain refusal must not fire
    (docs/spec/x2-cross-org-v0.1.md, Honest limits)."""
    scenario, _operator_public_pem = _mixed_chain_scenario(tmp_path, with_statement=False)
    scenario["name"] = "registry publishes no scope material for any signing key"
    scenario["expect"] = {
        "valid": True,
        "registry_ok": True,
        "scope": None,
        "reasonIncludes": [
            "scope unstated: the registry publishes no capability statement"
        ],
    }
    scenarios = {"cases": [scenario]}
    scen = tmp_path / "scenarios.json"
    scen.write_text(json.dumps(scenarios), encoding="utf-8")
    harness = ROOT / "tests" / "verifier_harness" / "x2_harness.mjs"
    r = subprocess.run(
        ["node", str(harness), str(ROOT), str(scen)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert r.returncode == 0, f"harness failed:\n{r.stdout}\n{r.stderr}"
