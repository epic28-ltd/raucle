"""Deterministic evidence minting for the receipt-ledger durability lane (issue 342).

Every helper derives its signing keys from fixed byte seeds
(``_seed_private``), pins its issued-at/registered-at/nonce fields to
named constants and writes only integer epochs, so regenerating the
committed fixtures (``python -m tests.ledger_support regenerate``) is
byte-stable: Ed25519 signatures are deterministic over these payloads.

The verification side never trusts these constants: the committed
fixtures under ``tests/fixtures/receipt-ledger-durability/`` carry only
PUBLIC keys and evidence bytes, and ``tests/test_receipt_anchor_fixtures.py``
verifies them offline through the existing verifier APIs alone.
"""

from __future__ import annotations

import base64
import datetime as _real_dt  # noqa: F401 (shim base)
import json
import tempfile
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from raucle.audit import Ed25519Signer, HashChainSink
from raucle.provenance import (
    AgentIdentity,
    CapabilityStatement,
    Operation,
    ProvenanceReceipt,
    _b64url_encode,
    _canonical_json,
    _sha256_hex,
    hash_text,
)
from raucle.receipt_store import SegmentedReceiptStore
from raucle.transparency import LOG_GENESIS_PREV_HASH, compute_chain_head

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "receipt-ledger-durability"

#: Epoch constants pinned for determinism (integer epochs only, no floats
#: in signed payload material).
BASE_IAT = 1_700_000_000
LOG_REGISTERED_AT_BASE = 1_700_100_000
FROZEN_SEAL_AT = 1_700_200_000
CHECKPOINT_NONCE = "0" * 32
CHECKPOINT_ISS = "raucle-portal"
LOG_OPERATOR_KID = "raucle-portal-test"
LOG_ORG = "anchorco"
SCITT_ENTRY_PROFILE = "urn:raucle:scitt:receipt-chain-head:v1"
SCITT_STATEMENT_SIGNATURE = "aWFuY2hvci1zaWduYXR1cmUtcGF0aC1wbGFjZWhvbGRlcg=="
CHAIN_ID = "chain-a"

LOG_OPERATOR_SEED = "raucle-issue-342-log-operator"


def _seed_private(name: str) -> Ed25519PrivateKey:
    """A fixed Ed25519 private key: sha256 of the seed name as the key seed."""
    import hashlib

    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(name.encode("utf-8")).digest())


def seeded_public_pem(seed_name: str) -> bytes:
    """The PEM bytes of a seeded key's public half."""
    return (
        _seed_private(seed_name)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def seeded_signer(seed_name: str) -> Ed25519Signer:
    """A house :class:`Ed25519Signer` over a seeded key (deterministic seals)."""
    return Ed25519Signer(_seed_private(seed_name))


# ---------------------------------------------------------------------------
# Receipt chains (the JWS provenance receipt ledger)
# ---------------------------------------------------------------------------


def _identity_statement(
    priv: Ed25519PrivateKey, pub_pem: bytes, key_id: str
) -> CapabilityStatement:
    stmt = CapabilityStatement(
        agent_id="agent:app",
        key_id=key_id,
        public_key_pem=pub_pem.decode("ascii"),
        allowed_models=[],
        allowed_tools=["lookup_balance"],
        data_classifications=[],
        issuer="raucle",
        issued_at=BASE_IAT,
        expires_at=None,
    )
    stmt.signature = base64.b64encode(priv.sign(_canonical_json(stmt.body()))).decode("ascii")
    return stmt


def identity_for_seed(seed_name: str) -> AgentIdentity:
    priv = _seed_private(seed_name)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = _sha256_hex(pub_pem)[:16]
    return AgentIdentity(
        agent_id="agent:app",
        private_key=priv,
        statement=_identity_statement(priv, pub_pem, key_id),
    )


def mint_receipt_dag_chain(
    *,
    depth: int,
    seed_name: str,
    base_iat: int = BASE_IAT,
    seed_by_step: dict[int, str] | None = None,
):
    """Mint a root-legal receipt chain: one ``user_input`` root plus
    ``depth`` tool_call receipts, each citing the previous receipt.

    ``seed_by_step`` re-signs individual steps with another identity (the
    key-rotation shape). Returns ``(envelopes, key_ids_per_line)`` where
    envelopes are the ``{"receipt_hash", "jws"}`` dicts the receipt
    ledger stores one per line. Deterministic for fixed seeds: Ed25519
    signatures are deterministic over the canonical payloads.
    """
    root_identity = identity_for_seed(seed_name)
    root = ProvenanceReceipt(
        agent_id=root_identity.agent_id,
        agent_key_id=root_identity.key_id,
        operation=Operation.USER_INPUT,
        input_hash=hash_text("issue-342 user input"),
        issued_at=base_iat,
    )
    root.sign(root_identity)
    envelopes = [{"receipt_hash": root.receipt_hash, "jws": root.jws}]
    key_ids = [root_identity.key_id]
    prev_hash = root.receipt_hash
    seed_by_step = seed_by_step or {}
    for step in range(depth):
        identity = identity_for_seed(seed_by_step.get(step, seed_name))
        call = ProvenanceReceipt(
            agent_id=identity.agent_id,
            agent_key_id=identity.key_id,
            operation=Operation.TOOL_CALL,
            parents=[prev_hash],
            tool="lookup_balance",
            input_hash=hash_text(f"call {step} args"),
            output_hash=hash_text(f"call {step} output"),
            issued_at=base_iat + 1 + step,
        )
        call.sign(identity)
        envelopes.append({"receipt_hash": call.receipt_hash, "jws": call.jws})
        key_ids.append(identity.key_id)
        prev_hash = call.receipt_hash
    return envelopes, key_ids


def chain_lines(envelopes: list[dict]) -> list[str]:
    """The receipt-ledger line bytes for envelopes, oldest first."""
    return [json.dumps(env, ensure_ascii=False) for env in envelopes]


def write_jsonl(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Audit hash chain (HashChainSink ledger)
# ---------------------------------------------------------------------------


def _frozen_dt_namespace():
    """A stand-in for ``raucle.audit.dt`` with a frozen now()."""

    class _FrozenDateTime(_real_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return _real_dt.datetime(2026, 11, 26, 12, 0, 0, tzinfo=_real_dt.timezone.utc)

    class _Shim:
        datetime = _FrozenDateTime
        timezone = _real_dt.timezone

    return _Shim()


def mint_audit_chain(
    path: Path, *, events: int = 5, checkpoint_every: int = 2, seed_name: str = "audit-key"
):
    """Mint a signed audit hash chain with deterministic bytes (frozen clock).

    Returns ``(public_key_pem, sink)``; the sink is closed before return.
    """
    signer = seeded_signer(seed_name)
    with mock.patch("raucle.audit.dt", _frozen_dt_namespace()):
        sink = HashChainSink(path, signer=signer, checkpoint_every=checkpoint_every)
        for i in range(events):
            sink.append({"seq": i, "note": f"event-{i}"})
        sink.close()
    return signer.public_key_pem(), sink


# ---------------------------------------------------------------------------
# Segment seals (the receipt store's seal sidecars)
# ---------------------------------------------------------------------------


def mint_sealed_segments(
    base_dir: Path, segments_lines: list[list[str]], *, seed_names: list[str]
) -> list[dict]:
    """Seal *segments_lines* through the real store, rotating the seal
    signer between segments. Returns the parsed ``.meta`` dicts; the
    sealed-at clock is frozen so the bytes are deterministic.
    """
    store = SegmentedReceiptStore(
        base_dir=base_dir, max_segment_bytes=1 << 30, seal_signer=seeded_signer(seed_names[0])
    )
    metas: list[dict] = []
    for index, lines in enumerate(segments_lines):
        for line in lines:
            store.append_line(line)
        with mock.patch("time.time", return_value=FROZEN_SEAL_AT + index):
            sealed = store.seal_now()
        assert sealed is not None
        metas.append(json.loads((base_dir / (sealed + ".meta")).read_text(encoding="utf-8")))
        if index + 1 < len(seed_names):
            store.set_seal_signer(seeded_signer(seed_names[index + 1]))
    return metas


# ---------------------------------------------------------------------------
# Hosted transparency log (registration proofs + epoch checkpoints)
# ---------------------------------------------------------------------------


def log_operator_key() -> tuple[Ed25519PrivateKey, str]:
    """The seeded operator key; its public PEM is what the verifier pins."""
    priv = _seed_private(LOG_OPERATOR_SEED)
    pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return priv, pem


def log_entries(*, org: str = LOG_ORG, count: int) -> list[dict]:
    """A per-org hash-chained registration log from genesis."""
    from tests.test_transparency_log_verify import _digest, _entry

    entries: list[dict] = []
    prev = LOG_GENESIS_PREV_HASH
    for seq in range(1, count + 1):
        entry = _entry(
            org, seq, prev, _digest(f"receipt-{org}-{seq}"), LOG_REGISTERED_AT_BASE + seq
        )
        entries.append(entry)
        prev = entry["entry_hash"]
    return entries


def sign_checkpoint(
    *, org: str, size: int, head_hash: str, epoch: int, iat: int, nonce: str = CHECKPOINT_NONCE
) -> str:
    """One deterministic epoch checkpoint over the named head."""
    header = {
        "alg": "EdDSA",
        "typ": "transparency-epoch/v1",
        "kid": LOG_OPERATOR_KID,
        "crit": ["raucle/v1"],
        "raucle/v1": "transparency",
    }
    payload = {
        "iss": CHECKPOINT_ISS,
        "org": org,
        "epoch": epoch,
        "size": size,
        "head_hash": head_hash,
        "iat": iat,
        "nonce": nonce,
    }
    priv, _ = log_operator_key()
    signing_input = (
        _b64url_encode(_canonical_json(header)) + "." + _b64url_encode(_canonical_json(payload))
    ).encode("ascii")
    return signing_input.decode("ascii") + "." + _b64url_encode(priv.sign(signing_input))


def inclusion_proof(entries: list[dict], *, target: int = 1) -> dict:
    """An inclusion proof whose checkpoint rides the seeded operator key."""
    head = entries[-1]
    return {
        "org": head["org"],
        "sequence": entries[target - 1]["sequence"],
        "entries": entries[target - 1 :],
        "size": head["sequence"],
        "head_hash": head["entry_hash"],
        "checkpoint_jws": sign_checkpoint(
            org=head["org"],
            size=head["sequence"],
            head_hash=head["entry_hash"],
            epoch=head["sequence"],
            iat=BASE_IAT + head["sequence"],
        ),
    }


def consistency_proof(entries: list[dict], *, from_size: int) -> dict:
    """A consistency proof between two signed heads, seeded checkpoints."""
    from_head = entries[from_size - 1]
    to_head = entries[-1]
    return {
        "org": from_head["org"],
        "from_size": from_size,
        "to_size": to_head["sequence"],
        "entries": entries[from_size:],
        "from_checkpoint_jws": sign_checkpoint(
            org=from_head["org"],
            size=from_head["sequence"],
            head_hash=from_head["entry_hash"],
            epoch=from_head["sequence"],
            iat=BASE_IAT + from_size,
        ),
        "to_checkpoint_jws": sign_checkpoint(
            org=to_head["org"],
            size=to_head["sequence"],
            head_hash=to_head["entry_hash"],
            epoch=to_head["sequence"],
            iat=BASE_IAT + to_head["sequence"],
        ),
    }


def statement_for_head(head, chain_id: str = CHAIN_ID) -> dict:
    """A SCITT signed-statement shape over a chain head (signature path present).

    The signature element is the documented position of the profile:
    full COSE verification against a transparency root is verifier
    wiring for a follow-up (docs/spec/transparency-v1.md), so the
    offline check ``verify_transparency_anchor`` implements is digest
    match + signature-path presence, never a COSE claim.
    """
    return {
        "statement": {
            "entry_profile": SCITT_ENTRY_PROFILE,
            "chain_id": chain_id,
            "chain_head": {"index": head.index, "hash": head.hash},
        },
        "signature": SCITT_STATEMENT_SIGNATURE,
    }


# ---------------------------------------------------------------------------
# Fixture regeneration (committed once; byte-stable re-generation)
# ---------------------------------------------------------------------------


def regenerate_fixtures(target_dir: Path | None = None) -> list[str]:
    """(Re)write every committed fixture under ``target_dir`` (the
    committed ``FIXTURE_DIR`` unless a caller passes another destination)."""
    import shutil

    out_dir = Path(target_dir) if target_dir is not None else FIXTURE_DIR
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    def _emit(name: str, payload: dict) -> None:
        path = out_dir / name
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        written.append(str(path))

    # 1. the plain receipt chain (single signing identity)
    envelopes, key_ids = mint_receipt_dag_chain(depth=3, seed_name="receipt-key-a")
    pub_pem = seeded_public_pem("receipt-key-a").decode("ascii")
    _emit(
        "receipt-chain.json",
        {
            "profile": "provenance-receipt-ledger/v1 chain of record",
            "chain": chain_lines(envelopes),
            "public_keys": {key_ids[0]: pub_pem},
            "expected": {
                "receipt_count": len(envelopes),
                "receipt_hashes": [e["receipt_hash"] for e in envelopes],
            },
        },
    )

    # 2. the key-rotation chain (later receipts signed under a new key id)
    envelopes_rot, key_ids_rot = mint_receipt_dag_chain(
        depth=4,
        seed_name="receipt-key-v1",
        seed_by_step={2: "receipt-key-v2", 3: "receipt-key-v2"},
    )
    _emit(
        "receipt-chain-rotation.json",
        {
            "profile": "provenance-receipt-ledger/v1 chain spanning a signing-key rotation",
            "chain": chain_lines(envelopes_rot),
            "public_keys": {
                key_ids_rot[0]: seeded_public_pem("receipt-key-v1").decode("ascii"),
                key_ids_rot[-1]: seeded_public_pem("receipt-key-v2").decode("ascii"),
            },
            "expected": {
                "receipt_count": len(envelopes_rot),
                "receipts_per_key": {
                    kid: sum(1 for k in key_ids_rot if k == kid) for kid in sorted(set(key_ids_rot))
                },
            },
        },
    )

    # 3. a sealed segment + signed seal sidecar from the real store
    envelopes_a, _ = mint_receipt_dag_chain(depth=2, seed_name="receipt-key-a")
    with tempfile.TemporaryDirectory() as td:
        metas = mint_sealed_segments(
            Path(td) / "segments", [chain_lines(envelopes_a)], seed_names=["seal-key-a"]
        )
        _emit(
            "segment-seal.json",
            {
                "profile": "segmented receipt store: one sealed segment + its Ed25519 seal meta",
                "segment": chain_lines(envelopes_a),
                "meta": metas[0],
                "public_key_pem": seeded_public_pem("seal-key-a").decode("ascii"),
                "expected": {
                    "receipt_count": len(envelopes_a),
                    "last_receipt_hash": envelopes_a[-1]["receipt_hash"],
                },
            },
        )

    # 4. the seal-rotation pair: segment A sealed under key 1, segment B
    #    sealed after the rotation with key 2 (set_seal_signer)
    envelopes_b, _ = mint_receipt_dag_chain(depth=2, seed_name="receipt-key-b")
    envelopes_c, _ = mint_receipt_dag_chain(depth=2, seed_name="receipt-key-c")
    with tempfile.TemporaryDirectory() as td:
        metas = mint_sealed_segments(
            Path(td) / "segments",
            [chain_lines(envelopes_b), chain_lines(envelopes_c)],
            seed_names=["seal-key-r1", "seal-key-r2"],
        )
        _emit(
            "segment-seal-rotation.json",
            {
                "profile": "sealed segments across a seal-identity rotation (set_seal_signer)",
                "segment_v1": chain_lines(envelopes_b),
                "meta_v1": metas[0],
                "public_key_v1": seeded_public_pem("seal-key-r1").decode("ascii"),
                "segment_v2": chain_lines(envelopes_c),
                "meta_v2": metas[1],
                "public_key_v2": seeded_public_pem("seal-key-r2").decode("ascii"),
                "expected": {
                    "receipt_count_v1": len(envelopes_b),
                    "receipt_count_v2": len(envelopes_c),
                    "last_receipt_hash_v2": envelopes_c[-1]["receipt_hash"],
                },
            },
        )

    # 5 + 6. the signed audit hash chain and its anchored head statement
    with tempfile.TemporaryDirectory() as td:
        chain_path = Path(td) / "chain.jsonl"
        audit_pem, _sink = mint_audit_chain(chain_path)
        chain_bytes = chain_path.read_text(encoding="utf-8").splitlines()
        chain_bytes = [ln for ln in chain_bytes if ln.strip()]
        head = compute_chain_head(chain_path)
        statement = statement_for_head(head)
        _emit(
            "audit-chain.json",
            {
                "profile": "audit hash chain of record: signed genesis + signed checkpoints",
                "chain": chain_bytes,
                "public_key_pem": audit_pem.decode("ascii"),
                "expected": {"event_count": 5, "checkpoint_count": 3, "head_index": head.index},
            },
        )
        _emit(
            "anchor-statement.json",
            {
                "profile": "SCITT signed statement anchoring the head of the audit chain fixture",
                "chain": chain_bytes,
                "chain_id": CHAIN_ID,
                "statement": statement["statement"],
                "signature": statement["signature"],
                "expected": {
                    "status": "TRANSPARENCY-ANCHORED",
                    "head_index": head.index,
                    "head_hash": head.hash,
                },
            },
        )

    # 7. the hosted transparency log (registration proofs + checkpoints)
    entries = log_entries(count=5)
    priv, op_pem = log_operator_key()
    del priv
    _emit(
        "transparency-log.json",
        {
            "profile": "hosted transparency log: registry entries + signed epoch checkpoints",
            "org": LOG_ORG,
            "entries": entries,
            "operator_public_key_pem": op_pem,
            "inclusion_proof": inclusion_proof(entries, target=1),
            "consistency_proof": consistency_proof(entries, from_size=3),
            "checkpoints": {
                str(size): sign_checkpoint(
                    org=LOG_ORG,
                    size=size,
                    head_hash=entries[size - 1]["entry_hash"],
                    epoch=size,
                    iat=BASE_IAT + size,
                )
                for size in (1, 3, 5)
            },
            "expected": {
                "size": len(entries),
                "head_hash": entries[-1]["entry_hash"],
                "checkpoints_sizes": [1, 3, 5],
            },
        },
    )
    return written


if __name__ == "__main__":
    regenerate_fixtures()
