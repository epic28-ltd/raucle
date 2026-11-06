"""Conformance-vector tests for raucle/epaec.py — EP-AEC verification (N4).

Drives the verifier over tests/vectors/epaec-v1.json, the shared corpus
vector set emitted by tools/make_epaec_vectors.py (consumable by N10 /
independent implementers).  Each vector pairs an issued chain with the
expected decision/overall/statuses/reasons, per
draft-schrock-ep-authorization-evidence-chain-00.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from raucle import epaec

VECTORS_PATH = Path(__file__).resolve().parent / "vectors" / "epaec-v1.json"

VERIFIER_KEY = {"kty": "EC", "crv": "P-256", "x": "", "y": ""}


def _load():
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def corpus():
    return _load()


def _verifiers_from_receipt_key(corpus):
    """Rebuild the vector set's verifier configuration from the stored receipts.

    The vector file records the trusting JWK's coordinates in the vector set
    header, emitted by tools/make_epaec_vectors.py; a relying party replays
    with exactly this configuration.
    """
    # No JWK stored in the vector doc: issue-time randomised ECDSA forbids
    # regenerating keys, so the vector doc embeds the signed receipts and the
    # verifier under test is configured per receipt via the doc's jwk block.
    jwk = corpus["jwk"]
    return {
        "ep-receipt": epaec.make_receipt_verifier(lambda _e: jwk),
        "policy-permit": lambda e: (
            isinstance(e, dict)
            and e.get("actionDigest") == epaec.canonical_action_digest(corpus["action"]),
            e.get("actionDigest") if isinstance(e, dict) else None,
        ),
    }


def test_vector_file_shape(corpus):
    assert corpus["profile"] == "EP-AEC-v1"
    assert corpus["draft"] == "draft-schrock-ep-authorization-evidence-chain-00"
    assert len(corpus["vectors"]) >= 7
    assert corpus["jwk"]["kty"] == "EC"


@pytest.mark.parametrize("index", range(8))
def test_vector_outcome(index, corpus):
    vectors = corpus["vectors"]
    if index >= len(vectors):
        pytest.skip("vector index out of range")
    v = vectors[index]
    res = epaec.verify_chain(v["chain"], _verifiers_from_receipt_key(corpus))
    expected = v["expected"]
    assert res.to_dict()["decision"] == expected["decision"]
    assert res.to_dict()["overall"] == expected["overall"]
    assert [c["status"] for c in res.to_dict()["components"]] == expected["statuses"]
    assert [c["reason"] for c in res.to_dict()["components"]] == expected["reasons"]
    assert res.requirement_error == expected["requirement_error"]


def test_vector_valid_e2e_allows(corpus):
    v = next(v for v in corpus["vectors"] if v["name"] == "valid_e2e")
    res = epaec.verify_chain(v["chain"], _verifiers_from_receipt_key(corpus))
    assert (res.decision, res.overall) == ("ALLOW", "PASS")
    assert all(c["status"] == "VALID" for c in res.components)


def test_vector_bytes_deterministic(corpus):
    v = next(v for v in corpus["vectors"] if v["name"] == "valid_e2e")
    verifiers = _verifiers_from_receipt_key(corpus)
    assert epaec.result_bytes(epaec.verify_chain(v["chain"], verifiers)) == epaec.result_bytes(
        epaec.verify_chain(v["chain"], verifiers)
    )
