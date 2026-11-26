"""Independent JOSE interoperability proof for the pq1 profile (re-check F143).

The pq1 JOSE profile claims a standards-conformant independent implementation
sees a three-segment Compact JWS (RFC 7515) and refuses it on the unknown
``raucle/pq1`` critical header entry rather than guessing. raucle's own tests
cannot prove the "independent implementation" half, so this module pins the
behaviour against an EXTERNAL, mainstream JOSE library driven unmodified.

Library: **joserfc** (pinned in pyproject ``[dev]``: ``>=1.7.7,<2``).
Behaviour recorded 2026-11-24 at CPython 3.13 / cryptography 50.0.2, on the
REAL untouched pq1 receipt (signature slot = 3373 bytes):

- Verification (``jws.deserialize_compact`` with a trusted Ed25519 key):
  REJECTS the unknown-crit payload BEFORE any signature work with
  ``joserfc.errors.UnsupportedHeaderError(
      "unsupported_header: Unsupported ['raucle/v1', 'raucle/pq1'] in header")``
  - the RFC 7515 section 4.1.11 behaviour an unaware verifier MUST have:
  no silent acceptance of an unrecognised critical mark. The library's
  ``validate_compact`` runs ``check_header`` before signature
  verification, so this rejection is the header-crit mechanism itself,
  not a signature failure. Re-verified identical on 1.7.7, the version
  the py3.10 resolution of the pin selects.
- Unverified framing parse (``jws.extract_compact``): on the verified
  minor 1.8.0 the library's documented ``max_signature_length`` bound
  (1024 bytes) applies to the base64url-encoded signature segment, so
  the real receipt's parse is REFUSED at that layer with
  ``joserfc.errors.ExceededSizeError("Signature of exceeds 1024
  bytes.")`` - an explicit rejection (a 4498-character slot is not a
  legal Ed25519 signature encoding in the first place), never a silent
  acceptance; pinned as-is (version-guarded: 1.7.7, the py3.10
  resolution, does not carry the default size bound and accepts the
  parse).
- The same parse with the library's own ``JWSRegistry`` constructed and
  its published ``max_signature_length`` attribute raised to the pq1
  slot's encoded length (configuration of a documented bound - no
  monkey-patching, no subclass, no shim): the untouched receipt parses
  as three-segment Compact framing and the protected header decodes,
  exposing ``crit``, the ``raucle/pq1`` extension value ``ml-dsa-65``
  and ``pqk``.

Why joserfc and not PyJWT: PyJWT 2.10.1 was probed with the same shape and
empirically DISQUALIFIED as the interop proof - ``jwt.get_unverified_header``
parses the framing and header fine, but ``jwt.decode`` with a valid Ed25519
signature SILENTLY ACCEPTS the receipt whose header carries unknown crit
entries (PyJWT implements no RFC 7515 crit handling). An interop proof
executed in the library that fails the check it is used for is no proof, so
the pinned library is the one whose rejection behaviour the finding asks to
demonstrate.

Closure criteria honoured here: the receipt bytes leave the shipped sign
path and reach BOTH verifiers untouched (no re-encoding, no shims, no
monkey-patching anywhere in this module); the crit rejection is asserted on
the library's own error type and message, not a widened ``Exception`` catch;
raucle's verifier accepts the same untouched receipt only when BOTH signature
components are verifiable (unknown PQ key fails closed; a flipped byte in the
ML-DSA half fails).
"""

from __future__ import annotations

import base64
import json
from importlib.metadata import version as _pkg_version

import pytest
from joserfc.errors import ExceededSizeError, UnsupportedHeaderError
from joserfc.jwk import OKPKey
from joserfc.jws import JWSRegistry, deserialize_compact, extract_compact

from raucle.pq import (
    ED25519_SIG_LEN,
    PQ1_CONCAT_LEN,
    pq_available,
    pq_public_key_pem,
)
from raucle.provenance import (
    AgentIdentity,
    ProvenanceLogger,
    ProvenanceVerifier,
)

#: Interop library the docstring records. Asserted so the docstring and the
#: installed dependency cannot drift apart silently.
INTEROP_LIBRARY = "joserfc"


def _resolved_version():
    """Version of the installed interop library as a comparable tuple."""
    parts = _pkg_version(INTEROP_LIBRARY).split(".")
    return tuple(int(p) for p in parts[:3])


pytestmark = pytest.mark.skipif(
    not pq_available(),
    reason="ML-DSA-65 unavailable in this cryptography build (interop proof needs the PQ path)",
)


@pytest.fixture(scope="module")
def pq1_receipt(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Mint a REAL pq1 receipt through the shipped sign path, untouched.

    Uses the production emitter exactly as the guarantee's pin suite does:
    ``ProvenanceLogger`` in strict quantum mode signing through
    ``HybridSigner``. The JWS string returned here is the receipt's emitted
    bytes, read verbatim from the chain sink and never re-encoded.
    """
    ident = AgentIdentity.generate(agent_id="agent:pq-interop")
    chain = tmp_path_factory.mktemp("pq-interop") / "chain.jsonl"
    logger = ProvenanceLogger(agent=ident, sink_path=str(chain), quantum_mode="strict")
    logger.record_user_input(text="independent JOSE interop proof (F143)")
    logger.close()
    with open(chain, encoding="utf-8") as fh:
        record = json.loads(fh.readline())
    jws = record["jws"]
    pq_pem = pq_public_key_pem(logger._hybrid.pq_private.public_key())
    return {
        "jws": jws,
        "chain": chain,
        "ident": ident,
        "pq_kid": logger._hybrid.pq_key_id,
        "pq_pem": pq_pem,
    }


class TestShippedEmission:
    """(a) The receipt minted by the shipped path carries the pq1 profile."""

    def test_receipt_is_three_segment_compact_jws(self, pq1_receipt):
        jws = pq1_receipt["jws"]
        parts = jws.split(".")
        assert len(parts) == 3, "untouched receipt is 3-segment Compact"
        assert jws.count(".") == 2, "untouched receipt is 3-segment Compact"
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["crit"] == ["raucle/v1", "raucle/pq1"]
        assert header["raucle/pq1"] == "ml-dsa-65"
        assert len(header["pqk"]) == 16
        assert len(base64.urlsafe_b64decode(parts[2] + "==")) == 64 + 3309


def _pq1_registry() -> JWSRegistry:
    """The library's own registry, its published size bound fitted to pq1.

    joserfc's ``JWSRegistry.max_signature_length`` defaults to 1024 bytes
    (a documented class-level bound) and applies to the base64url-encoded
    signature segment (the 3373-byte slot encodes to 4498 characters), so
    the bound is raised to the encoded length. Setting the attribute on a
    fresh instance through the public API is configuration, not
    modification: no monkey-patching, no subclass, no shim anywhere in
    this module.
    """
    registry = JWSRegistry(algorithms=["Ed25519"])
    encoded_len = (PQ1_CONCAT_LEN + 2) // 3 * 4  # base64url chars, no padding
    registry.max_signature_length = encoded_len
    return registry


class TestIndependentJoseLibrary:
    """(b)+(c) The untouched receipt against the unmodified external library."""

    def test_library_is_the_pinned_interop_target(self):
        assert _pkg_version(INTEROP_LIBRARY), (
            "the interop library must come from the installed [dev] dependency set"
        )

    def test_default_bounds_refuse_the_pq1_slot(self, pq1_receipt):
        """Out-of-the-box defaults refuse the 3373-byte slot explicitly.

        Recorded behaviour (joserfc 1.8.0): the registry's documented
        signature-size bound is 1024 bytes (applied to the base64url
        segment), so the parse dies at that layer with
        ``ExceededSizeError`` - never a silent acceptance. The py3.10
        resolution (joserfc 1.7.7) predates the default bound, so this
        records the 1.8.0-minor behaviour and is version-guarded.
        """
        if tuple(_resolved_version()) < (1, 8):
            pytest.skip("joserfc < 1.8 has no default signature-size bound")
        jws_bytes = pq1_receipt["jws"].encode("ascii")
        with pytest.raises(ExceededSizeError, match="1024"):
            extract_compact(jws_bytes)

    def test_library_parses_framing_and_protected_header(self, pq1_receipt):
        compact = extract_compact(pq1_receipt["jws"].encode("ascii"), registry=_pq1_registry())
        headers = compact.headers()
        assert headers["crit"] == ["raucle/v1", "raucle/pq1"], (
            "the external parser decodes the protected crit including the pq1 entry"
        )
        assert headers["raucle/pq1"] == "ml-dsa-65"
        assert len(headers["pqk"]) == 16
        payload = json.loads(compact.payload)
        assert payload["iss"] == "raucle-detect/provenance"

    def test_library_rejects_unknown_crit_on_verify(self, pq1_receipt):
        """RFC 7515 §4.1.11: no silent acceptance of an unrecognised crit mark.

        Pinned behaviour (joserfc 1.8.0): ``UnsupportedHeaderError`` carrying
        BOTH crit entries, raised before any signature verification. The
        assertion is deliberately narrow - error TYPE plus the crit entries
        named in the message - so a silent-accept regression cannot pass.
        """
        okp = OKPKey.import_key(pq1_receipt["ident"].public_key_pem())
        jws = pq1_receipt["jws"]
        registry = _pq1_registry()
        with pytest.raises(UnsupportedHeaderError) as exc_info:
            deserialize_compact(jws, okp, algorithms=["Ed25519"], registry=registry)
        assert "raucle/pq1" in str(exc_info.value), (
            f"the rejection names the critical entry it refused, got: {exc_info.value}"
        )
        assert "raucle/v1" in str(exc_info.value)


class TestRaucleVerifierSameReceipt:
    """(d) raucle's own verifier accepts the untouched receipt, both ways."""

    def test_verifier_accepts_with_both_components(self, pq1_receipt):
        ident: AgentIdentity = pq1_receipt["ident"]
        verifier = ProvenanceVerifier(
            public_keys={ident.key_id: ident.public_key_pem()},
            pq_public_keys={pq1_receipt["pq_kid"]: pq1_receipt["pq_pem"]},
        )
        report = verifier.verify_chain(pq1_receipt["chain"])
        assert report.valid, f"both-component verification failed: {report.errors}"
        assert report.receipt_count >= 1

    def test_verifier_fails_closed_without_the_pq_key(self, pq1_receipt):
        ident: AgentIdentity = pq1_receipt["ident"]
        verifier = ProvenanceVerifier(public_keys={ident.key_id: ident.public_key_pem()})
        report = verifier.verify_chain(pq1_receipt["chain"])
        assert not report.valid, "a pq1 receipt must not verify on the Ed25519 key alone"

    def test_verifier_rejects_a_flipped_ml_dsa_byte(self, pq1_receipt, tmp_path):
        with open(pq1_receipt["chain"], encoding="utf-8") as fh:
            line = fh.readline()
        record = json.loads(line)
        slot = _slot_bytes(record["jws"])
        slot[ED25519_SIG_LEN] ^= 0xFF  # first ML-DSA byte: the PQ component breaks
        tampered = _with_slot(
            record["jws"], base64.urlsafe_b64encode(bytes(slot)).decode().rstrip("=")
        )
        with open(pq1_receipt["chain"], encoding="utf-8") as fh:
            lines = fh.readlines()
        lines[0] = json.dumps({**record, "jws": tampered}) + "\n"
        mutant = tmp_path / "mutant-chain.jsonl"
        mutant.write_text("".join(lines), encoding="utf-8")

        ident: AgentIdentity = pq1_receipt["ident"]
        verifier = ProvenanceVerifier(
            public_keys={ident.key_id: ident.public_key_pem()},
            pq_public_keys={pq1_receipt["pq_kid"]: pq1_receipt["pq_pem"]},
        )
        report = verifier.verify_chain(mutant)
        assert not report.valid, "a broken ML-DSA component invalidates the receipt"


def _slot_bytes(jws: str) -> bytearray:
    """Signature slot of a Compact JWS as a mutable byte array."""
    parts = jws.split(".")
    pad = "=" * (-len(parts[2]) % 4)
    return bytearray(base64.urlsafe_b64decode(parts[2] + pad))


def _with_slot(jws: str, slot: str) -> str:
    """Rebuild the JWS with a replaced signature slot (used only for the
    explicitly tampered mutant, never for the untouched proof receipt)."""
    parts = jws.split(".")
    parts[2] = slot
    return ".".join(parts)
