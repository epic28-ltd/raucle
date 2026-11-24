"""Lane Q16 pins: the assurance-language closes (evidence levels, trust
modes, and the decision/execution boundary).

An external reviewer traced the gateway receipt path and found that the
language around receipts invites reading an AUTHORISATION decision receipt
as execution proof. Three claim classes are pinned here so the gap cannot
silently reopen:

1. Both public artefacts (the README security-claims section and
   docs/security-model.md) carry the three-guarantee receipt table, the
   four-level verdict vocabulary with honest availability status, the
   trust-mode labelling and the reviewer's planned schema vocabulary.
2. The README claim section never implies an authorisation receipt proves
   execution (bounded, deterministic grep discipline).
3. Receipts self-describe their evidence level via the informational
   ``x_evidence`` field, legacy receipts without the field still verify,
   a receipt claiming a higher level earns NO extra verifier trust, and
   trust modes are labelled informationally without changing any check.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raucle.audit import Ed25519Signer
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.passport import issue_passport, verify_passport
from raucle.provenance import (
    EVIDENCE_EXECUTOR_ATTESTED,
    EVIDENCE_GATE_OBSERVED,
    EVIDENCE_SELF_REPORTED,
    AgentIdentity,
    Operation,
    ProvenanceLogger,
    ProvenanceReceipt,
    ProvenanceVerifier,
    hash_text,
)
from raucle.trust_registry import TrustRegistry

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
SECURITY_MODEL = REPO_ROOT / "docs" / "security-model.md"

CLAIMS_START = "## The audit problem"
CLAIMS_END = "## What It Detects"

# The three-guarantee receipt table: every row label must appear in BOTH
# artefacts, and the authorisation row must carry the not-execution caveat.
GUARANTEE_ROW_LABELS = (
    "Authorisation evidence",
    "Application-attested execution evidence",
    "Executor-attested (registered roadmap)",
    "Externally anchored (registered roadmap)",
)

# The four-level verdict vocabulary (Close 2b): both artefacts must name
# every level, each with ITS honest availability marker.
LEVEL_AVAILABILITY = {
    "PROVENANCE_SIGNATURE_VALID": "issued today",
    "CAPABILITY_OPERATION_PERMITTED": "issued today",
    "GATE_DECISION_VERIFIED": "issued today",
    "EXECUTION_CONFIRMED": "registered roadmap",
}

# The reviewer's trust-level vocabulary, quoted as the planned schema
# evolution and marked designed-not-shipped.
VOCAB_WORDS = ("SELF_REPORTED", "GATE_OBSERVED", "EXECUTOR_ATTESTED", "EXTERNALLY_CONFIRMED")

TRUST_MODE_WORDS = ("self-asserted", "authority-issued")


def _claims_section() -> str:
    text = README.read_text(encoding="utf-8")
    start = text.index(CLAIMS_START)
    end = text.index(CLAIMS_END)
    return text[start:end]


def _lines_with(text: str, needle: str) -> list[str]:
    return [line for line in text.splitlines() if needle in line]


def _collapse(s: str) -> str:
    return " ".join(s.split())


# ---------------------------------------------------------------------------
# 1. Documentation pins: the three-guarantee table in BOTH artefacts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [README, SECURITY_MODEL], ids=["readme", "security-model"])
class TestThreeGuaranteeTable:
    """Close 1: the receipt-family separation, pinned in both artefacts."""

    def test_all_guarantee_rows_present(self, path):
        text = path.read_text(encoding="utf-8")
        for label in GUARANTEE_ROW_LABELS:
            assert label in text, f"{path.name}: guarantee row '{label}' missing"

    def test_authorisation_row_denies_execution_proof(self, path):
        text = path.read_text(encoding="utf-8")
        rows = _lines_with(text, "| Authorisation evidence |")
        assert rows, f"{path.name}: no authorisation-evidence table row"
        assert any("does NOT prove tool execution" in row for row in rows), (
            f"{path.name}: the authorisation row must state it does NOT prove tool execution"
        )

    def test_execution_row_names_self_reporting(self, path):
        text = path.read_text(encoding="utf-8")
        rows = _lines_with(text, "| Application-attested execution evidence |")
        assert rows and any("self_reported" in row for row in rows), (
            f"{path.name}: the execution-evidence row must name its self-reported x_evidence claim"
        )

    def test_roadmap_rows_cite_the_registered_programme(self, path):
        text = path.read_text(encoding="utf-8")
        w1_rows = _lines_with(text, "| Executor-attested (registered roadmap) |")
        assert w1_rows and any(
            "docs/spec/provenance/v1.2/state-verification.md" in row for row in w1_rows
        ), f"{path.name}: the executor-attested roadmap row must cite the W1 spec"
        anchor_rows = _lines_with(text, "| Externally anchored (registered roadmap) |")
        assert anchor_rows and any("transparency" in row.lower() for row in anchor_rows), (
            f"{path.name}: the externally-anchored roadmap row must name the transparency log"
        )

    def test_aec_draft_cited_as_standards_direction(self, path):
        text = path.read_text(encoding="utf-8")
        assert "draft-schrock-ep-authorization-evidence-chain" in text, (
            f"{path.name}: the AEC evidence-chain composition draft is the "
            "standards direction and must be cited"
        )

    def test_x_evidence_documented_in_both(self, path):
        text = _collapse(path.read_text(encoding="utf-8"))
        for needle in ("x_evidence", "gate_observed", "treated as informational"):
            assert needle in text, f"{path.name}: documents must carry '{needle}'"


# ---------------------------------------------------------------------------
# 1b. Documentation pins: the four-level verdict vocabulary with status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [README, SECURITY_MODEL], ids=["readme", "security-model"])
class TestVerdictVocabulary:
    """Close 2b(b): the four levels, each with its honest availability."""

    def test_all_four_levels_named(self, path):
        text = path.read_text(encoding="utf-8")
        for level in LEVEL_AVAILABILITY:
            assert level in text, f"{path.name}: verdict level '{level}' missing"

    def test_each_level_row_carries_its_status(self, path):
        text = path.read_text(encoding="utf-8")
        for level, status in LEVEL_AVAILABILITY.items():
            rows = _lines_with(text, level)
            assert rows, f"{path.name}: level '{level}' has no table row"
            assert any(status in row for row in rows), (
                f"{path.name}: level '{level}' must carry its availability status '{status}'"
            )

    def test_gate_row_names_the_authorisation_only_honesty(self, path):
        text = path.read_text(encoding="utf-8")
        rows = _lines_with(text, "GATE_DECISION_VERIFIED")
        assert any("does NOT prove execution" in row for row in rows), (
            f"{path.name}: the GATE_DECISION_VERIFIED row must state that the "
            "level is authorisation evidence only"
        )

    def test_execution_row_names_the_registered_programme(self, path):
        text = path.read_text(encoding="utf-8")
        rows = _lines_with(text, "| EXECUTION_CONFIRMED |")
        joined = " ".join(rows)
        assert "state-verification.md" in joined, (
            f"{path.name}: the EXECUTION_CONFIRMED roadmap row must cite the "
            "W1 state-verification spec"
        )
        assert "draft-schrock-ep-authorization-evidence-chain" in joined, (
            f"{path.name}: the EXECUTION_CONFIRMED roadmap row must cite the AEC composition draft"
        )
        assert any("not issued" in row or "no receipt kind issues" in row for row in rows), (
            f"{path.name}: the EXECUTION_CONFIRMED row must say today's "
            "product does not issue that level"
        )


# ---------------------------------------------------------------------------
# 1c. Documentation pins: trust-mode labelling and the planned vocabulary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [README, SECURITY_MODEL], ids=["readme", "security-model"])
class TestTrustModeLabelling:
    """Close 2b(a): self-asserted vs authority-issued, informational only."""

    def test_both_trust_modes_named(self, path):
        text = _collapse(path.read_text(encoding="utf-8"))
        for word in TRUST_MODE_WORDS:
            assert word in text, f"{path.name}: trust mode '{word}' missing"

    def test_never_implied_authorisation_from_self_signature(self, path):
        text = _collapse(path.read_text(encoding="utf-8"))
        assert "never implies organisational authorisation" in text, (
            f"{path.name}: the verifier promise that a cryptographic "
            "self-signature never implies organisational authorisation must "
            "be stated"
        )

    def test_mode_reporting_named_informational(self, path):
        text = _collapse(path.read_text(encoding="utf-8"))
        assert "informational" in text and "trust mode" in text.lower(), (
            f"{path.name}: the trust mode must be reported as an informational "
            "field of the verify verdict"
        )

    def test_reviewer_vocab_quoted_designed_not_shipped(self, path):
        text = _collapse(path.read_text(encoding="utf-8"))
        joined_vocab = " / ".join(VOCAB_WORDS)
        assert joined_vocab in text, (
            f"{path.name}: the reviewer vocabulary '{joined_vocab}' must be "
            "quoted as the planned schema evolution"
        )
        assert text.count("designed, not shipped") >= 1, (
            f"{path.name}: the planned schema evolution must be marked 'designed, not shipped'"
        )


# ---------------------------------------------------------------------------
# 2. README claim discipline: no authorisation receipt implies execution
# ---------------------------------------------------------------------------


class TestReadmeClaimDiscipline:
    """The reviewer's grep-discipline ask, bounded and deterministic."""

    # A claim-span that ties a receipt to a proof verb about execution.
    RECEIPT_PROVES_EXECUTION = re.compile(
        r"receipt[^.;]{0,220}?\b(?:proves?|confirms?|shows?|demonstrat\w+)\b"
        r"[^.;]{0,120}?\bexecut\w*",
        re.IGNORECASE,
    )
    # The exact legacy offenders the reviewer quoted back at us.
    LEGACY_PATTERNS = (
        r"what action was executed",
        r"authorised and what was done",
    )

    def test_no_proves_execution_phrase(self):
        claims = _claims_section()
        # The reviewer's ask, exact phrase form: the un-negated claim
        # "proves execution" is banned; the honest negated table rows
        # ("does NOT prove execution") stay allowed.
        match = re.search(r"proves\s+execution", claims, flags=re.IGNORECASE)
        assert match is None, (
            f"README claims section must not contain 'proves execution': "
            f"...{claims[max(0, match.start() - 60) : match.end() + 60]}..."
        )

    def test_no_receipt_proves_execution_claim(self):
        claims = _claims_section()
        for match in self.RECEIPT_PROVES_EXECUTION.finditer(claims):
            span = claims[match.start() : match.end()]
            span_lower = span.lower()
            # A span that carries its own negation is the honest form; only
            # an unhedged claim is a violation.
            if any(
                marker in span_lower
                for marker in ("not proof", "does not prove", "does NOT prove", "never proves")
            ):
                continue
            pytest.fail(
                "README claims section implies an authorisation receipt "
                f"proves execution: ...{_collapse(span)}..."
            )

    def test_legacy_offender_sentences_removed(self):
        claims = _claims_section()
        for pattern in self.LEGACY_PATTERNS:
            match = re.search(pattern, claims, flags=re.IGNORECASE)
            assert match is None, (
                f"README claims section still carries the execution-claim "
                f"legacy pattern {pattern!r}"
            )


# ---------------------------------------------------------------------------
# 3. Code pins: the additive x_evidence field on new receipts
# ---------------------------------------------------------------------------


POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
"""


def _decode_payload(jws: str) -> dict:
    payload_b64 = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))


class TestReceiptEvidenceField:
    """Close 2: receipts self-describe their evidence level, additively."""

    def test_gate_decision_receipts_carry_gate_observed(self, tmp_path):
        policy = tmp_path / "policies.yaml"
        policy.write_text(POLICY)
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file=str(policy),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
        )
        gw = RaucleGateway(config)
        client = TestClient(create_gateway_app(gw))
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
        )
        body = resp.json()
        assert body["decision"] == "allow"
        receipt_id = body["receipt_id"]
        stored = [
            json.loads(line) for line in (tmp_path / "receipts.jsonl").read_text().splitlines()
        ]
        envelope = next(e for e in stored if e["receipt_hash"] == receipt_id)
        payload = _decode_payload(envelope["jws"])
        # The pin names the field: new /gate decision receipts carry
        # evidence=gate_observed, riding the x_ extension namespace.
        assert payload["x_evidence"] == EVIDENCE_GATE_OBSERVED
        assert EVIDENCE_GATE_OBSERVED == "gate_observed"

    def test_tool_call_receipts_carry_self_reported(self, tmp_path):
        identity = AgentIdentity.generate(agent_id="agent:app", allowed_tools=["send_email"])
        logger = ProvenanceLogger(agent=identity, sink_path=tmp_path / "chain.jsonl")
        root = logger.record_user_input(text="send the summary")
        logger.record_tool_call(
            parents=[root], tool="send_email", input_args={"to": "a@b"}, output={"ok": True}
        )
        payloads = [
            _decode_payload(json.loads(line)["jws"])
            for line in (tmp_path / "chain.jsonl").read_text().splitlines()
        ]
        by_op = {p["operation"]: p for p in payloads}
        # Only the app-recorded tool_call receipt is self-reported; the
        # user_input root carries no evidence claim at all.
        assert by_op["tool_call"]["x_evidence"] == EVIDENCE_SELF_REPORTED
        assert EVIDENCE_SELF_REPORTED == "self_reported"
        assert "x_evidence" not in by_op["user_input"]

    def test_legacy_receipts_without_the_field_verify(self, tmp_path):
        identity = AgentIdentity.generate(agent_id="agent:legacy", allowed_tools=["legacy_tool"])
        root = ProvenanceReceipt(
            agent_id=identity.agent_id,
            agent_key_id=identity.key_id,
            operation=Operation.USER_INPUT,
            input_hash=hash_text("go"),
            issued_at=1700000000,
        )
        root.sign(identity)
        call = ProvenanceReceipt(
            agent_id=identity.agent_id,
            agent_key_id=identity.key_id,
            operation=Operation.TOOL_CALL,
            parents=[root.receipt_hash],
            tool="legacy_tool",
            input_hash=hash_text("{}"),
            output_hash=hash_text("{}"),
            issued_at=1700000002,
        )
        call.sign(identity)
        chain = tmp_path / "legacy.jsonl"
        with chain.open("a", encoding="utf-8") as fh:
            for receipt in (root, call):
                fh.write(
                    json.dumps(
                        {"receipt_hash": receipt.receipt_hash, "jws": receipt.jws},
                        ensure_ascii=False,
                    )
                    + "\n"
                )
        verifier = ProvenanceVerifier(public_keys={identity.key_id: identity.public_key_pem()})
        report = verifier.verify_chain(chain)
        # Legacy receipts (no x_evidence field, the pre-Q16 shape) still
        # verify: the field's absence is tolerated, never a failure.
        assert report.valid, report.errors

    def test_claimed_higher_level_is_the_producer_claim_only(self, tmp_path):
        identity = AgentIdentity.generate(agent_id="agent:app", allowed_tools=["send_email"])
        logger = ProvenanceLogger(agent=identity, sink_path=tmp_path / "chain.jsonl")
        root = logger.record_user_input(text="send the other summary")
        logger.record_tool_call(
            parents=[root], tool="send_email", input_args={"to": "c@d"}, output={"ok": True}
        )
        # Rewrap the tool receipt's claim as executor_attested: the app
        # self-declares a higher level than it can prove.
        line = json.loads((tmp_path / "chain.jsonl").read_text().splitlines()[1])
        receipt = ProvenanceReceipt.from_jws(line["jws"])
        receipt.x_evidence = EVIDENCE_EXECUTOR_ATTESTED
        assert EVIDENCE_EXECUTOR_ATTESTED == "executor_attested"
        receipt.sign(identity)
        # Rebuild the chain honestly: the original root envelope plus the
        # re-signed tool receipt that self-declares the higher level.
        chain = tmp_path / "replay.jsonl"
        root_env = json.loads((tmp_path / "chain.jsonl").read_text().splitlines()[0])
        with chain.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(root_env, ensure_ascii=False) + "\n")
            fh.write(
                json.dumps(
                    {"receipt_hash": receipt.receipt_hash, "jws": receipt.jws},
                    ensure_ascii=False,
                )
                + "\n"
            )
        verifier = ProvenanceVerifier(public_keys={identity.key_id: identity.public_key_pem()})
        report = verifier.verify_chain(chain)
        # The pin names the behaviour: a receipt claiming evidence=executor_attested
        # is TREATED AS the app's claim - it verifies like any other receipt,
        # the verifier grants no extra trust from the label.
        assert report.valid, report.errors
        assert report.signature_failures == 0
        assert report.capability_violations == 0


# ---------------------------------------------------------------------------
# 4. Code pins: trust modes are labelled informationally
# ---------------------------------------------------------------------------


class TestTrustModeLabellingCode:
    """Close 2b(a): the verdict distinguishes self-asserted statements."""

    def _identity_chain(self, tmp_path):
        identity = AgentIdentity.generate(agent_id="agent:tm", allowed_tools=["send_email"])
        logger = ProvenanceLogger(agent=identity, sink_path=tmp_path / "chain.jsonl")
        root = logger.record_user_input(text="say hello")
        logger.record_tool_call(
            parents=[root], tool="send_email", input_args={"to": "e@f"}, output={"ok": True}
        )
        return identity, tmp_path / "chain.jsonl"

    def test_statement_resolved_without_a_label_is_self_asserted(self, tmp_path):
        identity, chain_path = self._identity_chain(tmp_path)
        verifier = ProvenanceVerifier(
            public_keys={identity.key_id: identity.public_key_pem()},
            capabilities={identity.key_id: identity.statement},
        )
        report = verifier.verify_chain(chain_path)
        assert report.valid, report.errors
        assert report.capability_trust_modes == {identity.key_id: "self_asserted"}, (
            "a supplied statement with no explicit label is reported as self-asserted"
        )
        assert report.to_dict()["capability_trust_modes"] == report.capability_trust_modes

    def test_explicit_authority_issued_is_reported_not_enforced(self, tmp_path):
        identity, chain_path = self._identity_chain(tmp_path)
        base = dict(
            public_keys={identity.key_id: identity.public_key_pem()},
            capabilities={identity.key_id: identity.statement},
        )
        labelled = ProvenanceVerifier(
            **base,
            capability_trust_modes={identity.key_id: "authority_issued"},
        ).verify_chain(chain_path)
        unlabelled = ProvenanceVerifier(**base).verify_chain(chain_path)
        assert labelled.capability_trust_modes == {identity.key_id: "authority_issued"}
        # Informational only: the label never changes any check outcome.
        for attr in (
            "valid",
            "receipt_count",
            "signature_failures",
            "capability_violations",
            "taint_monotonicity_failures",
        ):
            assert getattr(labelled, attr) == getattr(unlabelled, attr), (
                f"the trust label must be informational only: {attr} changed"
            )

    def test_unknown_trust_mode_refused(self, tmp_path):
        identity, _chain_path = self._identity_chain(tmp_path)
        with pytest.raises(ValueError, match="trust mode"):
            ProvenanceVerifier(
                public_keys={identity.key_id: identity.public_key_pem()},
                capabilities={identity.key_id: identity.statement},
                capability_trust_modes={identity.key_id: "organisational"},
            )

    def test_passport_verdict_labels_itself_authority_issued(self, tmp_path):
        org_signer = Ed25519Signer.generate()
        reg = TrustRegistry(tmp_path / "reg.jsonl", operator_signer=Ed25519Signer.generate())
        reg.publish(org_signer.public_key_pem().decode(), issuer="Org X")
        agent = AgentIdentity.generate(agent_id="agent:pass.port", allowed_tools=["t"])
        passport = issue_passport(agent.statement, issuer_signer=org_signer, issuer="Org X")
        verdict = verify_passport(passport.to_dict(), registry=reg)
        assert verdict.valid
        assert verdict.trust_mode == "authority_issued"
        reg.revoke(passport.issuer_key_id, reason="rotated")
        bad = verify_passport(passport.to_dict(), registry=reg)
        assert not bad.valid
        # A failure verdict resolves no trust at all.
        assert bad.trust_mode == ""
