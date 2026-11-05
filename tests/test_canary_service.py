"""Tests for the one-time canary mint/observe service (P1.3a)."""

import json

import pytest

from raucle.agent_credentials import AgentCredentialStore
from raucle.canary_service import (
    REASON_OBSERVED,
    REASON_REPLAYED,
    REASON_REVOKED,
    REASON_UNKNOWN,
    CanaryService,
)


@pytest.fixture
def paths(tmp_path):
    return {
        "store": tmp_path / "agent-credentials.jsonl",
        "ledger": tmp_path / "canary-ledger.jsonl",
        "receipts": tmp_path / "canary-receipts.jsonl",
    }


@pytest.fixture
def make_service(paths):
    def factory() -> CanaryService:
        return CanaryService(
            AgentCredentialStore(path=paths["store"]),
            ledger_path=paths["ledger"],
            receipts_path=paths["receipts"],
        )

    return factory


def _receipt_events(paths) -> list[dict]:
    lines = paths["receipts"].read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


class TestMint:
    def test_mint_issues_raucle_credential(self, make_service, paths):
        service = make_service()
        mint = service.mint(run_id="run-1")
        # The canary value is a real rak_ credential the credential store honours.
        assert mint.value.startswith("rak_")
        assert mint.mint_id.startswith("canary:")
        assert mint.run_id == "run-1"
        assert mint.minted_at > 0
        # A fresh service instance sees the credential through the shared store.
        other = make_service()
        assert other._creds.verify(mint.value) == mint.mint_id  # noqa: SLF001

    def test_mint_records_issuance_receipt(self, make_service, paths):
        service = make_service()
        mint = service.mint(run_id="run-1")
        events = _receipt_events(paths)
        assert len(events) == 1
        assert events[0]["event"] == "canary.mint"
        assert events[0]["mint_id"] == mint.mint_id
        assert events[0]["run_id"] == "run-1"
        assert events[0]["key_fingerprint"] == mint.key_fingerprint
        assert events[0]["ts"] > 0

    def test_minted_at_recorded_in_ledger(self, make_service, paths):
        service = make_service()
        mint = service.mint(run_id="run-1")
        record = json.loads(paths["ledger"].read_text(encoding="utf-8").splitlines()[0])
        assert record["mint_id"] == mint.mint_id
        assert record["minted_at"] == pytest.approx(mint.minted_at)
        assert record["run_id"] == "run-1"
        assert record["consumed_at"] is None

    def test_each_mint_is_unique(self, make_service):
        service = make_service()
        a = service.mint(run_id="run-1")
        b = service.mint(run_id="run-2")
        assert a.value != b.value
        assert a.mint_id != b.mint_id


class TestObserve:
    def test_first_observation_succeeds(self, make_service):
        service = make_service()
        mint = service.mint(run_id="run-1")
        verdict = service.observe(mint.value)
        assert verdict.observed() is True
        assert verdict.status == "observed"
        assert verdict.reason == REASON_OBSERVED
        assert verdict.mint_id == mint.mint_id
        assert verdict.run_id == "run-1"
        assert verdict.key_fingerprint == mint.key_fingerprint
        assert verdict.minted_at == pytest.approx(mint.minted_at)
        assert verdict.observed_at > 0

    def test_second_observation_fails_one_time_semantics(self, make_service):
        service = make_service()
        mint = service.mint(run_id="run-1")
        first = service.observe(mint.value)
        assert first.observed() is True
        second = service.observe(mint.value)
        assert second.observed() is False
        assert second.reason == REASON_REPLAYED
        assert second.mint_id == mint.mint_id

    def test_observation_persists_across_service_reload(self, make_service):
        service = make_service()
        mint = service.mint(run_id="run-1")
        assert make_service().observe(mint.value).observed() is True
        # A fresh instance (fresh process) must still refuse the consumed canary.
        assert make_service().observe(mint.value).reason == REASON_REPLAYED

    def test_observation_success_is_receipted(self, make_service, paths):
        service = make_service()
        mint = service.mint(run_id="run-1")
        service.observe(mint.value)
        events = _receipt_events(paths)
        observe = [e for e in events if e["event"] == "canary.observe"]
        assert len(observe) == 1
        assert observe[0]["status"] == "observed"
        assert observe[0]["mint_id"] == mint.mint_id

    def test_unknown_canary_fails(self, make_service, paths):
        service = make_service()
        service.mint(run_id="run-1")
        verdict = service.observe("rak_not_a_real_canary_value")
        assert verdict.observed() is False
        assert verdict.reason == REASON_UNKNOWN
        assert verdict.mint_id == ""
        assert verdict.run_id == ""
        # Denials are provably recorded.
        denials = [e for e in _receipt_events(paths) if e["event"] == "canary.deny"]
        assert len(denials) == 1
        assert denials[0]["reason"] == REASON_UNKNOWN

    def test_empty_and_non_string_values_fail(self, make_service):
        service = make_service()
        service.mint(run_id="run-1")
        for bad in ("", 123):  # type: ignore[list-item]
            verdict = service.observe(bad)  # type: ignore[arg-type]
            assert verdict.observed() is False
            assert verdict.reason == REASON_UNKNOWN

    def test_revoked_credential_denied_and_receipted(self, make_service, paths):
        service = make_service()
        mint = service.mint(run_id="run-1")
        assert service._creds.revoke(agent_id=mint.mint_id) is True  # noqa: SLF001
        verdict = service.observe(mint.value)
        assert verdict.observed() is False
        assert verdict.reason == REASON_REVOKED
        assert verdict.mint_id == mint.mint_id
        denials = [e for e in _receipt_events(paths) if e["event"] == "canary.deny"]
        assert len(denials) == 1
        assert denials[0]["reason"] == REASON_REVOKED

    def test_denial_does_not_consume_an_unknown_canary(self, make_service):
        service = make_service()
        mint = service.mint(run_id="run-1")
        # Observing an unrelated value leaves the real canary outstanding.
        assert service.observe("rak_something_else_entirely").observed() is False
        assert service.observe(mint.value).observed() is True


class TestDeterministicVerdict:
    def test_same_inputs_produce_identical_verdict_bytes(self, make_service):
        service = make_service()
        mint = service.mint(run_id="run-1")
        first = service.observe(mint.value, at=1000.0)
        second = service.observe(mint.value, at=2000.0)
        third = service.observe(mint.value, at=3000.0)
        assert first.verdict_bytes() != second.verdict_bytes()
        assert first.observed() is True
        # The same denial replayed at different times yields identical bytes.
        assert second.observed() is False
        assert second.verdict_bytes() == third.verdict_bytes()

    def test_verdict_bytes_are_canonical_json(self, make_service):
        service = make_service()
        mint = service.mint(run_id="run-1")
        verdict = service.observe(mint.value, at=1000.0)
        payload = json.loads(verdict.verdict_bytes())
        assert payload == {
            "key_fingerprint": mint.key_fingerprint,
            "mint_id": mint.mint_id,
            "reason": "observed",
            "run_id": "run-1",
            "status": "observed",
        }
        # Sorted keys, compact separators, deterministic encoding.
        assert verdict.verdict_bytes() == json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def test_bytes_exclude_wall_clock_stamps(self, make_service):
        service = make_service()
        mint = service.mint(run_id="run-1")
        verdict = service.observe(mint.value, at=1000.0)
        assert verdict.observed_at == 1000.0
        assert b"1000" not in verdict.verdict_bytes()
        assert str(mint.minted_at).encode() not in verdict.verdict_bytes()

    def test_denial_bytes_deterministic_per_reason(self, make_service):
        service = make_service()
        service.mint(run_id="run-1")
        unknown_a = service.observe("rak_unknown_one", at=1.0)
        unknown_b = service.observe("rak_unknown_one", at=2.0)
        assert unknown_a.verdict_bytes() == unknown_b.verdict_bytes()

    def test_to_dict_carries_mint_time_and_observed_at(self, make_service):
        service = make_service()
        mint = service.mint(run_id="run-1")
        verdict = service.observe(mint.value, at=4242.0)
        d = verdict.to_dict()
        assert d["minted_at"] == pytest.approx(mint.minted_at)
        assert d["observed_at"] == 4242.0
        # The full dictionary is richer than the comparable bytes.
        assert set(d) >= {
            "status",
            "reason",
            "mint_id",
            "run_id",
            "key_fingerprint",
            "minted_at",
            "observed_at",
        }


class TestLedgerIntegrity:
    def test_corrupt_ledger_fails_closed(self, make_service, paths):
        service = make_service()
        service.mint(run_id="run-1")
        paths["ledger"].write_text("this is not json\n", encoding="utf-8")
        with pytest.raises(ValueError, match="refusing to reset"):
            make_service()

    def test_corrupt_ledger_line_fails_closed(self, make_service, paths):
        paths["ledger"].write_text('{"minted_at": 1.0}\n', encoding="utf-8")
        with pytest.raises(ValueError, match="not a mint record"):
            make_service()
