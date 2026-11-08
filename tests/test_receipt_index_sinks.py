"""RED-034: a configured receipt index is fed on every sink.

Before this fix the index insert lived inside the segmented-store branch of
``_sign_and_store_receipt``. Configure ``RAUCLE_RECEIPT_INDEX_PATH`` without
``RAUCLE_RECEIPT_STORE_DIR`` and every receipt went to the flat file and never
to the index: the admin panel reported ``total 0`` while the store held the
whole chain. The chain was fine; the audit view was empty.
"""

from __future__ import annotations

import json

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.receipt_index import ReceiptIndex


def _policy(tmp_path):
    path = tmp_path / "policies.yaml"
    path.write_text(
        """
version: 1
issuer: test.bank
policies:
  - tool: pay
    agent_id: agent:bot
    ttl_seconds: 300
    constraints:
      allow:
        account: ["ACC-001"]
"""
    )
    return path


def _config(tmp_path, *, segmented: bool = False) -> GatewayConfig:
    cfg = GatewayConfig(
        policy_file=str(_policy(tmp_path)),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        receipt_index_path=str(tmp_path / "index.sqlite"),
        registry_path=str(tmp_path / "registry.jsonl"),
        signer_key_path=str(tmp_path / "signer.pem"),
        agent_credentials_file=str(tmp_path / "creds.jsonl"),
        gate_auth="off",
        signer_backend="local",
    )
    if segmented:
        cfg.receipt_store_dir = str(tmp_path / "segments")
    return cfg


class TestFlatFileSink:
    def test_receipts_reach_the_index(self, tmp_path):
        gateway = RaucleGateway(_config(tmp_path))
        gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")
        assert gateway._receipt_index is not None
        assert gateway._receipt_index.count() == 1

    def test_query_returns_the_indexed_row(self, tmp_path):
        gateway = RaucleGateway(_config(tmp_path))
        gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")
        index = gateway._receipt_index
        assert index is not None
        page = index.query(limit=10)
        rows = page["receipts"] if isinstance(page, dict) else page
        assert len(rows) == 1
        assert rows[0]["tool"] == "pay"
        assert rows[0]["agent_id"] == "agent:bot"

    def test_boot_rebuilds_the_index_from_an_existing_flat_file(self, tmp_path):
        cfg = _config(tmp_path)
        first = RaucleGateway(cfg)
        first.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")

        # Drop the projection, then start again: the chain is the truth.
        ReceiptIndex(sqlite_path=str(tmp_path / "index.sqlite")).close()
        (tmp_path / "index.sqlite").unlink()
        second = RaucleGateway(cfg)
        assert second._receipt_index is not None
        assert second._receipt_index.count() == 1

    def test_index_write_failure_never_breaks_the_chain(self, tmp_path, monkeypatch):
        gateway = RaucleGateway(_config(tmp_path))
        monkeypatch.setattr(
            gateway._receipt_index,
            "index_receipt",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        decision = gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")
        assert decision["decision"] == "allow"
        assert decision["receipt_id"]
        lines = (tmp_path / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        assert "jws" in json.loads(lines[0])


class TestSegmentedSinkStillWorks:
    def test_segmented_store_is_indexed(self, tmp_path):
        gateway = RaucleGateway(_config(tmp_path, segmented=True))
        gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")
        assert gateway._receipt_index is not None
        assert gateway._receipt_index.count() == 1


class TestRebuildHelper:
    def test_rebuild_from_flat_file_is_idempotent(self, tmp_path):
        gateway = RaucleGateway(_config(tmp_path))
        gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")
        index = ReceiptIndex(sqlite_path=str(tmp_path / "index.sqlite"))
        try:
            assert index.rebuild_from_flat_file(str(tmp_path / "receipts.jsonl")) == 1
            assert index.rebuild_from_flat_file(str(tmp_path / "receipts.jsonl")) == 1
            assert index.count() == 1
        finally:
            index.close()

    def test_malformed_lines_are_skipped(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        path.write_text('not json\n{"no": "envelope"}\n', encoding="utf-8")
        index = ReceiptIndex(sqlite_path=str(tmp_path / "index.sqlite"))
        try:
            assert index.rebuild_from_flat_file(str(path)) == 0
        finally:
            index.close()
