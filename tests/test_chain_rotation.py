"""J1: operator-facing chain rotation + boot memory ceiling.

The 18 Nov demo incident root cause: the gateway boot maps the whole audit
chain and the receipt-store index into memory (measured at roughly twice the
on-disk bytes in RSS), so an unbounded store eventually meets a bounded box
and the process is OOM-killed at boot, repeatedly, under restart:always.
The live fix rotated the stores by hand. These tests pin the product form of
that fix (gap a): a receipted ``raucle rotate-chain`` operator action and a
boot preflight that refuses with a NAMED error, before any load, naming the
rotate command. Rotation NEVER deletes: prior links are archived intact and
stay verifiable offline; the fresh chain of record opens with a new link
describing the boundary.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from raucle.errors import BootMemoryCeilingExceeded, RotationRefusedError
from raucle.gateway import GatewayConfig, RaucleGateway


def _utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _receipt_store_config(tmp_path: Path, *, segmented: bool = True) -> GatewayConfig:
    """Env-shaped config: flat receipt path still names the data dir (the
    signing key lives beside it), the segment dir holds the chain of record."""
    return GatewayConfig(
        host="127.0.0.1",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        receipt_store_dir=str(tmp_path / "receipts") if segmented else "",
        audit_chain=str(tmp_path / "audit.jsonl"),
        audit_persist=True,
        audit_log_file=str(tmp_path / "gateway-audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
    )


def _seed_stores(config: GatewayConfig, *, events: int = 3):
    """Give every configured store some real content worth archiving.

    Returns the audit-chain signer so tests can verify the archive offline."""
    from raucle.audit import Ed25519Signer, HashChainSink

    signer = Ed25519Signer.generate()
    sink = HashChainSink(Path(config.audit_chain), signer=signer, checkpoint_every=0)
    for i in range(events):
        sink.append({"event": "gate_decision", "index": i})
    sink.close()

    Path(config.audit_log_file).parent.mkdir(parents=True, exist_ok=True)
    with open(config.audit_log_file, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"tool": "web.fetch", "decision": "allow"}) + "\n")

    envelope = json.dumps(
        {"receipt_hash": "sha256:" + "ab" * 32, "jws": "eyJhbGciOiJFZERTQSJ9.e30.AA"}
    )
    if config.receipt_store_dir:
        from raucle.receipt_store import SegmentedReceiptStore

        store = SegmentedReceiptStore(base_dir=config.receipt_store_dir)
        store.append_line(envelope)
    else:
        Path(config.receipt_store).parent.mkdir(parents=True, exist_ok=True)
        with open(config.receipt_store, "a", encoding="utf-8") as fh:
            fh.write(envelope + "\n")
    return signer


def _fresh_receipt_envelopes(config: GatewayConfig) -> list[dict]:
    """Every envelope in the FRESH receipt store, oldest first."""
    if config.receipt_store_dir:
        from raucle.receipt_store import SegmentedReceiptStore

        store = SegmentedReceiptStore(base_dir=config.receipt_store_dir)
        out = [store.find_by_hash(r["receipt_hash"]) for r in store.recent(limit=100)]
        return [rec for rec in reversed(out) if rec is not None]
    with open(config.receipt_store, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _jws_payload(jws: str) -> dict:
    part = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * ((4 - len(part) % 4) % 4)))


def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * ((4 - len(part) % 4) % 4))


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


class TestRotateChain:
    def test_archives_every_store_and_mints_boundary_receipt(self, tmp_path):
        from raucle.chain_rotation import rotate_chain

        config = _receipt_store_config(tmp_path)
        _seed_stores(config)
        today = _utc_today()

        result = rotate_chain(config, operator="craig", reason="demo memory wall")

        # Archives exist under the same directory, dated, content intact.
        archived_chain = Path(str(config.audit_chain) + f".archived-{today}")
        archived_log = Path(str(config.audit_log_file) + f".archived-{today}")
        archived_segments = Path(str(config.receipt_store_dir) + f".archived-{today}")
        assert archived_chain.is_file()
        assert archived_log.is_file()
        assert archived_segments.is_dir()
        assert (archived_segments / "seg-000000.jsonl").is_file()
        # The live paths hold FRESH stores, not the archived content: the
        # fresh audit chain opens with a signed genesis header and zero
        # events, the fresh segment holds only the rotation receipt, and
        # nothing recreates the connection log.
        assert not Path(config.audit_log_file).exists()
        live_chain = [
            json.loads(line)
            for line in Path(config.audit_chain).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert live_chain[0]["chain_meta"] is True
        assert all("event" not in rec for rec in live_chain)
        live_segment = Path(config.receipt_store_dir) / "seg-000000.jsonl"
        live_lines = [ln for ln in live_segment.read_text(encoding="utf-8").splitlines() if ln]
        assert len(live_lines) == 1
        assert archived_chain.name.startswith("audit.jsonl.archived-")

        # The fresh store's FIRST link is the rotation receipt.
        envelopes = _fresh_receipt_envelopes(config)
        assert envelopes, "fresh store must hold the rotation receipt"
        receipt = envelopes[0]
        assert receipt["receipt_hash"].startswith("sha256:")
        assert result["receipt_hash"] == receipt["receipt_hash"]

        payload = _jws_payload(receipt["jws"])
        assert payload["typ"] == "provenance-receipt/v1"
        assert payload["iss"] == "raucle-gateway"
        assert payload["operation"] == "guardrail_scan"
        # Spec v1 §4.2 required fields for a GUARDRAIL_SCAN receipt.
        for field in ("input_hash", "ruleset_hash", "guardrail_verdict"):
            assert payload.get(field), f"receipt missing required field {field}"
        # The new link parents the archived chain of record's tail receipt.
        assert payload["parents"] == ["sha256:" + "ab" * 32]

        x = payload["x_rotation"]
        assert x["operator"] == "craig"
        assert x["reason"] == "demo memory wall"
        assert x["archived_on"] == today
        assert x["archived_at"]
        kinds = {entry["kind"] for entry in x["stores"]}
        assert kinds == {"audit_chain", "audit_log", "receipt_store"}
        chain_entry = next(e for e in x["stores"] if e["kind"] == "audit_chain")
        assert chain_entry["path"] == str(config.audit_chain)
        assert chain_entry["archived_path"] == str(archived_chain)
        (digest,) = chain_entry["files"]
        assert digest["sha256"] == _sha256_file(archived_chain)
        assert digest["bytes"] == archived_chain.stat().st_size

    def test_rotation_receipt_signature_verifies_offline(self, tmp_path):
        """The receipt verifies with the gateway's own public key, offline."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        from raucle.chain_rotation import rotate_chain

        config = _receipt_store_config(tmp_path)
        _seed_stores(config)
        rotate_chain(config, operator="craig", reason="offline verify")

        receipt = _fresh_receipt_envelopes(config)[0]
        head, payload_b64, sig_b64 = receipt["jws"].split(".")
        signing_input = (head + "." + payload_b64).encode("ascii")
        key_path = Path(config.receipt_store).parent / "gateway-signing-key.pem"
        assert key_path.is_file()
        from cryptography.hazmat.primitives import serialization

        private_key = serialization.load_pem_private_key(key_path.read_bytes(), None)
        public_key = private_key.public_key()
        assert isinstance(public_key, Ed25519PublicKey)
        public_key.verify(_b64url_decode(sig_b64), signing_input)
        header = json.loads(_b64url_decode(head))
        assert header["alg"] == "EdDSA"
        assert header["typ"] == "provenance-receipt/v1"

    def test_second_rotation_same_day_refuses_idempotent_safe(self, tmp_path):
        from raucle.chain_rotation import rotate_chain

        config = _receipt_store_config(tmp_path)
        _seed_stores(config)
        today = _utc_today()
        rotate_chain(config, operator="craig", reason="first")

        with pytest.raises(RotationRefusedError, match=f"archived-{today}"):
            rotate_chain(config, operator="craig", reason="second")

        # The refusal is clean: no new archives, no second receipt.
        assert len(_fresh_receipt_envelopes(config)) == 1
        archived = [p.name for p in tmp_path.iterdir() if ".archived-" in p.name]
        assert len(archived) == 3  # chain, log, segments dir

    def test_rotate_refuses_when_nothing_to_rotate(self, tmp_path):
        from raucle.chain_rotation import rotate_chain

        config = _receipt_store_config(tmp_path)
        with pytest.raises(RotationRefusedError, match="nothing to rotate"):
            rotate_chain(config, operator="craig", reason="empty")

    def test_operator_identity_is_required_with_named_refusal(self, tmp_path, monkeypatch):
        from raucle.chain_rotation import rotate_chain

        config = _receipt_store_config(tmp_path)
        _seed_stores(config)
        monkeypatch.delenv("RAUCLE_OPERATOR", raising=False)
        with pytest.raises(RotationRefusedError, match="RAUCLE_OPERATOR"):
            rotate_chain(config, operator="", reason="who did this")

        # The env var is the documented fallback identity.
        monkeypatch.setenv("RAUCLE_OPERATOR", "env-operator")
        rotate_chain(config, operator="", reason="env identity")
        receipt = _fresh_receipt_envelopes(config)[0]
        assert _jws_payload(receipt["jws"])["x_rotation"]["operator"] == "env-operator"

    def test_audit_log_only_rotated_when_persist_is_on(self, tmp_path):
        from raucle.chain_rotation import rotate_chain

        config = _receipt_store_config(tmp_path, segmented=False)
        config.audit_persist = False
        _seed_stores(config)

        rotate_chain(config, operator="craig", reason="no connection log")

        today = _utc_today()
        # The connection log was never a configured store: untouched.
        assert Path(config.audit_log_file).is_file()
        assert not Path(str(config.audit_log_file) + f".archived-{today}").exists()
        # The flat receipt store archived instead.
        assert Path(str(config.receipt_store) + f".archived-{today}").is_file()

    def test_flat_store_rotation_receipt_is_first_link(self, tmp_path):
        from raucle.chain_rotation import rotate_chain

        config = _receipt_store_config(tmp_path, segmented=False)
        _seed_stores(config)
        rotate_chain(config, operator="craig", reason="flat store")
        envelopes = _fresh_receipt_envelopes(config)
        assert len(envelopes) == 1
        assert _jws_payload(envelopes[0]["jws"])["x_rotation"]["operator"] == "craig"

    def test_archived_audit_chain_still_verifies_offline(self, tmp_path):
        """Honest archive contract: the archived chain is untouched evidence."""
        from raucle.audit import AuditVerifier
        from raucle.chain_rotation import rotate_chain

        config = _receipt_store_config(tmp_path)
        signer = _seed_stores(config, events=3)
        rotate_chain(config, operator="craig", reason="archive then verify")

        archived = Path(str(config.audit_chain) + f".archived-{_utc_today()}")
        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(archived)
        assert report.valid, report.errors
        assert report.event_count == 3

    def test_gateway_boots_on_fresh_stores_after_rotation(self, tmp_path):
        """Boot-after-rotation contract: the same config boots clean, the
        rotation receipt is the first link, and new receipts append after it."""
        from raucle.chain_rotation import rotate_chain

        config = _receipt_store_config(tmp_path)
        _seed_stores(config)
        rotate_chain(config, operator="craig", reason="boot check")

        gateway = RaucleGateway(config)
        assert gateway._receipt_index is not None
        # The fresh index rebuilt from the fresh store: one projected receipt.
        assert gateway._receipt_index.count() == 1

        # A later gate receipt lands AFTER the rotation boundary link.
        payload = {
            "iss": "raucle-gateway",
            "typ": "provenance-receipt/v1",
            "iat": 1,
            "operation": "guardrail_scan",
            "input_hash": "x",
            "ruleset_hash": "x",
            "guardrail_verdict": "allow",
        }
        gateway._sign_and_store_receipt(payload)
        oldest_first = _fresh_receipt_envelopes(config)
        assert len(oldest_first) == 2
        boundary = _jws_payload(oldest_first[0]["jws"])
        assert boundary["x_rotation"]["kind"] == "chain_rotation"
        assert "x_rotation" not in _jws_payload(oldest_first[1]["jws"])


class TestBootMemoryPreflight:
    def test_refuses_with_named_error_before_any_load(self, tmp_path):
        from raucle.chain_rotation import boot_memory_preflight, resolve_boot_stores

        config = _receipt_store_config(tmp_path)
        _seed_stores(config)
        # 2 MB of chain on a 1 MB ceiling: the projection must refuse.
        with open(config.audit_chain, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"index": 3, "pad": "x" * 2_000_000}) + "\n")
        config.boot_mem_ceiling_mb = 1

        with pytest.raises(BootMemoryCeilingExceeded) as excinfo:
            boot_memory_preflight(config)
        # The error names the operator's escape route.
        assert "raucle rotate-chain" in str(excinfo.value)
        assert "1" in str(excinfo.value)  # the ceiling itself is stated

        # Boot through the gateway refuses BEFORE loading anything: no signing
        # key is created, so nothing was initialised past the check.
        key_path = Path(config.receipt_store).parent / "gateway-signing-key.pem"
        with pytest.raises(BootMemoryCeilingExceeded, match="raucle rotate-chain"):
            RaucleGateway(config)
        assert not key_path.exists()

        # The preflight's file set is the rotation's file set (one truth).
        kinds = {entry["kind"] for entry in resolve_boot_stores(config)}
        assert kinds == {"audit_chain", "audit_log", "receipt_store"}

    def test_passes_and_reports_the_projection(self, tmp_path):
        from raucle.chain_rotation import BOOT_MEM_RSS_MULTIPLIER, boot_memory_preflight

        config = _receipt_store_config(tmp_path)
        _seed_stores(config)
        config.boot_mem_ceiling_mb = 4096

        report = boot_memory_preflight(config)
        assert report["ceiling_mb"] == 4096
        assert report["multiplier"] == BOOT_MEM_RSS_MULTIPLIER
        assert report["projected_mb"] > 0
        on_disk = sum(
            Path(f).stat().st_size
            for entry in report["stores"]
            for f in entry["files"]
            if Path(f).exists()
        )
        assert report["projected_mb"] >= (on_disk * BOOT_MEM_RSS_MULTIPLIER) / (1024 * 1024)

    def test_default_ceiling_derived_from_detected_memory(self):
        from raucle.chain_rotation import default_boot_ceiling_mb, detected_total_memory_mb

        # Headroom: a quarter of the box, never below 2 GB.
        assert default_boot_ceiling_mb(16384) == 16384 - 4096
        assert default_boot_ceiling_mb(4096) == 4096 - 2048
        assert (detected_total_memory_mb() or 0) > 0

    def test_ceiling_env_bonds_to_config(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAUCLE_BOOT_MEM_CEILING_MB", "512")
        assert GatewayConfig.from_env().boot_mem_ceiling_mb == 512
        monkeypatch.delenv("RAUCLE_BOOT_MEM_CEILING_MB")
        assert GatewayConfig.from_env().boot_mem_ceiling_mb == 0


class TestRotateChainCli:
    def test_cli_rotates_then_refuses_repeat(self, tmp_path, monkeypatch, capsys):
        from raucle import cli

        monkeypatch.setenv("RAUCLE_SIGNER", "local")
        monkeypatch.setenv("RAUCLE_POLICY_FILE", "")
        monkeypatch.setenv("RAUCLE_RECEIPT_STORE", str(tmp_path / "receipts.jsonl"))
        monkeypatch.setenv("RAUCLE_RECEIPT_STORE_DIR", str(tmp_path / "receipts"))
        monkeypatch.setenv("RAUCLE_AUDIT_CHAIN", str(tmp_path / "audit.jsonl"))
        monkeypatch.setenv("RAUCLE_AUDIT_PERSIST", "true")
        monkeypatch.setenv("RAUCLE_AUDIT_LOG", str(tmp_path / "gateway-audit.jsonl"))
        monkeypatch.setenv("RAUCLE_REGISTRY_PATH", str(tmp_path / "registry.jsonl"))
        config = GatewayConfig.from_env()
        _seed_stores(config)

        code = cli.main(["rotate-chain", "--operator", "craig", "--reason", "demo wall"])
        assert code == 0
        out = capsys.readouterr().out
        assert f".archived-{_utc_today()}" in out
        assert "sha256:" in out  # the receipt hash is printed

        code = cli.main(["rotate-chain", "--operator", "craig", "--reason", "again"])
        assert code == 1
        assert "already exists" in capsys.readouterr().err

    def test_cli_requires_operator_identity(self, tmp_path, monkeypatch, capsys):
        from raucle import cli

        monkeypatch.setenv("RAUCLE_POLICY_FILE", "")
        monkeypatch.setenv("RAUCLE_RECEIPT_STORE", str(tmp_path / "receipts.jsonl"))
        monkeypatch.setenv("RAUCLE_AUDIT_CHAIN", str(tmp_path / "audit.jsonl"))
        monkeypatch.delenv("RAUCLE_OPERATOR", raising=False)
        code = cli.main(["rotate-chain", "--reason", "anonymous"])
        assert code == 1
        assert "RAUCLE_OPERATOR" in capsys.readouterr().err
