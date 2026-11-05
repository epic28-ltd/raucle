"""Tests for the tamper-evident audit chain."""

from __future__ import annotations

import json

import pytest

cryptography = pytest.importorskip("cryptography")

from raucle.audit import (
    AuditVerifier,
    Ed25519Signer,
    HashChainSink,
    _merkle_root,
)


class TestHashChainSink:
    def test_basic_append(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"verdict": "CLEAN"})
            sink.append({"verdict": "MALICIOUS"})
        # Two event records + one chain_meta header
        records = [json.loads(line) for line in path.read_text().strip().split("\n")]
        events = [r for r in records if not (r.get("checkpoint") or r.get("chain_meta"))]
        assert len(events) == 2

    def test_chain_links_records(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            r1 = sink.append({"verdict": "CLEAN"})
            r2 = sink.append({"verdict": "SUSPICIOUS"})
        assert r2["prev_hash"] == r1["hash"]
        assert r1["index"] == 0
        assert r2["index"] == 1

    def test_resume_existing_chain(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            r1 = sink.append({"verdict": "CLEAN"})

        # Reopen and append
        with HashChainSink(path) as sink:
            r2 = sink.append({"verdict": "MALICIOUS"})

        assert r2["index"] == 1
        assert r2["prev_hash"] == r1["hash"]

    def test_signed_checkpoint_emitted(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=2) as sink:
            sink.append({"v": "a"})
            sink.append({"v": "b"})  # triggers checkpoint at index 2
            sink.append({"v": "c"})

        lines = path.read_text().strip().split("\n")
        records = [json.loads(line) for line in lines]
        checkpoints = [r for r in records if r.get("checkpoint")]
        assert len(checkpoints) >= 1
        assert "merkle_root" in checkpoints[0]
        assert "signature" in checkpoints[0]


class TestAuditVerifier:
    def test_clean_chain_verifies(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=1) as sink:
            sink.append({"v": "a"})
            sink.append({"v": "b"})

        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert report.valid is True
        assert report.event_count == 2
        assert report.invalid_signatures == 0

    def test_tampered_record_detected(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"v": "original"})
            sink.append({"v": "second"})

        # Tamper with the first EVENT record (line 0 is the chain_meta
        # header; events start at line 1).
        lines = path.read_text().strip().split("\n")
        records = [json.loads(line) for line in lines]
        first_event_idx = next(
            i for i, r in enumerate(records) if not (r.get("chain_meta") or r.get("checkpoint"))
        )
        records[first_event_idx]["event"]["v"] = "modified"
        path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        report = AuditVerifier().verify_chain(path)
        assert report.valid is False
        assert report.first_invalid_index == 0

    def test_invalid_signature_detected(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=1) as sink:
            sink.append({"v": "a"})

        # Verify with a DIFFERENT key
        wrong_signer = Ed25519Signer.generate()
        report = AuditVerifier(public_key_pem=wrong_signer.public_key_pem()).verify_chain(path)
        assert report.valid is False
        assert report.invalid_signatures >= 1


class TestChainHeader:
    """Chain header (``chain_meta``) — D4 from the HOLD SCOPE review."""

    def _records(self, path):
        return [json.loads(line) for line in path.read_text().strip().split("\n")]

    def test_unsigned_chain_emits_unsigned_header(self, tmp_path, caplog):
        path = tmp_path / "chain.jsonl"
        import logging

        with caplog.at_level(logging.WARNING), HashChainSink(path) as sink:
            sink.append({"v": "a"})

        header = self._records(path)[0]
        assert header["chain_meta"] is True
        assert header["signed"] is False
        assert "key_id" not in header
        assert "signature" not in header
        assert "UNSIGNED" in caplog.text  # loud warning emitted

    def test_signed_chain_emits_signed_header(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer) as sink:
            sink.append({"v": "a"})

        header = self._records(path)[0]
        assert header["chain_meta"] is True
        assert header["signed"] is True
        assert header["key_id"] == signer.key_id()
        assert "signature" in header

    def test_resume_does_not_emit_a_second_header(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"v": "a"})
        with HashChainSink(path) as sink:
            sink.append({"v": "b"})

        records = self._records(path)
        headers = [r for r in records if r.get("chain_meta")]
        assert len(headers) == 1  # one and only one header per chain

    def test_verifier_surfaces_signed_mode_signed(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=1) as sink:
            sink.append({"v": "a"})

        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert report.signed_mode == "signed"
        assert report.chain_key_id == signer.key_id()
        assert report.valid

    def test_verifier_surfaces_signed_mode_unsigned(self, tmp_path):
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"v": "a"})

        report = AuditVerifier().verify_chain(path)
        assert report.signed_mode == "unsigned"
        assert report.chain_key_id is None

    def test_verifier_rejects_signed_checkpoint_in_unsigned_chain(self, tmp_path):
        """Splicing a signed checkpoint into an unsigned chain is a forgery
        indicator. The verifier must catch it."""
        path = tmp_path / "chain.jsonl"
        with HashChainSink(path) as sink:
            sink.append({"v": "a"})

        # Forge: produce a fake checkpoint and append it.
        signer = Ed25519Signer.generate()
        fake_ckpt = {
            "checkpoint": True,
            "index": 1,
            "merkle_root": "0" * 64,
            "key_id": signer.key_id(),
            "signature": "abcd",
            "timestamp": "2026-05-28T00:00:00Z",
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(fake_ckpt) + "\n")

        report = AuditVerifier().verify_chain(path)
        assert report.valid is False
        assert any("signed=false" in e for e in report.errors)

    def test_verifier_rejects_checkpoint_kid_mismatch(self, tmp_path):
        """A checkpoint whose key_id does not match the chain_meta header's
        key_id is treated as a splice from another chain."""
        path = tmp_path / "chain.jsonl"
        signer = Ed25519Signer.generate()
        with HashChainSink(path, signer=signer, checkpoint_every=1) as sink:
            sink.append({"v": "a"})

        # Tamper: rewrite the only checkpoint to claim a different key_id.
        records = self._records(path)
        for i, r in enumerate(records):
            if r.get("checkpoint"):
                r["key_id"] = "deadbeef00000000"
                records[i] = r
                break
        path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert report.valid is False
        assert any("chain_meta key_id" in e for e in report.errors)


class TestEd25519SignerFailLoud:
    """FIX 1.2 — Ed25519Signer fails loud on a private key that cannot
    yield a public key."""

    def test_raises_configuration_error_on_bad_private_key(self):
        from raucle.errors import ConfigurationError

        # ``object()`` has no ``public_key()`` method — Ed25519Signer's
        # try/except previously swallowed this and produced a signer
        # with key_id() == "unsigned". The fix surfaces it.
        with pytest.raises(ConfigurationError):
            Ed25519Signer(private_key=object())


class TestSinkFromEnv:
    """FIX 1.4 — sink_from_env refuses to continue when an explicit
    audit-key env var is set but unparseable."""

    def test_refuses_bad_audit_key(self, tmp_path, monkeypatch):
        from raucle.audit import sink_from_env
        from raucle.errors import ConfigurationError

        monkeypatch.setenv("RAUCLE_DETECT_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
        monkeypatch.setenv("RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM", "not a real PEM")
        with pytest.raises(ConfigurationError):
            sink_from_env()

    def test_absent_audit_path_returns_none(self, monkeypatch):
        from raucle.audit import sink_from_env

        monkeypatch.delenv("RAUCLE_DETECT_AUDIT_PATH", raising=False)
        assert sink_from_env() is None


class TestMerkleRoot:
    def test_empty_list(self):
        # Should return sha256 of empty bytes
        assert _merkle_root([]) == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_single_leaf(self):
        h = "a" * 64
        assert _merkle_root([h]) == h

    def test_two_leaves_deterministic(self):
        r1 = _merkle_root(["a" * 64, "b" * 64])
        r2 = _merkle_root(["a" * 64, "b" * 64])
        assert r1 == r2
        assert len(r1) == 64

    def test_odd_leaves_duplicates_last(self):
        # Three leaves should hash without error (last is duplicated at each odd level)
        r = _merkle_root(["a" * 64, "b" * 64, "c" * 64])
        assert len(r) == 64
