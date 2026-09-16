"""Tests for PQ-aware audit packs and the MCP verify_receipt tool."""

import json
import shutil
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from raucle.audit_pack import build_pack, verify_pack
from raucle.mcp_server import MCPServer
from raucle.pq import pq_available, pq_generate, pq_public_key_pem
from raucle.provenance import AgentIdentity, ProvenanceLogger
from raucle.verdicts import VerdictSigner, hash_ruleset

audit_pq = pytest.mark.skipif(not pq_available(), reason="ML-DSA-65 unavailable")


@pytest.fixture()
def tmp():
    d = Path(tempfile.mkdtemp())
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture()
def audit_key(tmp):
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    (tmp / "audit.pem").write_bytes(pem)
    return key


@pytest.fixture()
def hybrid_chain(tmp):
    ident = AgentIdentity.generate(agent_id="agent:pack")
    pq_priv, pq_pub, pq_kid = pq_generate()
    chain = tmp / "chain.jsonl"
    log = ProvenanceLogger(
        agent=ident,
        sink_path=str(chain),
        quantum_mode="strict",
        pq_private_key=pq_priv,
    )
    log.record_user_input(text="hello pack")
    log.close()
    return ident, pq_pub, pq_kid, chain


@audit_pq
class TestAuditPackPQ:
    def _build(self, tmp, hybrid_chain, audit_key, **extra):
        ident, pq_pub, pq_kid, chain = hybrid_chain
        out = tmp / f"pack-{len(list(tmp.iterdir()))}"
        index = build_pack(
            chain_path=str(chain),
            public_keys={ident.key_id: ident.public_key_pem()},
            audit_key_pem=(tmp / "audit.pem").read_bytes(),
            out_dir=str(out),
            generated_at=1758000000,
            pq_public_keys={pq_kid: pq_public_key_pem(pq_pub)},
            require_pq=True,
            **extra,
        )
        return out, index

    def test_hybrid_pack_verifies_offline(self, tmp, hybrid_chain, audit_key):
        out, index = self._build(tmp, hybrid_chain, audit_key)
        assert index["require_pq"] is True
        roles = {m["role"] for m in index["members"]}
        assert "pq-public-key" in roles
        verdict = verify_pack(out)
        assert verdict.ok
        assert verdict.chain_valid

    def test_hybrid_chain_without_pq_keys_fails_closed(self, tmp, hybrid_chain, audit_key):
        ident, pq_pub, pq_kid, chain = hybrid_chain
        out = tmp / "pack-nopq"
        build_pack(
            chain_path=str(chain),
            public_keys={ident.key_id: ident.public_key_pem()},
            audit_key_pem=(tmp / "audit.pem").read_bytes(),
            out_dir=str(out),
            generated_at=1758000000,
            require_pq=True,
        )
        verdict = verify_pack(out)
        assert not verdict.ok
        assert not verdict.chain_valid

    def test_classical_pack_still_verifies(self, tmp, audit_key):
        ident = AgentIdentity.generate(agent_id="agent:classic")
        chain = tmp / "classic.jsonl"
        log = ProvenanceLogger(agent=ident, sink_path=str(chain))
        log.record_user_input(text="classic")
        log.close()
        out = tmp / "pack-classic"
        build_pack(
            chain_path=str(chain),
            public_keys={ident.key_id: ident.public_key_pem()},
            audit_key_pem=(tmp / "audit.pem").read_bytes(),
            out_dir=str(out),
            generated_at=1758000000,
        )
        verdict = verify_pack(out)
        assert verdict.ok
        index = json.loads((out / "PACK.json").read_text())
        assert index.get("require_pq") is False

    def test_tampered_pq_member_rejected(self, tmp, hybrid_chain, audit_key):
        out, index = self._build(tmp, hybrid_chain, audit_key)
        member = next(m for m in index["members"] if m["role"] == "pq-public-key")
        target = out / member["path"]
        raw = bytearray(target.read_bytes())
        raw[-40] ^= 0x01
        target.write_bytes(bytes(raw))
        verdict = verify_pack(out)
        assert not verdict.ok
        assert not verdict.integrity_ok


class TestMCPVerifyReceipt:
    def _pub_pem(self, key):
        return (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )

    def _signer(self):
        key = Ed25519PrivateKey.generate()
        return key, VerdictSigner(key)

    def test_valid_receipt(self):
        key, signer = self._signer()
        jws = signer.issue(
            input_text="transfer 500 to ACC-9",
            verdict="allow",
            confidence=0.99,
            ruleset_hash=hash_ruleset([{"id": "r1", "pattern": "transfer"}]),
            model_version="acme-1",
        )
        res = MCPServer()._t_verify_receipt({"receipt": jws, "pubkey_pem": self._pub_pem(key)})
        assert res["valid"] is True
        assert res["payload"]["verdict"] == "allow"

    def test_tampered_receipt(self):
        key, signer = self._signer()
        jws = signer.issue(
            input_text="x",
            verdict="deny",
            confidence=1.0,
            ruleset_hash=hash_ruleset([]),
        )
        bad = jws[:-2] + ("AA" if jws[-2:] != "AA" else "BB")
        res = MCPServer()._t_verify_receipt({"receipt": bad, "pubkey_pem": self._pub_pem(key)})
        assert res["valid"] is False
        assert "error" in res

    def test_wrong_key_rejected(self):
        key, signer = self._signer()
        jws = signer.issue(
            input_text="x",
            verdict="deny",
            confidence=1.0,
            ruleset_hash=hash_ruleset([]),
        )
        other = Ed25519PrivateKey.generate()
        res = MCPServer()._t_verify_receipt({"receipt": jws, "pubkey_pem": self._pub_pem(other)})
        assert res["valid"] is False

    def test_input_binding_enforced(self):
        key, signer = self._signer()
        jws = signer.issue(
            input_text="original prompt",
            verdict="allow",
            confidence=0.9,
            ruleset_hash=hash_ruleset([]),
        )
        res = MCPServer()._t_verify_receipt(
            {
                "receipt": jws,
                "pubkey_pem": self._pub_pem(key),
                "expected_input": "different prompt",
            }
        )
        assert res["valid"] is False

    def test_missing_args_rejected(self):
        with pytest.raises(ValueError, match="receipt and pubkey_pem"):
            MCPServer()._t_verify_receipt({"receipt": "", "pubkey_pem": ""})

    def test_advertised_in_tools_list(self):
        server = MCPServer()
        listing = server._h_tools_list({})
        names = [t["name"] for t in listing["tools"]]
        assert "verify_receipt" in names
        schema = next(t for t in listing["tools"] if t["name"] == "verify_receipt")
        assert set(schema["inputSchema"]["required"]) == {"receipt", "pubkey_pem"}
