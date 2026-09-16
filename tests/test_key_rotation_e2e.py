"""Key rotation end-to-end test (PR-D Task D1).

This test IS the runbook's proof: the rotation procedure in
docs/security/key-operations.md maps 1:1 onto these steps. If the
procedure changes, this test changes with it.

The rotation contract:
1. Old receipts verify AFTER rotation (the registry keeps old public keys).
2. New mints use the new key immediately.
3. Revocation of the old key fails closed for NEW authorisation but old
   signatures still verify (revoke != erase).
"""


from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.trust_registry import TrustRegistry


class TestKeyRotationE2E:
    def test_full_rotation_procedure(self, tmp_path):
        reg_path = tmp_path / "registry.jsonl"
        reg = TrustRegistry(path=reg_path)

        # -- Boot 1: the old issuer --------------------------------------
        old_issuer = CapabilityIssuer.generate(issuer="acme.bank")
        old_pem = old_issuer.public_key_pem
        if isinstance(old_pem, bytes):
            old_pem = old_pem.decode("ascii")
        reg.publish(old_pem, issuer="acme.bank")
        old_kid = old_issuer.key_id

        # A token minted under the old key, verified under the old trust set
        token = old_issuer.mint(agent_id="agent:pay", tool="transfer", ttl_seconds=3600)
        gate_with_old = CapabilityGate(trusted_issuers=reg.as_issuer_map())
        assert gate_with_old.check(token, tool="transfer", agent_id="agent:pay").allowed

        # -- Rotation: publish new under a VERSIONED issuer identity -----
        # The registry enforces one active classical key per issuer name
        # (impersonation control): publishing a second key as "acme.bank"
        # raises. Zero-downtime rotation therefore mints the new generation
        # under a versioned identity and both verify during the window.
        new_issuer = CapabilityIssuer.generate(issuer="acme.bank/v2")
        new_pem = new_issuer.public_key_pem
        if isinstance(new_pem, bytes):
            new_pem = new_pem.decode("ascii")
        reg.publish(new_pem, issuer="acme.bank/v2")
        new_kid = new_issuer.key_id
        assert new_kid != old_kid

        # -- The dual-trust window: BOTH keys verify -----------------------
        # (this is the zero-downtime transition: agents holding either
        # generation of tokens pass)
        reg2 = TrustRegistry(path=reg_path)  # fresh fold
        window_gate = CapabilityGate(trusted_issuers=reg2.as_issuer_map())
        assert window_gate.check(token, tool="transfer", agent_id="agent:pay").allowed
        new_token = new_issuer.mint(agent_id="agent:pay", tool="transfer", ttl_seconds=3600)
        assert window_gate.check(new_token, tool="transfer", agent_id="agent:pay").allowed

        # -- Retire the old key -------------------------------------------
        reg.revoke(old_kid, reason="scheduled rotation")
        reg3 = TrustRegistry(path=reg_path)
        post_gate = CapabilityGate(trusted_issuers=reg3.as_issuer_map())

        # NEW mints under the old key fail closed: the gate has no trust for it
        fresh_old_token = old_issuer.mint(agent_id="agent:pay", tool="transfer", ttl_seconds=3600)
        assert not post_gate.check(fresh_old_token, tool="transfer", agent_id="agent:pay").allowed

        # The new generation keeps working
        assert post_gate.check(new_token, tool="transfer", agent_id="agent:pay").allowed

    def test_old_signatures_verify_after_revocation(self, tmp_path):
        """Revocation kills the TRUST, not the MATH: a receipt signed by the
        old key still verifies against its public key offline (revoke !=
        erase). This is the archival property regulators need."""
        from raucle.verdicts import VerdictSigner, VerdictVerifier

        signer = VerdictSigner.generate()
        jws = signer.issue(
            input_text="x",
            verdict="allow",
            confidence=0.9,
            ruleset_hash="abc123",
        )
        pub_pem = signer.public_key_pem()
        # "rotate": a new signer exists, the old one is "revoked"
        _new_signer = VerdictSigner.generate()
        # the OLD receipt still verifies with the old public key
        verifier = VerdictVerifier(public_key_pem=pub_pem)
        payload = verifier.verify(jws)
        assert payload.verdict == "allow"

    def test_gateway_signing_key_rotation_procedure(self, tmp_path):
        """The gateway-specific procedure: stop, rotate the PEM, start.
        Old gate receipts (chain of record) verify against the archived
        public key; new receipts use the new identity."""

        from raucle.gateway import GatewayConfig, RaucleGateway
        from raucle.provenance import ProvenanceVerifier

        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file="",
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            signer_key_path=str(tmp_path / "gw-signing.pem"),
            emit_receipts=True,
        )
        # Boot 1: generates the key, emits a receipt
        gw1 = RaucleGateway(config)
        kid1 = gw1.gate_identity.key_id
        pub1 = gw1.gate_identity.public_key_pem()
        gw1.check_tool_call("lookup", {"a": 1}, "agent:x")
        del gw1

        # Rotation: archive the old key, delete, boot generates a new one
        (tmp_path / "archived-signing.pem").write_bytes((tmp_path / "gw-signing.pem").read_bytes())
        (tmp_path / "gw-signing.pem").unlink()
        gw2 = RaucleGateway(config)
        kid2 = gw2.gate_identity.key_id
        assert kid2 != kid1
        gw2.check_tool_call("lookup", {"a": 2}, "agent:x")

        # Archival property: the old key verifies the OLD receipts offline,
        # forever. A mixed-generation chain is verified per-generation: the
        # whole chain verifies with BOTH public keys.
        pub2 = gw2.gate_identity.public_key_pem()
        verifier_both = ProvenanceVerifier(public_keys={kid1: pub1, kid2: pub2})
        report = verifier_both.verify_chain(config.receipt_store)
        assert report.valid, report.errors
        assert report.receipt_count >= 2  # both generations in one chain
        lines = (tmp_path / "receipts.jsonl").read_text().strip().splitlines()
        import base64 as _b64
        import json as _json

        kids = set()
        for line in lines:
            jws = _json.loads(line)["jws"]
            header = _json.loads(_b64.urlsafe_b64decode(jws.split(".")[0] + "=="))
            kids.add(header["kid"])
        assert kid1 in kids and kid2 in kids  # both generations present, both verifiable
