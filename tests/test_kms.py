"""Tests for the KMS/HSM remote signer abstraction."""

from unittest.mock import MagicMock

import pytest

from raucle.audit import Ed25519Signer
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.kms import KMSSigner, Signer, create_signer


class TestSignerProtocol:
    """The Signer protocol should be satisfied by both local and remote signers."""

    def test_ed25519_signer_satisfies_protocol(self):
        signer = Ed25519Signer.generate()
        assert isinstance(signer, Signer)

    def test_kms_signer_satisfies_protocol(self):
        mock_fn = MagicMock(return_value=b"\x00" * 64)
        signer = KMSSigner(
            sign_fn=mock_fn,
            public_key_pem=b"-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n",
        )
        assert isinstance(signer, Signer)


class TestKMSSigner:
    """The generic KMS signer delegates to a callable."""

    def test_sign_delegates_to_callable(self):
        expected_sig = b"\x01" * 64
        sign_fn = MagicMock(return_value=expected_sig)
        signer = KMSSigner(sign_fn=sign_fn, public_key_pem=b"fake-pem")
        result = signer.sign(b"test data")
        assert result == expected_sig
        sign_fn.assert_called_once_with(b"test data")

    def test_public_key_pem_returns_provided_pem(self):
        pem = b"-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n"
        signer = KMSSigner(sign_fn=lambda d: b"\x00" * 64, public_key_pem=pem)
        assert signer.public_key_pem() == pem


class TestCapabilityIssuerWithRemoteSigner:
    """CapabilityIssuer.from_signer creates an issuer backed by a KMS signer."""

    def test_from_signer_creates_issuer(self):
        """An issuer created from a remote signer can mint tokens."""
        # Create a local signer to get a real keypair
        local = Ed25519Signer.generate()
        pub_pem = local.public_key_pem()

        # Create a KMS signer that delegates to the local signer's sign method
        kms_signer = KMSSigner(sign_fn=local.sign, public_key_pem=pub_pem)

        # Create an issuer from the remote signer
        issuer = CapabilityIssuer.from_signer("test.bank", kms_signer)
        assert issuer.issuer == "test.bank"
        assert issuer.public_key_pem == pub_pem.decode("ascii")
        assert issuer.key_id  # should have a key_id

    def test_remote_issuer_mints_valid_tokens(self):
        """Tokens minted by a remote signer should verify in the gate."""
        local = Ed25519Signer.generate()
        pub_pem = local.public_key_pem()
        kms_signer = KMSSigner(sign_fn=local.sign, public_key_pem=pub_pem)
        issuer = CapabilityIssuer.from_signer("test.bank", kms_signer)

        # Mint a token
        token = issuer.mint(
            agent_id="agent:test",
            tool="lookup",
            constraints={"allowed_values": {"id": ["A"]}},
            ttl_seconds=60,
        )
        assert token.token_id.startswith("cap:")
        assert token.signature  # should have a signature

        # The gate should verify the token using the public key
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        decision = gate.check(token, tool="lookup", agent_id="agent:test", args={"id": "A"})
        assert decision.allowed, f"gate should allow valid token: {decision.reason}"

    def test_remote_issuer_denies_invalid_constraint(self):
        """The gate should still deny tokens with constraint violations."""
        local = Ed25519Signer.generate()
        pub_pem = local.public_key_pem()
        kms_signer = KMSSigner(sign_fn=local.sign, public_key_pem=pub_pem)
        issuer = CapabilityIssuer.from_signer("test.bank", kms_signer)

        token = issuer.mint(
            agent_id="agent:test",
            tool="lookup",
            constraints={"allowed_values": {"id": ["A"]}},
            ttl_seconds=60,
        )
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        decision = gate.check(token, tool="lookup", agent_id="agent:test", args={"id": "Z"})
        assert not decision.allowed

    def test_remote_issuer_attenuates(self):
        """Remote issuers can attenuate (narrow) capability tokens."""
        local = Ed25519Signer.generate()
        pub_pem = local.public_key_pem()
        kms_signer = KMSSigner(sign_fn=local.sign, public_key_pem=pub_pem)
        issuer = CapabilityIssuer.from_signer("test.bank", kms_signer)

        parent = issuer.mint(
            agent_id="agent:test",
            tool="lookup",
            constraints={"allowed_values": {"id": ["A", "B", "C"]}},
            ttl_seconds=60,
        )
        child = issuer.attenuate(parent, extra_constraints={"allowed_values": {"id": ["A"]}})
        assert child.token_id != parent.token_id
        assert child.parent_id == parent.token_id

        # The child should be more restrictive
        # Note: attenuation produces a parent chain - gate needs a parent_resolver
        # to verify the chain. For this test we just verify the child is minted
        # and signed correctly by the remote signer.
        assert child.signature  # should have a signature from the remote signer

        # Verify the parent still works (no chain needed for root tokens)
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        d_parent = gate.check(parent, tool="lookup", agent_id="agent:test", args={"id": "A"})
        assert d_parent.allowed

    def test_save_private_key_raises_for_remote(self):
        """save_private_key should raise for remote signers (key is in KMS)."""
        local = Ed25519Signer.generate()
        kms_signer = KMSSigner(sign_fn=local.sign, public_key_pem=local.public_key_pem())
        issuer = CapabilityIssuer.from_signer("test.bank", kms_signer)

        with pytest.raises(NotImplementedError, match="remote signer"):
            issuer.save_private_key("/tmp/should-not-exist.pem")

    def test_local_issuer_still_works(self):
        """Local issuers (without remote signer) should work as before."""
        issuer = CapabilityIssuer.generate(issuer="test.local")
        token = issuer.mint(
            agent_id="agent:test",
            tool="lookup",
            constraints={"allowed_values": {"id": ["A"]}},
            ttl_seconds=60,
        )
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        d = gate.check(token, tool="lookup", agent_id="agent:test", args={"id": "A"})
        assert d.allowed


class TestCreateSignerFactory:
    """The create_signer factory should return the right signer type."""

    def test_local_backend(self):
        signer = create_signer(backend="local")
        assert isinstance(signer, Ed25519Signer)
        assert signer.public_key_pem()

    def test_default_is_local(self, monkeypatch):
        monkeypatch.delenv("RAUCLE_SIGNER", raising=False)
        signer = create_signer()
        assert isinstance(signer, Ed25519Signer)

    def test_kms_backend(self):
        sign_fn = MagicMock(return_value=b"\x00" * 64)
        pem = b"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"
        signer = create_signer(backend="kms", sign_fn=sign_fn, public_key_pem=pem)
        assert isinstance(signer, KMSSigner)
        assert signer.sign(b"data") == b"\x00" * 64

    def test_unknown_backend_raises(self):
        with pytest.raises(ValueError, match="unknown backend"):
            create_signer(backend="invalid")


class TestEndToEndWithKMS:
    """End-to-end test: mint token with KMS signer, verify in gate, check receipt."""

    def test_full_flow_with_kms_signer(self):
        """Full capability flow using a KMS-backed signer."""
        # Set up: local key simulates the KMS-held key
        local = Ed25519Signer.generate()
        kms = KMSSigner(sign_fn=local.sign, public_key_pem=local.public_key_pem())
        issuer = CapabilityIssuer.from_signer("enterprise.bank", kms)

        # Mint a capability
        token = issuer.mint(
            agent_id="agent:production",
            tool="transfer_money",
            constraints={
                "allowed_values": {"from_account": ["ACC-001"], "to_account": ["ACC-002"]},
                "max_value": {"amount": 10000},
            },
            ttl_seconds=3600,
        )

        # Gate should verify
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})

        # Authorised call
        d1 = gate.check(
            token,
            tool="transfer_money",
            agent_id="agent:production",
            args={"from_account": "ACC-001", "to_account": "ACC-002", "amount": 5000},
        )
        assert d1.allowed

        # Over limit
        d2 = gate.check(
            token,
            tool="transfer_money",
            agent_id="agent:production",
            args={"from_account": "ACC-001", "to_account": "ACC-002", "amount": 50000},
        )
        assert not d2.allowed

        # Wrong account
        d3 = gate.check(
            token,
            tool="transfer_money",
            agent_id="agent:production",
            args={"from_account": "ACC-001", "to_account": "ACC-999", "amount": 100},
        )
        assert not d3.allowed
