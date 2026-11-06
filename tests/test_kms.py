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


# ---------------------------------------------------------------------------
# Backend signers via fake SDK modules (no network, no real cloud account)
# ---------------------------------------------------------------------------

import base64
import sys
import types


class _FakeKMSClient:
    """Records KMS API shapes and returns KMS-shaped responses."""

    def __init__(self):
        self.sign_calls: list[dict] = []
        self.get_public_key_calls = 0

    def sign(self, **kwargs):
        self.sign_calls.append(kwargs)
        return {"Signature": b"\x02" * 64}

    def get_public_key(self, KeyId):
        self.get_public_key_calls += 1
        assert KeyId == "alias/raucle-issuing-key"
        # Minimal DER SubjectPublicKeyInfo for an Ed25519 key
        return {"PublicKey": bytes.fromhex("302a300506032b6570032100" + "ab" * 32)}


_boto3_state: dict = {}


def _fake_boto3_client(service, region_name):
    """boto3.client('kms', region_name=...) → a recording fake KMS client."""
    assert service == "kms"
    _boto3_state["region"] = region_name
    _boto3_state.setdefault("clients", []).append(_FakeKMSClient())
    return _boto3_state["clients"][-1]


def _install_boto3(monkeypatch) -> None:
    _boto3_state.clear()
    mod = types.ModuleType("boto3")
    mod.client = _fake_boto3_client
    monkeypatch.setitem(sys.modules, "boto3", mod)


def _make_fake_key(id: str, pub32: bytes):
    key = types.SimpleNamespace()
    key.id = id
    key.key = types.SimpleNamespace(x=base64.urlsafe_b64encode(pub32).decode("ascii").rstrip("="))
    return key


class _FakeKeyClient:
    def __init__(self, vault_url, credential):
        assert vault_url == "https://vault.example.net"
        self.credential = credential

    def get_key(self, name):
        assert name == "raucle-issuing-key"
        return _make_fake_key(
            "https://vault.example.net/keys/raucle-issuing-key/ver1", b"\x11" * 32
        )


class _FakeCryptographyClient:
    def __init__(self, key, credential):
        self.key = key

    def sign(self, *, algorithm, data):
        assert data == b"payload"
        return types.SimpleNamespace(signature=b"\x03" * 64)


class _FakeCryptoModule(types.ModuleType):
    class SignatureAlgorithm:
        es256k = "ES256K"


class _FakeTransit:
    def __init__(self):
        self.sign_kwargs = None
        self.read_key_calls = 0

    def sign_data(self, *, name, hash_input, algorithm):
        self.sign_kwargs = {"name": name, "hash_input": hash_input, "algorithm": algorithm}
        b64 = base64.b64encode(b"\x04" * 64).decode()
        return {"data": {"signature": f"vault:v1:{b64}"}}

    def read_key(self, *, name):
        self.read_key_calls += 1
        assert name == "raucle-transit-key"
        return {
            "data": {
                "latest_version": 2,
                "keys": {
                    "1": {"public_key": base64.b64encode(b"\x00" * 32).decode()},
                    "2": {"public_key": base64.b64encode(b"\x0f" * 32).decode()},
                },
            }
        }


class _FakeHvacClient:
    transit = None


def _install_fake_azure(monkeypatch) -> None:
    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = lambda: "cred"
    keys = types.ModuleType("azure.keyvault.keys")
    keys.KeyClient = _FakeKeyClient
    crypto = types.ModuleType("azure.keyvault.keys.crypto")
    crypto.CryptographyClient = _FakeCryptographyClient
    crypto.SignatureAlgorithm = _FakeCryptoModule.SignatureAlgorithm
    azure = types.ModuleType("azure")
    azure.__path__ = []  # package
    azure_keys = types.ModuleType("azure.keyvault")
    azure_keys.__path__ = []
    monkeypatch.setitem(sys.modules, "azure", azure)
    monkeypatch.setitem(sys.modules, "azure.identity", identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault", azure_keys)
    monkeypatch.setitem(sys.modules, "azure.keyvault.keys", keys)
    monkeypatch.setitem(sys.modules, "azure.keyvault.keys.crypto", crypto)


class TestAWSSigner:
    def test_requires_key_id_from_arg_or_env(self, monkeypatch):
        from raucle.kms import AWSSigner

        monkeypatch.delenv("RAUCLE_KMS_KEY_ID", raising=False)
        _install_boto3(monkeypatch)
        with pytest.raises(ValueError, match="key_id is required"):
            AWSSigner()

    def test_signs_via_kms_and_caches_public_pem(self, monkeypatch):
        from raucle.kms import AWSSigner

        _install_boto3(monkeypatch)
        sig = AWSSigner(key_id="alias/raucle-issuing-key", region="eu-central-1")
        assert _boto3_state["region"] == "eu-central-1"
        out = sig.sign(b"canonical bytes")
        assert out == b"\x02" * 64
        client = sig._client
        assert client.sign_calls[0]["SigningAlgorithm"] == "ED25519"
        assert client.sign_calls[0]["MessageType"] == "RAW"
        assert client.sign_calls[0]["Message"] == b"canonical bytes"

        pem = sig.public_key_pem()
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----\n")
        assert pem.endswith(b"-----END PUBLIC KEY-----\n")
        # cached: second read must not re-fetch
        assert sig.public_key_pem() == pem
        assert client.get_public_key_calls == 1

    def test_signs_with_key_id_from_environment(self, monkeypatch):
        from raucle.kms import AWSSigner

        monkeypatch.setenv("RAUCLE_KMS_KEY_ID", "alias/from-env")
        monkeypatch.delenv("AWS_REGION", raising=False)
        _install_boto3(monkeypatch)
        s = AWSSigner()
        assert s._key_id == "alias/from-env"
        assert s._region == "eu-west-1"
        assert s.sign(b"x") == b"\x02" * 64


class TestAzureSigner:
    def test_requires_boto3_like_sdk_when_missing(self, monkeypatch):
        from raucle.kms import AzureSigner

        monkeypatch.setitem(sys.modules, "azure.identity", None)  # import fails
        with pytest.raises(ImportError, match="AzureSigner requires"):
            AzureSigner(vault_url="https://vault.example.net", key_name="k")

    def test_env_required_errors(self, monkeypatch):
        from raucle.kms import AzureSigner

        _install_fake_azure(monkeypatch)
        monkeypatch.delenv("RAUCLE_KV_URL", raising=False)
        monkeypatch.delenv("RAUCLE_KV_KEY_NAME", raising=False)
        with pytest.raises(ValueError, match="vault_url is required"):
            AzureSigner(key_name="k")
        with pytest.raises(ValueError, match="key_name is required"):
            AzureSigner(vault_url="https://vault.example.net")

    def test_sign_and_pem_from_jwk_x(self, monkeypatch):
        from raucle.kms import AzureSigner

        _install_fake_azure(monkeypatch)
        s = AzureSigner(vault_url="https://vault.example.net", key_name="raucle-issuing-key")
        assert s._key_id.endswith("ver1")
        assert s._crypto.key.id.endswith("ver1")
        assert s.sign(b"payload") == b"\x03" * 64
        pem = s.public_key_pem()
        assert b"BEGIN PUBLIC KEY" in pem
        der = pem.split(b"-----BEGIN PUBLIC KEY-----\n")[1].split(b"-----END")[0]
        body = base64.b64decode(der)
        # Ed25519 SPKI: OID 1.3.101.112 present, key material is the 32 bytes
        assert b"+ep" in body
        assert b"\x11" * 32 in body


def _install_hvac(monkeypatch):
    hvac = types.ModuleType("hvac")
    transit = _FakeTransit()

    def client(url, token):
        c = types.SimpleNamespace()
        c.secrets = types.SimpleNamespace(transit=transit)
        assert url.startswith("https://vault.")
        assert token == "s-token"
        return c

    hvac.Client = client
    monkeypatch.setitem(sys.modules, "hvac", hvac)
    return transit


class TestVaultSigner:
    def test_requires_hvac_when_missing(self, monkeypatch):
        from raucle.kms import VaultSigner

        monkeypatch.setitem(sys.modules, "hvac", None)
        with pytest.raises(ImportError, match="VaultSigner requires"):
            VaultSigner(vault_url="https://vault.x", token="t", key_name="k")

    def test_env_required_errors(self, monkeypatch):
        from raucle.kms import VaultSigner

        _install_hvac(monkeypatch)
        monkeypatch.delenv("RAUCLE_VAULT_URL", raising=False)
        monkeypatch.delenv("RAUCLE_VAULT_KEY_NAME", raising=False)
        with pytest.raises(ValueError, match="vault_url is required"):
            VaultSigner(token="s-token", key_name="k")
        with pytest.raises(ValueError, match="key_name is required"):
            VaultSigner(vault_url="https://vault.x", token="s-token")

    def test_sign_strips_vault_sealed_prefix(self, monkeypatch):
        from raucle.kms import VaultSigner

        transit = _install_hvac(monkeypatch)
        s = VaultSigner(vault_url="https://vault.p", token="s-token", key_name="raucle-transit-key")
        out = s.sign(b"bytes")
        assert transit.sign_kwargs == {
            "name": "raucle-transit-key",
            "hash_input": base64.b64encode(b"bytes").decode("ascii"),
            "algorithm": "ed25519",
        }
        assert out == b"\x04" * 64

    def test_public_pem_uses_latest_version_key(self, monkeypatch):
        from raucle.kms import VaultSigner

        _install_hvac(monkeypatch)
        s = VaultSigner(vault_url="https://vault.p", token="s-token", key_name="raucle-transit-key")
        pem = s.public_key_pem()
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        body = base64.b64decode(pem.split(b"-----BEGIN PUBLIC KEY-----\n")[1].split(b"-----END")[0])
        assert b"\x0f" * 32 in body  # version 2 key material
        s._public_pem = None
        s.public_key_pem()
        # second call uses cache — transit.read_key still once? cache means one fetch
        assert s._public_pem is not None


class TestCreateSignerBackends:
    def test_aws_backend(self, monkeypatch):
        _install_boto3(monkeypatch)
        from raucle.kms import AWSSigner, create_signer

        s = create_signer(backend="aws", key_id="alias/k", region="eu-west-2")
        assert isinstance(s, AWSSigner)

    def test_azure_backend(self, monkeypatch):
        _install_fake_azure(monkeypatch)
        from raucle.kms import AzureSigner, create_signer

        s = create_signer(
            backend="azure", vault_url="https://vault.example.net", key_name="raucle-issuing-key"
        )
        assert isinstance(s, AzureSigner)

    def test_vault_backend(self, monkeypatch):
        _install_hvac(monkeypatch)
        from raucle.kms import VaultSigner, create_signer

        s = create_signer(
            backend="vault", vault_url="https://vault.p", token="s-token", key_name="k"
        )
        assert isinstance(s, VaultSigner)

    def test_raucle_signer_env_selects_aws(self, monkeypatch):
        _install_boto3(monkeypatch)
        monkeypatch.setenv("RAUCLE_SIGNER", "aws")
        monkeypatch.setenv("RAUCLE_KMS_KEY_ID", "alias/env-key")
        from raucle.kms import AWSSigner, create_signer

        assert isinstance(create_signer(), AWSSigner)

    def test_boto3_missing_raises_import_error_with_pip_hint(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "boto3", None)
        from raucle.kms import AWSSigner

        with pytest.raises(ImportError, match="pip install boto3"):
            AWSSigner(key_id="alias/k")
