"""Raucle Gateway - enterprise AI agent governance gateway.

A Docker-deployable gateway that sits between AI agents and their tools.
Enforces capability gates, produces signed receipts, and provides an
admin panel for policy configuration, statistics, and log forwarding.

Architecture:

    AI Agent -> [Raucle Gateway] -> Tool (API, MCP, function call)
                   |
                   +-> Admin Panel (FastAPI web UI)
                   +-> Receipt Store (JSONL / S3 / Kafka)
                   +-> SIEM Forwarder (Splunk HEC / Elastic / Azure Sentinel)
                   +-> Policy Engine (YAML DSL)
                   +-> KMS Signer (AWS / Azure / Vault)

Admin panel features:
  - Policy management: create, edit, validate, deploy policies (YAML DSL)
  - Dashboard: gate decisions (allow/deny counts), latency, top tools
  - Receipt viewer: browse and verify provenance receipts
  - Log forwarding: configure SIEM destinations (Splunk, Elastic, Sentinel)
  - User management: admin, operator, auditor roles (API key auth)
  - Configuration: KMS signer, registry, compliance framework settings
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class GatewayConfig:
    """Gateway configuration loaded from environment or config file."""

    # Core
    host: str = "0.0.0.0"
    port: int = 8080
    admin_port: int = 8081
    admin_api_key: str = ""
    health_check_token: str = ""  # if set, /health requires this token

    # Config file path (for admin panel config editing)
    config_file: str = "/etc/raucle/gateway-config.yaml"

    # Signer
    signer_backend: str = "local"  # local, aws, azure, vault
    kms_key_id: str = ""
    kms_region: str = "eu-west-1"

    # Policy
    policy_file: str = "/etc/raucle/policies.yaml"
    policy_dir: str = ""  # if set, loads all *.yaml files from this directory

    # Learn mode: record unmatched tool calls so the operator can generate
    # a draft policy from observed traffic. Fail-closed: learning never
    # authorises anything; it only produces a reviewable draft.
    learn_mode: bool = False

    # Receipts
    receipt_store: str = "/data/receipts.jsonl"
    audit_chain: str = "/data/audit.jsonl"

    # Gate authentication: "off" (trusted internal network, declared
    # agent_id), "apikey" (per-agent API key, X-Api-Key header), or
    # "token" (capability token, X-Capability-Token header - the
    # Lean-proven mode). Default "off" is backwards compatible; the
    # boot log warns that declared identity is trusted.
    gate_auth: str = "off"
    agent_credentials_file: str = "/data/agent-credentials.jsonl"
    signer_key_path: str = ""  # empty = <data-dir>/gateway-signing-key.pem

    # Signed gate receipts (PR-B): every /gate decision is emitted as a
    # provenance receipt (GUARDRAIL_SCAN-shaped, x_gate extension) signed
    # by the persistent gateway identity.
    emit_receipts: bool = True
    trace_header: str = "X-Trace-Id"
    # Segmented store (B2): directory of seg-NNNNNN.jsonl files. When set,
    # receipts go through SegmentedReceiptStore instead of the flat
    # receipt_store file. Empty = legacy flat file.
    receipt_store_dir: str = ""
    receipt_segment_max_bytes: int = 67108864  # 64 MiB

    # SIEM
    siem_enabled: bool = False
    siem_backend: str = ""  # splunk, elastic, sentinel, kafka
    siem_url: str = ""
    siem_token: str = ""

    # Audit log persistence
    audit_persist: bool = False  # persist connection log to disk
    audit_log_file: str = "/data/gateway-audit.jsonl"

    # Compliance
    compliance_framework: str = "eu-ai-act"  # eu-ai-act, iso-42001, soc2

    # Registry
    registry_path: str = "/data/registry.jsonl"

    @classmethod
    def from_env(cls) -> GatewayConfig:
        """Load configuration from environment variables."""
        return cls(
            host=os.environ.get("RAUCLE_GATEWAY_HOST", "0.0.0.0"),
            port=int(os.environ.get("RAUCLE_GATEWAY_PORT", "8080")),
            admin_port=int(os.environ.get("RAUCLE_ADMIN_PORT", "8081")),
            admin_api_key=os.environ.get("RAUCLE_ADMIN_KEY", ""),
            health_check_token=os.environ.get("RAUCLE_HEALTH_KEY", ""),
            signer_backend=os.environ.get("RAUCLE_SIGNER", "local"),
            kms_key_id=os.environ.get("RAUCLE_KMS_KEY_ID", ""),
            kms_region=os.environ.get("AWS_REGION", "eu-west-1"),
            policy_file=os.environ.get("RAUCLE_POLICY_FILE", "/etc/raucle/policies.yaml"),
            policy_dir=os.environ.get("RAUCLE_POLICY_DIR", ""),
            learn_mode=os.environ.get("RAUCLE_LEARN_MODE", "").lower() in ("1", "true", "yes"),
            receipt_store=os.environ.get("RAUCLE_RECEIPT_STORE", "/data/receipts.jsonl"),
            audit_chain=os.environ.get("RAUCLE_AUDIT_CHAIN", "/data/audit.jsonl"),
            siem_enabled=os.environ.get("RAUCLE_SIEM_ENABLED", "").lower() in ("1", "true", "yes"),
            siem_backend=os.environ.get("RAUCLE_SIEM_BACKEND", ""),
            siem_url=os.environ.get("RAUCLE_SIEM_URL", ""),
            siem_token=os.environ.get("RAUCLE_SIEM_TOKEN", ""),
            audit_persist=os.environ.get("RAUCLE_AUDIT_PERSIST", "").lower()
            in ("1", "true", "yes"),
            audit_log_file=os.environ.get("RAUCLE_AUDIT_LOG", "/data/gateway-audit.jsonl"),
            compliance_framework=os.environ.get("RAUCLE_COMPLIANCE_FRAMEWORK", "eu-ai-act"),
            registry_path=os.environ.get("RAUCLE_REGISTRY_PATH", "/data/registry.jsonl"),
            gate_auth=os.environ.get("RAUCLE_GATE_AUTH", "off"),
            agent_credentials_file=os.environ.get(
                "RAUCLE_AGENT_CREDENTIALS", "/data/agent-credentials.jsonl"
            ),
            signer_key_path=os.environ.get("RAUCLE_SIGNER_KEY_PATH", ""),
            emit_receipts=os.environ.get("RAUCLE_EMIT_RECEIPTS", "1") not in ("0", "false", "no"),
            trace_header=os.environ.get("RAUCLE_TRACE_HEADER", "X-Trace-Id"),
            receipt_store_dir=os.environ.get("RAUCLE_RECEIPT_STORE_DIR", ""),
            receipt_segment_max_bytes=int(
                os.environ.get("RAUCLE_RECEIPT_SEGMENT_MAX_BYTES", "67108864")
            ),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> GatewayConfig:
        """Load from a YAML config file."""
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def to_yaml(self) -> str:
        """Serialise config to YAML for editing."""
        data = {}
        for k in self.__dataclass_fields__:
            val = getattr(self, k)
            # Skip secrets and non-serialisable fields
            if k in ("admin_api_key", "siem_token", "config_file"):
                continue
            if isinstance(val, (str, int, float, bool, type(None))):
                data[k] = val
        return yaml.dump(data, default_flow_style=False, sort_keys=False)

    def save_to_yaml(self, path: str | Path | None = None) -> None:
        """Write config to a YAML file."""
        target = Path(path or self.config_file)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_yaml(), encoding="utf-8")

    def update_from_dict(self, updates: dict[str, Any]) -> list[str]:
        """Update fields from a dict. Returns list of changed field names."""
        changed: list[str] = []
        for k, v in updates.items():
            if k in self.__dataclass_fields__ and k not in (
                "admin_api_key",
                "siem_token",
                "config_file",
            ):
                old_val = getattr(self, k)
                if old_val != v:
                    setattr(self, k, v)
                    changed.append(k)
        return changed


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


@dataclass
class GatewayStats:
    """Live gateway statistics for the admin dashboard."""

    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_requests: int = 0
    allowed: int = 0
    denied: int = 0
    escalated: int = 0
    by_tool: dict[str, dict[str, int]] = field(default_factory=dict)
    latency_us_total: int = 0
    latency_us_count: int = 0

    def record(self, tool: str, decision: str, latency_us: int) -> None:
        self.total_requests += 1
        if decision == "allow":
            self.allowed += 1
            self.by_tool.setdefault(tool, {})
            self.by_tool[tool]["allow"] = self.by_tool[tool].get("allow", 0) + 1
        elif decision == "deny":
            self.denied += 1
            self.by_tool.setdefault(tool, {})
            self.by_tool[tool]["deny"] = self.by_tool[tool].get("deny", 0) + 1
        else:
            self.escalated += 1
            self.by_tool.setdefault(tool, {})
            self.by_tool[tool][decision] = self.by_tool[tool].get(decision, 0) + 1
        self.latency_us_total += latency_us
        self.latency_us_count += 1

    def summary(self) -> dict[str, Any]:
        avg_latency = (
            self.latency_us_total / self.latency_us_count if self.latency_us_count > 0 else 0
        )
        return {
            "uptime_since": self.start_time,
            "total_requests": self.total_requests,
            "allowed": self.allowed,
            "denied": self.denied,
            "escalated": self.escalated,
            "avg_latency_us": round(avg_latency, 1),
            "tools": dict(self.by_tool),
        }


# ---------------------------------------------------------------------------
# SIEM Forwarder
# ---------------------------------------------------------------------------


class SIEMForwarder:
    """Forward gate decisions to a SIEM system.

    Supports Splunk HEC, Elasticsearch, and Azure Sentinel (Log Analytics).
    Falls back to local logging if SIEM is unreachable.
    """

    def __init__(self, config: GatewayConfig) -> None:
        self.enabled = config.siem_enabled
        self.backend = config.siem_backend
        self.url = config.siem_url
        self.token = config.siem_token
        self._buffer: list[dict[str, Any]] = []

    def forward(self, event: dict[str, Any]) -> None:
        """Send a gate decision event to the configured SIEM."""
        if not self.enabled:
            self._buffer.append(event)
            if len(self._buffer) > 100:
                self._buffer.pop(0)
            return

        try:
            if self.backend == "splunk":
                self._forward_splunk(event)
            elif self.backend == "elastic":
                self._forward_elastic(event)
            elif self.backend == "sentinel":
                self._forward_sentinel(event)
        except Exception as exc:
            logger.warning("SIEM forward failed: %s", exc)
            self._buffer.append(event)

    def _forward_splunk(self, event: dict[str, Any]) -> None:
        import requests

        headers = {"Authorization": f"Splunk {self.token}"}
        payload = {"event": event, "sourcetype": "raucle:gate"}
        requests.post(self.url, json=payload, headers=headers, timeout=5)

    def _forward_elastic(self, event: dict[str, Any]) -> None:
        import requests

        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"ApiKey {self.token}"
        requests.post(self.url, json=event, headers=headers, timeout=5)

    def _forward_sentinel(self, event: dict[str, Any]) -> None:
        """Azure Sentinel via Log Analytics Data Collector API."""
        import base64
        import hashlib
        import hmac

        import requests

        workspace_id = os.environ.get("AZURE_LOG_ANALYTICS_WORKSPACE_ID", "")
        shared_key = os.environ.get("AZURE_LOG_ANALYTICS_SHARED_KEY", "")
        if not workspace_id or not shared_key:
            return

        body = json.dumps(event)
        resource = "/api/logs"
        rfc1123date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_length = len(body)
        signed_content = f"POST\n{content_length}\napplication/json\n{rfc1123date}{resource}"
        decoded_key = base64.b64decode(shared_key)
        signature = hmac.new(decoded_key, signed_content.encode("utf-8"), hashlib.sha256).digest()
        encoded_sig = base64.b64encode(signature).decode("ascii")
        auth_header = f"SharedKey {workspace_id}:{encoded_sig}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": auth_header,
            "x-ms-date": rfc1123date,
        }
        url = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
        requests.post(url, data=body, headers=headers, timeout=5)

    def buffered_events(self) -> list[dict[str, Any]]:
        """Return events that couldn't be forwarded (for admin panel display)."""
        return list(self._buffer)


# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------


@dataclass
class GatewayUser:
    """An admin panel user."""

    api_key: str
    role: str  # admin, operator, auditor
    name: str = ""
    created_at: float = field(default_factory=lambda: time.time())
    expires_at: float | None = None  # None = never expires
    # TOTP MFA fields
    totp_secret: str = ""  # base32 secret, empty = MFA not set up
    mfa_enabled: bool = False  # True after user verifies first TOTP code

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def requires_mfa(self) -> bool:
        """True if this user must provide a TOTP code to authenticate."""
        return self.mfa_enabled and bool(self.totp_secret)


class UserManager:
    """API-key-based user management with optional TOTP MFA.

    Roles:
    - admin: full access (policies, users, config, stats, receipts)
    - operator: policies, stats, receipts (no user management)
    - auditor: stats, receipts (read-only)

    Keys can have an optional expiry timestamp (Unix epoch seconds).
    Expired keys are automatically rejected on authentication.

    MFA:
    - Call setup_mfa() to generate a TOTP secret and provisioning URI
    - User scans the QR code with their authenticator app
    - Call verify_mfa() with the first 6-digit code to confirm setup
    - After that, every API call must include X-TOTP header with a valid code
    - MFA can be disabled by an admin via disable_mfa()
    """

    def __init__(self, persist_path: str | Path | None = None) -> None:
        """User manager with optional file persistence (A3).

        When *persist_path* is given, users are loaded on construction and
        every mutation (add/remove/MFA change) is written atomically. A
        corrupt file fails closed. Without it, behaviour is exactly the
        historical in-memory manager (demo mode relies on this).
        """
        self._users: dict[str, GatewayUser] = {}
        self._persist_path = Path(persist_path) if persist_path else None
        if self._persist_path is not None:
            self._load_users()

    def _load_users(self) -> None:
        import json as _json

        assert self._persist_path is not None
        path = self._persist_path
        if not path.exists():
            return
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = _json.loads(line)
            except _json.JSONDecodeError as exc:
                raise ValueError(
                    f"user store {path} is corrupt (line {lineno}: {exc}); refusing to reset"
                ) from exc
            if not isinstance(rec, dict):
                raise ValueError(f"user store {path} is corrupt (line {lineno})")
            user = GatewayUser(
                api_key=rec["api_key"],
                role=rec["role"],
                name=rec.get("name", ""),
                expires_at=rec.get("expires_at"),
            )
            if rec.get("totp_secret"):
                user.totp_secret = rec["totp_secret"]
            self._users[user.api_key] = user

    def _persist_users(self) -> None:
        import contextlib as _contextlib
        import json as _json
        import os
        import tempfile as _tempfile

        if self._persist_path is None:
            return
        path = self._persist_path
        records = []
        for user in self._users.values():
            rec = {
                "api_key": user.api_key,
                "role": user.role,
                "name": user.name,
                "expires_at": user.expires_at,
            }
            if getattr(user, "totp_secret", None):
                rec["totp_secret"] = user.totp_secret
            records.append(rec)
        payload = "".join(_json.dumps(r) + "\n" for r in records)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = _tempfile.mkstemp(dir=str(path.parent), prefix=".users-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except Exception:
            with _contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def add_user(
        self,
        api_key: str,
        role: str,
        name: str = "",
        expires_at: float | None = None,
    ) -> GatewayUser:
        user = GatewayUser(api_key=api_key, role=role, name=name, expires_at=expires_at)
        self._users[api_key] = user
        self._persist_users()
        return user

    def get_user(self, api_key: str) -> GatewayUser | None:
        import hmac as _hmac

        for stored_key, user in self._users.items():
            if _hmac.compare_digest(stored_key, api_key):
                if user.is_expired():
                    return None
                return user
        return None

    def setup_mfa(self, api_key: str) -> dict[str, str] | None:
        """Generate a TOTP secret and provisioning URI for a user.

        Returns dict with 'secret' and 'uri' keys, or None if user not found.
        The secret is stored on the user but MFA is not enabled until
        verify_mfa() is called with a valid code.
        """
        user = self._users.get(api_key)
        if user is None:
            return None
        try:
            import pyotp
        except ImportError:
            return None
        secret = pyotp.random_base32()
        user.totp_secret = secret
        self._persist_users()
        user.mfa_enabled = False  # not enabled until verified
        totp = pyotp.TOTP(secret)
        issuer = "Raucle Gateway"
        label = user.name or api_key[:8]
        uri = totp.provisioning_uri(name=label, issuer_name=issuer)
        return {"secret": secret, "uri": uri}

    def verify_mfa(self, api_key: str, code: str) -> bool:
        """Verify a TOTP code and enable MFA for the user.

        Call after setup_mfa() once the user has scanned the QR code.
        If the code is valid, MFA is enabled for future authentication.
        """
        user = self._users.get(api_key)
        if user is None or not user.totp_secret:
            return False
        try:
            import pyotp

            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(code, valid_window=1):
                user.mfa_enabled = True
                return True
        except Exception:
            pass
        return False

    def verify_totp(self, user: GatewayUser, code: str) -> bool:
        """Verify a TOTP code for an already-enabled user. Does not enable."""
        if not user.totp_secret:
            return False
        try:
            import pyotp

            totp = pyotp.TOTP(user.totp_secret)
            return totp.verify(code, valid_window=1)
        except Exception:
            return False

    def disable_mfa(self, api_key: str) -> bool:
        """Disable MFA for a user. Returns True if successful."""
        user = self._users.get(api_key)
        if user is None:
            return False
        user.totp_secret = ""
        self._persist_users()
        user.mfa_enabled = False
        return True

    def list_users(self) -> list[GatewayUser]:
        return list(self._users.values())

    def remove_user(self, api_key: str) -> bool:
        if api_key in self._users:
            del self._users[api_key]
            self._persist_users()
            return True
        return False

    def can_access(self, api_key: str, resource: str) -> bool:
        """Check if a user can access a resource."""
        user = self._users.get(api_key)
        if user is None:
            return False
        if user.role == "admin":
            return True
        if user.role == "operator":
            return resource in ("policies", "stats", "receipts", "config")
        if user.role == "auditor":
            return resource in ("stats", "receipts")
        return False


# ---------------------------------------------------------------------------
# Gateway core
# ---------------------------------------------------------------------------


class _KmsGateIdentity:
    """AgentIdentity-compatible signing shim for KMS-backed gate identities.

    Provides agent_id/key_id/public_key_pem for statement handling and
    delegates sign() to the KMS signer. Receipts verify against the KMS
    public key offline.
    """

    def __init__(self, agent_id: str, statement: Any, signer: Any) -> None:
        self.agent_id = agent_id
        self.statement = statement
        self._signer = signer

    @property
    def key_id(self) -> str:
        return self.statement.key_id

    def public_key_pem(self) -> bytes:
        return self.statement.public_key_pem.encode("ascii")

    def sign(self, data: bytes) -> bytes:
        return self._signer.sign(data)


class RaucleGateway:
    """The gateway core: policy engine + gate + receipt store + stats.

    This is the stateful core that the FastAPI admin panel and the
    gateway proxy endpoints share.
    """

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self.stats = GatewayStats()
        self.siem = SIEMForwarder(config)
        self.users = UserManager()
        self._tokens: dict[str, Any] = {}  # tool_name -> Capability
        self._policy_rules: dict[str, list[Any]] = {}  # tool_name -> [PolicyRule]
        self._all_rules: list[Any] = []
        self._learned: dict[str, dict[str, Any]] = {}  # learn-mode observations
        self._signer = None
        self._issuer: Any = None
        self._gate: Any = None
        self._receipt_writer = None
        self._connection_log: list[dict[str, Any]] = []
        self._max_log_size = 500

        # Gate authentication (A1). "off" preserves today's behaviour
        # exactly: declared agent_id is trusted, suitable only for
        # trusted internal networks. "apikey"/"token" require a
        # credential before policy evaluation.
        self._gate_auth_mode = (config.gate_auth or "off").lower()
        if self._gate_auth_mode not in ("off", "apikey", "token"):
            raise ValueError(
                f"invalid RAUCLE_GATE_AUTH {self._gate_auth_mode!r}: expected off, apikey or token"
            )
        self._agent_creds = None
        self._caller_gate = None
        # Segmented receipt store (B2). Legacy flat file remains the default
        # for backwards compatibility; setting receipt_store_dir switches the
        # emitter to segmented storage.
        self._receipt_store = None
        if config.receipt_store_dir:
            from raucle.receipt_store import SegmentedReceiptStore

            self._receipt_store = SegmentedReceiptStore(
                base_dir=config.receipt_store_dir,
                max_segment_bytes=config.receipt_segment_max_bytes,
            )
        if self._gate_auth_mode == "off":
            logger.warning(
                "gate auth mode is 'off': declared agent_id is TRUSTED. "
                "Suitable only for trusted internal networks; set "
                "RAUCLE_GATE_AUTH=apikey or token for authenticated deployment."
            )
        elif self._gate_auth_mode == "apikey":
            from raucle.agent_credentials import AgentCredentialStore

            self._agent_creds = AgentCredentialStore(path=config.agent_credentials_file)
        elif self._gate_auth_mode == "token":
            # Caller tokens are verified against the trust registry's
            # active issuer keys. Built lazily on first use; see
            # _init_caller_gate().
            self._caller_gate = None
        else:  # unreachable: validated above
            raise ValueError(self._gate_auth_mode)

        # Bootstrap from config
        self._init_signer()
        self._init_gate_identity()
        self._load_policies()

    def _init_gate_identity(self) -> None:
        """Derive the gate's provenance identity (agent:gate) from the
        persistent signer key (PR-B).

        The identity self-signs its capability statement (OSS mode) and its
        key material IS the persistent signing key, so gate receipts verify
        across restarts. KMS signers sign via the KMS backend; the identity
        statement still pins the public key for offline verification.
        """
        import base64 as _base64
        import hashlib as _hashlib

        from cryptography.hazmat.primitives import serialization

        from raucle.provenance import (
            AgentIdentity,
            CapabilityStatement,
            _canonical_json,
        )

        if self.config.signer_backend == "local":
            priv = self._signer._private_key
            pub_pem = priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            key_id = _hashlib.sha256(pub_pem).hexdigest()[:16]
            now = int(time.time())
            stmt = CapabilityStatement(
                agent_id="agent:gate",
                key_id=key_id,
                public_key_pem=pub_pem.decode("ascii"),
                allowed_models=[],
                allowed_tools=[],
                data_classifications=[],
                issuer="raucle-gateway",
                issued_at=now,
                expires_at=None,
            )
            sig = priv.sign(_canonical_json(stmt.body()))
            stmt.signature = _base64.b64encode(sig).decode("ascii")
            self._gate_identity = AgentIdentity(
                agent_id="agent:gate", private_key=priv, statement=stmt
            )
        else:
            # KMS signers: the KMS public key backs the identity
            pub_pem_bytes = self._signer.public_key_pem()
            pub_pem = (
                pub_pem_bytes.decode("ascii") if isinstance(pub_pem_bytes, bytes) else pub_pem_bytes
            )
            key_id = _hashlib.sha256(pub_pem.encode("ascii")).hexdigest()[:16]
            now = int(time.time())
            stmt = CapabilityStatement(
                agent_id="agent:gate",
                key_id=key_id,
                public_key_pem=pub_pem,
                allowed_models=[],
                allowed_tools=[],
                data_classifications=[],
                issuer="raucle-gateway",
                issued_at=now,
                expires_at=None,
            )
            # KMS-signed statement: sign the canonical body through the signer
            body_sig = self._signer.sign(_canonical_json(stmt.body()))
            stmt.signature = _base64.b64encode(body_sig).decode("ascii")
            self._gate_identity = _KmsGateIdentity(
                agent_id="agent:gate", statement=stmt, signer=self._signer
            )

    def _signer_key_path(self) -> Path:
        """Where the local signing key persists (A2)."""
        from pathlib import Path as _P

        if self.config.signer_key_path:
            return _P(self.config.signer_key_path)
        # Default: alongside the receipt store (<data-dir>/gateway-signing-key.pem)
        base = _P(self.config.receipt_store).parent
        return base / "gateway-signing-key.pem"

    def _init_signer(self) -> None:
        """Initialise the signer (local or KMS).

        Local signers PERSIST (A2): first boot generates the key and writes
        it (0600); later boots load it, so receipts verify across restarts.
        A corrupt key file fails closed - regenerating would orphan every
        receipt signed by the previous key.
        """
        from raucle.kms import create_signer

        if self.config.signer_backend == "local":
            key_path = self._signer_key_path()
            self._signer = self._load_or_create_local_signer(key_path)
        else:
            self._signer = create_signer(
                backend=self.config.signer_backend,
                key_id=self.config.kms_key_id,
                region=self.config.kms_region,
            )

        # Create issuer from THE signer's key material (A2: local signers
        # now persist, so the issuer identity is stable across restarts -
        # tokens minted before a restart verify after it)
        from raucle.capability import CapabilityIssuer

        if self.config.signer_backend == "local":
            self._issuer = CapabilityIssuer(
                issuer="raucle-gateway", private_key=self._signer._private_key
            )
        else:
            self._issuer = CapabilityIssuer.from_signer("raucle-gateway", self._signer)

        # Create gate
        from raucle.capability import CapabilityGate

        self._gate = CapabilityGate(
            trusted_issuers={self._issuer.key_id: self._issuer.public_key_pem}
        )

    def _load_or_create_local_signer(self, key_path: Path):
        """Load the persistent Ed25519 signer, creating it on first boot.

        Fail-closed on corrupt material: a regenerated key would orphan
        every previously-signed receipt.
        """
        import os

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from raucle.audit import Ed25519Signer

        if key_path.exists():
            data = key_path.read_bytes()
            try:
                private_key = serialization.load_pem_private_key(data, password=None)
            except Exception as exc:
                logger.error(
                    "gateway signing key %s is corrupt (%s); refusing to "
                    "regenerate - restore the key file or, if the key is "
                    "lost, archive all prior receipts and delete the file "
                    "to start a fresh key",
                    key_path,
                    exc,
                )
                raise ValueError(f"corrupt gateway signing key {key_path}: {exc}") from exc
            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError(f"gateway signing key {key_path} is not an Ed25519 key")
            signer = Ed25519Signer(private_key)
            logger.info("loaded gateway signing key %s (key_id=%s)", key_path, signer.key_id())
            return signer

        key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key = Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # 0600 from creation
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
            fh.flush()
            os.fsync(fh.fileno())
        signer = Ed25519Signer(private_key)
        logger.info("generated new gateway signing key %s (key_id=%s)", key_path, signer.key_id())
        return signer

    def _emit_gate_receipt(
        self,
        *,
        decision: str,
        reason: str,
        tool: str,
        agent_id: str,
        args: dict,
        policy: str | None,
        latency_us: int,
        source: str,
        destination: str,
        trace_id: str,
    ) -> str | None:
        """Emit a signed provenance receipt for a gate decision (PR-B).

        Shape: GUARDRAIL_SCAN operation (rootable, carries verdict +
        ruleset hash - the closest spec-v1 operation to a policy decision
        point) with an ``x_gate`` extension binding the full decision
        context. Written as a minimal envelope {receipt_hash, jws} to the
        receipt store. Returns the receipt hash, or None when emission is
        disabled.
        """
        if not self.config.emit_receipts:
            return None
        from raucle.provenance import (
            _b64url_encode,
            _canonical_json,
            _sha256_hex,
        )

        payload: dict[str, Any] = {
            "iss": "raucle-gateway",
            "typ": "provenance-receipt/v1",
            "iat": int(time.time()),
            "agent_id": self._gate_identity.agent_id,
            "agent_key_id": self._gate_identity.key_id,
            "operation": "guardrail_scan",
            "parents": [],
            "taint": ["gate:observed"],
            "input_hash": _sha256_hex(_canonical_json(args)),
            "ruleset_hash": self._policy_ruleset_hash(tool),
            "guardrail_verdict": decision,
            "x_gate": {
                "decision": decision,
                "reason": reason,
                "tool": tool,
                "agent_id": agent_id,
                "source": source,
                "destination": destination,
                "policy": policy,
                "latency_us": latency_us,
                "trace_id": trace_id,
            },
        }
        header = {
            "alg": "EdDSA",
            "typ": "provenance-receipt/v1",
            "kid": self._gate_identity.key_id,
            "crit": ["raucle/v1"],
            "raucle/v1": "provenance",
        }
        signing_input = (
            _b64url_encode(_canonical_json(header)) + "." + _b64url_encode(_canonical_json(payload))
        ).encode("ascii")
        sig = self._gate_identity.sign(signing_input)
        jws = signing_input.decode("ascii") + "." + _b64url_encode(sig)
        receipt_hash = "sha256:" + _sha256_hex(jws.encode("ascii"))
        line = json.dumps({"receipt_hash": receipt_hash, "jws": jws}, ensure_ascii=False)
        if self._receipt_store is not None:
            self._receipt_store.append_line(line)
            return receipt_hash
        if self._receipt_writer is None:
            path = Path(self.config.receipt_store)
            path.parent.mkdir(parents=True, exist_ok=True)
            # Long-lived append sink (same lifetime as the process); noqa:
            # closing per write would break the chain-of-record's ordering.
            self._receipt_writer = open(  # noqa: SIM115
                path, "a", encoding="utf-8"
            )
        self._receipt_writer.write(line + "\n")
        self._receipt_writer.flush()
        return receipt_hash

    def _policy_ruleset_hash(self, tool: str) -> str:
        """Hash of the policy rule in force for *tool* (binds the decision
        to the exact policy content)."""
        import hashlib as _hl

        from raucle.provenance import _canonical_json

        rule = self._policy_rules.get(tool)
        if rule is None:
            return _hl.sha256(b"no-policy").hexdigest()
        try:
            rule_dict = rule.to_dict()
        except Exception:
            rule_dict = {"repr": repr(rule)}
        return _hl.sha256(_canonical_json(rule_dict)).hexdigest()

    @property
    def gate_identity(self):
        """The gate's provenance identity (public for verification wiring)."""
        return self._gate_identity

    def _policy_files(self) -> list[Path]:
        """Enumerate policy files from the configured file or directory."""
        if self.config.policy_dir:
            pdir = Path(self.config.policy_dir)
            if pdir.is_dir():
                return sorted(pdir.glob("*.yaml"))
            logger.warning("Policy dir %s does not exist", pdir)
            return []
        pfile = Path(self.config.policy_file)
        return [pfile] if pfile.exists() else []

    def _load_rules(self, files: list[Path]) -> list[Any]:
        """Load PolicyRules from each file, tagging each with its source file."""
        from raucle.policy import PolicyFile

        rules: list[Any] = []
        for fpath in files:
            try:
                pf = PolicyFile.load(fpath)
                for rule in pf.policies:
                    rule.source_file = str(fpath)
                rules.extend(pf.policies)
                logger.info(
                    "Loaded %d rules from %s (issuer=%s)",
                    len(pf.policies),
                    fpath.name,
                    pf.issuer,
                )
            except Exception:
                logger.exception("Failed to load %s", fpath)
        return rules

    def _index_rules(self, rules: list[Any]) -> None:
        """Index rules by tool and mint one capability token per tool."""
        self._policy_rules: dict[str, list[Any]] = {}
        self._tokens: dict[str, Any] = {}
        self._all_rules = rules

        for rule in rules:
            self._policy_rules.setdefault(rule.tool, []).append(rule)

        for rule in rules:
            if rule.tool in self._tokens:
                continue
            try:
                kwargs = rule.to_mint_kwargs()
                self._tokens[rule.tool] = self._issuer.mint(**kwargs)
            except Exception:
                logger.exception("Failed to mint token for %s", rule.tool)

    def _mint_for_rule(self, rule: Any) -> Any:
        """Mint a fresh capability token for *rule*.

        Used for first-use and for re-minting when the cached token has
        expired: policy TTLs are short by design (120-3600s), and a
        long-running gateway must keep authorising conforming calls after
        the startup token's TTL has elapsed. The re-mint is signed by the
        same issuer key, under the same policy constraints, so the
        security posture is unchanged: expiry bounds each token's window,
        not the deployment's lifetime.
        """
        return self._issuer.mint(**rule.to_mint_kwargs())

    def _load_policies(self) -> None:
        """Load policies from a file or directory of YAML files.

        If ``policy_dir`` is set, loads all ``*.yaml`` files from that
        directory. Otherwise loads the single ``policy_file``.

        Each policy rule can specify ``source`` and ``destination`` match
        patterns. When a tool call arrives, the gateway finds the first
        matching rule (by source/destination) for that tool.
        """
        files = self._policy_files()
        if not files:
            logger.info("No policy files found, running with no policies")
            self._policy_rules = {}
            self._tokens = {}
            self._all_rules = []
            return

        rules = self._load_rules(files)
        self._index_rules(rules)

        logger.info(
            "Total: %d rules across %d files, %d tools",
            len(rules),
            len(files),
            len(self._tokens),
        )

    def _deny_result(
        self,
        result: dict[str, Any],
        reason: str,
        start: float,
        *,
        siem: bool = True,
    ) -> dict[str, Any]:
        """Finalise a denied result: stats, optional SIEM, connection log."""
        result["decision"] = "deny"
        result["reason"] = reason
        result["latency_us"] = int((time.perf_counter() - start) * 1e6)
        self.stats.record(result["tool"], "deny", result["latency_us"])
        try:
            result["receipt_id"] = self._emit_gate_receipt(
                decision="deny",
                reason=reason,
                tool=result["tool"],
                agent_id=result.get("agent_id", ""),
                args=result.get("_args", {}),
                policy=result.get("policy"),
                latency_us=result["latency_us"],
                source=result.get("source", ""),
                destination=result.get("destination", ""),
                trace_id=result.get("_trace_id", ""),
            )
        except Exception:
            # Fail-closed accountability: if the receipt cannot be written,
            # the decision itself is downgraded to deny (already deny) but the
            # failure is surfaced.
            logger.exception("receipt emission failed on deny path")
        if siem:
            self.siem.forward(
                {
                    "event": "gate_decision",
                    "tool": result["tool"],
                    "decision": "deny",
                    "reason": reason,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        self._log_connection(result)
        return result

    def _find_rule(self, tool: str, source: str, destination: str) -> Any:
        """Find the first policy rule for *tool* matching source/destination."""
        for rule in self._policy_rules.get(tool, []):
            if rule.matches(source, destination):
                return rule
        return None

    def authenticate_caller(
        self,
        *,
        api_key: str | None = None,
        capability_token: dict[str, Any] | None = None,
        tool: str = "",
        args: dict[str, Any] | None = None,
        declared_agent_id: str = "",
    ) -> tuple[str | None, str]:
        """Authenticate the caller of /gate under the configured auth mode.

        Returns ``(agent_id, reason)``. On success ``agent_id`` is the
        AUTHENTICATED identity (never the declared one) and ``reason`` is
        empty. On failure ``agent_id`` is None and ``reason`` explains the
        denial (the caller must deny with 401/reason).

        Modes:
        - off: declared identity passes through unchanged (compat).
        - apikey: X-Api-Key looked up in the credential store.
        - token: X-Capability-Token verified (signature, issuer trust,
          TTL, binding to this tool/args) and the token's agent_id used.
        """
        args = args or {}
        if self._gate_auth_mode == "off":
            return declared_agent_id, ""

        if self._gate_auth_mode == "apikey":
            if not api_key:
                return None, "api key required (X-Api-Key)"
            assert self._agent_creds is not None
            agent_id = self._agent_creds.verify(api_key)
            if agent_id is None:
                return None, "invalid or revoked api key"
            return agent_id, ""

        # token mode
        if not capability_token:
            return None, "capability token required (X-Capability-Token)"
        from raucle.capability import Capability

        gate = self._ensure_caller_gate()
        try:
            token = (
                capability_token
                if isinstance(capability_token, Capability)
                else Capability.from_dict(capability_token)
            )
        except (ValueError, TypeError) as exc:
            return None, f"malformed capability token: {exc}"
        decision = gate.check(token, tool=tool, agent_id=token.agent_id, args=args)
        if not decision.allowed:
            return None, f"token rejected: {decision.reason}"
        if declared_agent_id and declared_agent_id != token.agent_id:
            return None, "agent_id/token mismatch"
        return token.agent_id, ""

    def _ensure_caller_gate(self):
        """Lazily build the caller-token verification gate.

        Issuer trust = every ACTIVE key in the trust registry, so a
        registry revocation propagates to gate auth on the next call
        (registry reloaded per call - cheap for realistic registry
        sizes, correct under revocation).
        """
        from raucle.capability import CapabilityGate
        from raucle.trust_registry import TrustRegistry

        issuers: dict[str, str] = {}
        reg_path = self.config.registry_path
        if reg_path:
            try:
                reg = TrustRegistry(path=reg_path)
                issuers = reg.as_issuer_map()  # {key_id: pem}, revoked dropped
            except Exception as exc:  # missing registry file, etc.
                logger.warning("trust registry unavailable for gate auth: %s", exc)
        if not issuers:
            # Fall back to the gateway's own issuer so a zero-registry
            # deployment can still use token mode (the gateway is the
            # only issuer in that topology). Documented in auth modes.
            issuers = {self._issuer.key_id: self._issuer.public_key_pem}
        # Rebuilt per call so registry revocations propagate immediately.
        # as_issuer_map is a fold over the registry - cheap at realistic sizes.
        return CapabilityGate(trusted_issuers=issuers)

    def check_tool_call(
        self,
        tool: str,
        args: dict[str, Any],
        agent_id: str = "",
        source: str = "",
        destination: str = "",
        trace_id: str = "",
    ) -> dict[str, Any]:
        """Gate a tool call. Returns decision dict.

        Returns:
            {
                "decision": "allow" | "deny" | "escalate",
                "reason": str,
                "tool": str,
                "agent_id": str,
                "source": str,
                "destination": str,
                "policy": str | None,
                "args_hash": str,
                "receipt_id": str | None,
                "latency_us": int,
                "timestamp": str,
            }
        """
        start = time.perf_counter()
        trace_id = trace_id or ""

        result: dict[str, Any] = {
            "_trace_id": trace_id,
            "_args": args,
            "trace_id": trace_id,
            "tool": tool,
            "decision": "deny",
            "reason": "unknown tool",
            "agent_id": agent_id,
            "source": source or agent_id or "unknown",
            "destination": destination or tool,
            "policy": None,
            "args_hash": "",
            "receipt_id": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if tool not in self._policy_rules or tool not in self._tokens:
            self._learn_observe(tool, args, agent_id, source, destination)
            return self._deny_result(result, f"no policy configured for tool '{tool}'", start)

        matched_rule = self._find_rule(tool, source, destination)
        if matched_rule is None:
            self._learn_observe(tool, args, agent_id, source, destination)
            return self._deny_result(
                result,
                f"no policy for tool '{tool}' matching "
                f"source='{source}' destination='{destination}'",
                start,
                siem=False,
            )

        token = self._tokens[tool]
        actual_agent_id = agent_id or matched_rule.agent_id
        now_ts = time.time()
        if token.expires_at <= now_ts:
            # Token TTL elapsed; re-mint under the matched rule (same issuer
            # key, same constraints) so short policy TTLs do not brick a
            # long-running gateway. Fail-closed if re-minting fails.
            try:
                token = self._mint_for_rule(matched_rule)
                self._tokens[tool] = token
            except Exception:
                logger.exception("Re-mint failed for %s", tool)
                return self._deny_result(result, "token expired and re-mint failed", start)
        result["policy"] = Path(matched_rule.source_file).name if matched_rule.source_file else tool

        decision = self._gate.check(
            token,
            tool=tool,
            agent_id=actual_agent_id,
            args=args,
        )
        result["decision"], result["reason"] = self._apply_decision(decision, matched_rule, args)

        latency_us = int((time.perf_counter() - start) * 1e6)
        self.stats.record(tool, result["decision"], latency_us)

        self.siem.forward(
            {
                "event": "gate_decision",
                "tool": tool,
                "decision": result["decision"],
                "reason": result["reason"],
                "args": args,
                "agent_id": actual_agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "latency_us": latency_us,
            }
        )

        result["latency_us"] = latency_us
        result["agent_id"] = actual_agent_id
        try:
            result["receipt_id"] = self._emit_gate_receipt(
                decision=result["decision"],
                reason=result["reason"],
                tool=tool,
                agent_id=actual_agent_id,
                args=args,
                policy=result.get("policy"),
                latency_us=latency_us,
                source=result.get("source", ""),
                destination=result.get("destination", ""),
                trace_id=result.get("_trace_id", ""),
            )
        except Exception:
            logger.exception("receipt emission failed; downgrading to deny")
            return self._deny_result(result, "receipt emission failed", start, siem=False)
        self._log_connection(result)
        return result

    # ------------------------------------------------------------------
    # Learn mode: observe unmatched calls, draft policies from traffic
    # ------------------------------------------------------------------

    def _learn_observe(
        self,
        tool: str,
        args: dict[str, Any],
        agent_id: str,
        source: str,
        destination: str,
    ) -> None:
        """Record an unmatched tool call for draft-policy generation.

        Called only on the deny path (unknown tool or no matching rule):
        the gate stays fail-closed while learning. Nothing is recorded
        when learn mode is off. Observed argument values stay in memory
        and leave the gateway only as inferred constraints (allow lists,
        numeric bounds, required fields) in the generated draft.
        """
        if not getattr(self.config, "learn_mode", False):
            return
        try:
            entry = self._learned.setdefault(
                tool,
                {
                    "agent_ids": set(),
                    "sources": set(),
                    "destinations": set(),
                    "fields": {},  # field -> {"kind":..., "values": set | bounds}
                    "calls": 0,
                },
            )
            entry["calls"] += 1
            if agent_id:
                entry["agent_ids"].add(agent_id)
            if source:
                entry["sources"].add(source)
            if destination:
                entry["destinations"].add(destination)
            for field, value in (args or {}).items():
                f = entry["fields"].setdefault(
                    field, {"kind": "string", "values": set(), "min": None, "max": None, "seen": 0}
                )
                f["seen"] += 1
                if isinstance(value, bool):
                    f["kind"] = "bool"
                    f["values"].add(value)
                elif isinstance(value, int):
                    f["kind"] = "int"
                    f["min"] = value if f["min"] is None else min(f["min"], value)
                    f["max"] = value if f["max"] is None else max(f["max"], value)
                elif isinstance(value, str):
                    f["kind"] = "string"
                    f["values"].add(value)
                else:
                    f["kind"] = "other"
        except Exception:
            logger.exception("learn observe failed")

    def _learn_clear(self) -> None:
        """Discard all learned observations."""
        self._learned.clear()

    def learn_summary(self) -> dict[str, Any]:
        """Observed-but-unauthorised traffic summary (counts only)."""
        return {
            "learn_mode": bool(getattr(self.config, "learn_mode", False)),
            "tools": {
                tool: {
                    "calls": data["calls"],
                    "agents": sorted(data["agent_ids"]),
                    "tools_seen": 1,
                }
                for tool, data in self._learned.items()
            },
        }

    def draft_policy(self) -> str:
        """Generate a draft policy YAML from learned observations.

        The draft infers, per observed tool:
          - agent_id / source / destination from the observed traffic
            (fnmatch-special characters escaped to literal matching)
          - allow lists for string fields with low cardinality (<= 6 values)
          - min/max bounds for integer fields
          - required fields observed in every call
        The draft is a PROPOSAL: the operator reviews, edits, and saves it
        through the policy editor. Learning never authorises traffic.
        """
        if not self._learned:
            return ""
        lines: list[str] = [
            "# DRAFT policy generated by raucle learn mode.",
            "#",
            "# Every rule below was inferred from OBSERVED traffic that the gate",
            "# DENIED. Review each constraint, tighten where the business context",
            "# demands it, then save + reload to activate. Learning never",
            "# authorises traffic on its own.",
            "version: 1",
            "issuer: learned.draft.review",
            "policies:",
        ]
        for tool, data in sorted(self._learned.items()):
            agents = sorted(data["agent_ids"])
            sources = sorted(data["sources"])
            dests = sorted(data["destinations"])
            agent_id = agents[0] if agents else f"agent:{tool}"
            src = sources[0] if sources else "*"
            dst = dests[0] if dests else "*"
            lines.append(f"  - tool: {tool}")
            lines.append(f"    agent_id: {agent_id}")
            lines.append("    ttl_seconds: 300")
            lines.append(f'    source: "{src}"')
            lines.append(f'    destination: "{dst}"')
            cons: list[str] = []
            allow_map: dict[str, list[str]] = {}
            max_map: dict[str, int] = {}
            min_map: dict[str, int] = {}
            required: list[str] = []
            for fname, f in sorted(data["fields"].items()):
                if f["kind"] == "string" and 0 < len(f["values"]) <= 6:
                    allow_map[fname] = sorted(f["values"])
                if f["kind"] == "int":
                    # Pad bounds 10% headroom for the observed range.
                    span = max(f["max"] - f["min"], 1)
                    max_map[fname] = f["max"] + max(1, span // 10)
                    if f["min"] is not None and f["min"] > 0:
                        min_map[fname] = max(0, f["min"] - max(1, span // 10))
                if f["seen"] >= data["calls"] and fname not in allow_map:
                    required.append(fname)
            if allow_map:
                cons.append("      allow:")
                for field, values in allow_map.items():
                    rendered = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in values)
                    cons.append(f"        {field}: [{rendered}]")
            if max_map:
                cons.append("      max:")
                for field, v in max_map.items():
                    cons.append(f"        {field}: {v}")
            if min_map:
                cons.append("      min:")
                for field, v in min_map.items():
                    cons.append(f"        {field}: {v}")
            if required:
                req = ", ".join(f'"{f}"' for f in required)
                cons.append(f"      require: [{req}]")
            if cons:
                lines.append("    constraints:")
                lines.extend(cons)
            else:
                lines.append("    constraints: {}")
            calls = data["calls"]
            lines.append(f'    description: "Draft from {calls} observed call(s); review"')
            lines.append("")
        return chr(10).join(lines)

    @staticmethod
    def _apply_decision(
        decision: Any,
        rule: Any,
        args: dict[str, Any],
    ) -> tuple[str, str]:
        """Map a gate decision + approval threshold to (decision, reason)."""
        if not decision.allowed:
            return "deny", decision.reason
        from raucle.policy import check_approval_needed

        if rule is not None and check_approval_needed(rule, args):
            return "escalate", "requires human approval"
        return "allow", decision.reason

    def get_stats(self) -> dict[str, Any]:
        return self.stats.summary()

    def _log_connection(self, result: dict[str, Any]) -> None:
        """Add a connection record to the in-memory ringbuffer and optionally disk."""
        entry = {
            "timestamp": result.get("timestamp", ""),
            "source": result.get("source", ""),
            "destination": result.get("destination", ""),
            "tool": result.get("tool", ""),
            "agent_id": result.get("agent_id", ""),
            "policy": result.get("policy"),
            "decision": result.get("decision", ""),
            "reason": result.get("reason", ""),
            "latency_us": result.get("latency_us", 0),
        }
        self._connection_log.append(entry)
        if len(self._connection_log) > self._max_log_size:
            self._connection_log.pop(0)

        # Persist to disk if enabled
        if self.config.audit_persist:
            try:
                import json as _json

                log_path = Path(self.config.audit_log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(_json.dumps(entry) + "\n")
            except Exception as exc:
                logger.warning("Failed to persist audit log: %s", exc)

    def get_connections(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent connections (most recent first)."""
        return list(reversed(self._connection_log[-limit:]))

    def reload_policies(self) -> dict[str, Any]:
        """Hot-reload policies from the config file or directory."""
        try:
            self._load_policies()
            total_rules = getattr(self, "_all_rules", [])
            return {
                "status": "ok",
                "rules": len(total_rules),
                "tools": len(self._tokens),
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}


__all__ = [
    "GatewayConfig",
    "GatewayStats",
    "SIEMForwarder",
    "GatewayUser",
    "UserManager",
    "RaucleGateway",
]
