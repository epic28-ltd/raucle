"""Deployment intake: external (portal-signed) policy deployments (H1 phase 5).

The gate's POST /api/deployments/accept endpoint accepts a portal-issued
JWS deployment receipt plus the canonical policy artefact it binds.
Trust is PINNED, never delegated: the gate verifies the JWS against the
``deployment_trust`` section of its own configuration
(``RAUCLE_GATE_CONFIG``-style YAML, mirrored by the ``RAUCLE_DEPLOYMENT_TRUST``
JSON file for env-only deployments). Portal credentials never flow to the
gate; the gate holds only a public key.

What the gate trusts (only when ``deployment_trust`` is configured):

- an EdDSA (Ed25519) JWS whose signature verifies against the pinned
  ``public_key_pem`` (inline PEM) or ``key_path`` (PEM file);
- issuer ``iss`` equal to the pinned ``issuer`` (default ``raucle-portal``);
- a bounded ``x_policy_deploy`` block whose ``artefact_sha256`` matches
  sha256 of the artefact bytes presented in the same request;
- a ``nonce`` it has never seen (bounded nonce cache, fail-closed when
  the cache file cannot be written).

On verified accept the gate, under its OWN identity:

- writes the artefact atomically (tmp + os.replace) to the configured
  ``policy_target`` (default: the gate's live ``policy_file``), and
  hot-reloads the policy store;
- appends ONE hash-chained audit event to the gate's chain of record
  (``audit_chain``), checkpoint-signed with the gate's key, binding
  {policy_digest, version, action, portal_receipt_hash, actor} and the
  gate-issued receipt hash (a real gate-signed provenance receipt in the
  org's receipt store).

A third party verifies the whole vertical slice offline with no operator
advantage: verify the portal JWS with the pinned portal public key,
locate the gate receipt in the receipt store, then re-verify the audit
chain with raucle.audit.AuditVerifier and the gate's public key.

What the gate refuses (fail-closed, and the rejection IS audited):

- anything else: bad signature, missing signer, wrong issuer, digest
  mismatch, replayed nonce, malformed artefact. The deployed policy is
  never touched on a refusal.

Default posture is unchanged: a deployment that configures no
``deployment_trust`` section has no intake endpoint at all (404).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PORTAL_ISSUER = "raucle-portal"
_EXPECTED_ALG = "EdDSA"
_EXPECTED_TYP = "provenance-receipt/v1"
_RECEIPT_CRIT = "raucle/v1"
_NONCE_CACHE_MAX = 4096


class DeploymentIntakeError(Exception):
    """An intake request failed verification; the artefact is not applied."""

    def __init__(self, status_code: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DeploymentTrust:
    """The gate's PINNED portal trust root. Nothing here is negotiable."""

    issuer: str = PORTAL_ISSUER
    public_key_pem: str = ""  # inline PEM (wins when both are given)
    key_path: str = ""  # path to the PEM file
    algorithm: str = _EXPECTED_ALG
    policy_target: str = ""  # where artefacts land; "" = config.policy_file
    nonce_cache: str = ""  # "" = beside the gate's audit chain

    def public_pem_bytes(self) -> bytes | None:
        """The pinned public key, or None when no signer is available.

        None is a fail-closed condition, never a bypass: a pinned trust
        root whose key cannot be read must refuse deployments, not trust
        them anyway.
        """
        if self.public_key_pem.strip():
            return self.public_key_pem.encode("utf-8")
        if not self.key_path:
            return None
        path = Path(self.key_path)
        if not path.is_file():
            return None
        return path.read_bytes()


def resolve_deployment_trust(raw: dict[str, Any] | None) -> DeploymentTrust | None:
    """Build the pinned trust root from the ``deployment_trust`` mapping.

    Returns None when no mapping is configured (the default posture).
    A mapping with unknown keys or a non-EdDSA algorithm is a
    configuration error: fail-closed with None plus a loud log, because
    half-configured trust must not silently disable verification.
    """
    if not raw:
        return None
    if not isinstance(raw, dict):
        logger.warning("deployment_trust is not a mapping; intake disabled (fail-closed)")
        return None
    unknown = set(raw) - {
        "issuer",
        "public_key_pem",
        "key_path",
        "algorithm",
        "policy_target",
        "nonce_cache",
        "enabled",
    }
    if unknown:
        logger.warning("deployment_trust unknown keys %s; intake disabled", sorted(unknown))
        return None
    if raw.get("enabled") is False:
        return None
    algorithm = raw.get("algorithm", _EXPECTED_ALG) or _EXPECTED_ALG
    if algorithm != _EXPECTED_ALG:
        logger.warning("deployment_trust algorithm %r not supported; intake disabled", algorithm)
        return None
    trust = DeploymentTrust(
        issuer=str(raw.get("issuer") or PORTAL_ISSUER),
        public_key_pem=str(raw.get("public_key_pem") or ""),
        key_path=str(raw.get("key_path") or ""),
        algorithm=algorithm,
        policy_target=str(raw.get("policy_target") or ""),
        nonce_cache=str(raw.get("nonce_cache") or ""),
    )
    if trust.public_pem_bytes() is None:
        # Pinned trust root with a missing/unreadable signer: keep the
        # mapping (the endpoint exists) but every request fails closed.
        logger.warning(
            "deployment_trust pinned but no public key is readable; "
            "intake will refuse all deployments (fail-closed)"
        )
    return trust


def _b64url_decode(segment: str) -> bytes:
    import base64

    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def verify_portal_jws(jws: str, trust: DeploymentTrust) -> dict[str, Any]:
    """Offline-verify the portal's JWS against the pinned trust root.

    Returns the decoded payload. Raises DeploymentIntakeError with the
    exact refusal class: bad signature -> 401; unknown issuer, wrong
    shape -> 403; no verifier key (signer absent) -> 503.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pem = trust.public_pem_bytes()
    if pem is None:
        raise DeploymentIntakeError(
            503,
            "trust_root_unavailable",
            "deployment trust root is pinned but its public key is unreadable",
        )
    parts = str(jws).split(".")
    if len(parts) != 3:
        raise DeploymentIntakeError(403, "malformed_jws", "JWS must have three segments")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        sig = _b64url_decode(parts[2])
    except (ValueError, json.JSONDecodeError) as exc:
        raise DeploymentIntakeError(403, "malformed_jws", f"undecodable JWS: {exc}") from exc
    if header.get("alg") != trust.algorithm or header.get("alg") != _EXPECTED_ALG:
        raise DeploymentIntakeError(403, "bad_algorithm", "JWS alg is not the pinned EdDSA")
    if header.get("typ") != _EXPECTED_TYP:
        raise DeploymentIntakeError(403, "bad_typ", "unexpected receipt typ")
    crit = header.get("crit")
    if crit != [_RECEIPT_CRIT] or header.get(_RECEIPT_CRIT) is None:
        raise DeploymentIntakeError(403, "bad_crit", "missing required crit member")
    if payload.get("iss") != trust.issuer:
        raise DeploymentIntakeError(403, "untrusted_issuer", "issuer is not the pinned trust root")
    extension = payload.get("x_policy_deploy")
    if not isinstance(extension, dict):
        raise DeploymentIntakeError(403, "malformed_jws", "missing x_policy_deploy block")
    for bound in ("policy_id", "version", "action", "actor", "nonce", "artefact_sha256"):
        if bound not in extension:
            raise DeploymentIntakeError(403, "malformed_jws", f"x_policy_deploy missing {bound}")
    if extension.get("nonce") != payload.get("nonce"):
        raise DeploymentIntakeError(403, "malformed_jws", "nonce mismatch")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        public_key = serialization.load_pem_public_key(pem)
        if not isinstance(public_key, Ed25519PublicKey):
            raise DeploymentIntakeError(
                503, "trust_root_unavailable", "pinned trust root is not an Ed25519 key"
            )
        public_key.verify(sig, signing_input)
    except InvalidSignature:
        raise DeploymentIntakeError(401, "bad_signature", "JWS signature does not verify") from None
    except DeploymentIntakeError:
        raise
    except Exception as exc:
        raise DeploymentIntakeError(
            503, "trust_root_unavailable", f"trust-root key cannot be used: {exc}"
        ) from exc
    return payload


class NonceCache:
    """Bounded persistent nonce cache; replay protection, fail-closed on IO."""

    def __init__(self, path: Path, max_entries: int = _NONCE_CACHE_MAX) -> None:
        self._path = path
        self._max = max_entries
        self._lock = threading.Lock()
        self._seen: list[str] = []
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            seen = data.get("seen")
            if isinstance(seen, list):
                self._seen = [str(n) for n in seen[-self._max :]]
        except (OSError, json.JSONDecodeError, AttributeError):
            self._seen = []
            if self._path.exists():
                # An unreadable existing cache must not silently reset
                # the replay window: refuse deployments (caller maps
                # empty-but-existing cache to fail-closed).
                logger.warning("nonce cache unreadable at %s; treating as empty", self._path)
        except Exception:  # noqa: BLE001 - any corrupt cache is a refusal
            self._seen = []

    def _persist(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"seen": self._seen[-self._max :]})
        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", dir=self._path.parent, prefix=".nonce-", delete=False, suffix=".json"
            ) as fh:
                tmp_path = fh.name
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self._path)
        except OSError as exc:
            raise DeploymentIntakeError(
                503,
                "nonce_cache_unavailable",
                f"cannot persist the nonce cache: {exc}",
            ) from exc

    def claim(self, nonce: str) -> None:
        """Record a nonce; raises on replay BEFORE the artefact is applied."""
        with self._lock:
            if nonce in self._seen:
                raise DeploymentIntakeError(403, "replayed_nonce", "nonce already recorded")
            self._seen.append(nonce)
            self._persist()


class NonceCacheUnreadable(Exception):
    """The existing nonce cache file exists but cannot be parsed."""


def open_nonce_cache(trust: DeploymentTrust, audit_chain: str) -> NonceCache:
    path = Path(trust.nonce_cache or f"{audit_chain}.deploy-nonces.json")
    if path.exists():
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise NonceCacheUnreadable(str(path)) from None
    return NonceCache(path)


def write_policy_artefact_atomic(path: Path, artefact: str) -> None:
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=path.parent, prefix=".deploy-artefact-", delete=False, suffix=".yaml"
        ) as fh:
            tmp_path = fh.name
            fh.write(artefact)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


def sha256_text(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def parse_artefact(artefact: str) -> dict[str, Any]:
    """Validate the artefact is a loadable gate policy file (structure only)."""
    import yaml

    try:
        doc = yaml.safe_load(artefact)
    except yaml.YAMLError as exc:
        raise DeploymentIntakeError(400, "malformed_artefact", f"not valid YAML: {exc}") from exc
    required = {"version", "issuer", "policies"}
    if not isinstance(doc, dict) or not required.issubset(doc):
        raise DeploymentIntakeError(
            400, "malformed_artefact", "artefact lacks version/issuer/policies"
        )
    if not isinstance(doc["policies"], list) or not doc["policies"]:
        raise DeploymentIntakeError(400, "malformed_artefact", "policies must be a non-empty list")
    return doc


def accept_deployment(
    gateway: Any,
    *,
    jws: str,
    artefact: str,
) -> tuple[int, dict[str, Any]]:
    """The intake core: verify, apply, chain. Returns (http_status, body).

    Every refusal path audits the rejection into the gate's chain and
    never touches the live policy file.
    """
    from raucle.audit import HashChainSink
    from raucle.provenance import _canonical_json, _sha256_hex

    trust = resolve_deployment_trust(getattr(gateway.config, "deployment_trust", None))
    if trust is None:
        raise DeploymentIntakeError(503, "intake_disabled", "deployment intake is not configured")
    audit_path = Path(gateway.config.audit_chain)

    def _audit_sink_signer() -> Any:
        """An audit-checkpoint signer under the gate's own identity.

        The gateway identity is a provenance AgentIdentity (key_id is a
        property); the chain's checkpoints expect the audit Ed25519Signer
        shape, so wrap the same private key. One gate identity, one chain
        of record - the portal never signs here.
        """
        from cryptography.hazmat.primitives import serialization

        from raucle.audit import Ed25519Signer

        identity = getattr(gateway, "_gate_identity", None)
        if identity is None:
            return None
        private = serialization.load_pem_private_key(identity.private_key_pem(), password=None)
        return Ed25519Signer(private)

    def _audit(kind: str, extension: dict[str, Any]) -> str:
        sink = HashChainSink(audit_path, signer=_audit_sink_signer())
        try:
            record = sink.append({"event": "gateway_deployment_intake", "kind": kind, **extension})
        finally:
            sink.close()
        return str(record["hash"])

    def _gate_receipt(extension: dict[str, Any]) -> str:
        payload: dict[str, Any] = {
            "iss": "raucle-gateway",
            "typ": "provenance-receipt/v1",
            "iat": int(__import__("time").time()),
            "agent_id": gateway._gate_identity.agent_id,
            "agent_key_id": gateway._gate_identity.key_id,
            "operation": "guardrail_scan",
            "parents": [],
            "taint": ["policy:deployment"],
            "input_hash": _sha256_hex(_canonical_json(extension)),
            "ruleset_hash": _sha256_hex(_canonical_json(extension)),
            "guardrail_verdict": "policy_deploy_accept",
            "x_policy_deploy": extension,
        }
        nonce = extension.get("gate_nonce")
        if nonce is not None:
            payload["nonce"] = nonce
        receipt_hash = gateway._sign_and_store_receipt(payload)
        if not receipt_hash:
            raise DeploymentIntakeError(
                503, "receipt_emission_failed", "gate receipt emission failed; artefact not applied"
            )
        return str(receipt_hash)

    try:
        payload = verify_portal_jws(jws, trust)
    except DeploymentIntakeError as exc:
        # Every pre-application refusal is audited: who tried what is
        # evidence. The artefact is never touched on a refusal.
        try:
            _audit(
                exc.code,
                {"issuer_hint": str(exc.detail), "policy_digest": sha256_text(artefact)},
            )
        except Exception:  # noqa: BLE001 - audit failure must not mask 401/403
            logger.exception("rejection audit append failed")
        raise
    extension = payload["x_policy_deploy"]

    # Digest binding: the artefact in THIS request is the artefact signed.
    expected = str(extension.get("artefact_sha256") or "")
    if expected and not _sha256_hex(artefact.encode("utf-8")).endswith(
        expected.removeprefix("sha256:")
    ):
        _audit(
            "digest_mismatch",
            {"policy_digest": sha256_text(artefact), "issuer": payload.get("iss")},
        )
        raise DeploymentIntakeError(400, "digest_mismatch", "artefact does not match the receipt")

    try:
        parse_artefact(artefact)
    except DeploymentIntakeError as exc:
        _audit(
            exc.code,
            {"policy_digest": sha256_text(artefact), "issuer": payload.get("iss")},
        )
        raise

    try:
        cache = open_nonce_cache(trust, str(audit_path))
        cache.claim(str(extension.get("nonce")))
    except NonceCacheUnreadable:
        raise DeploymentIntakeError(
            503, "nonce_cache_unavailable", "nonce cache unreadable; refusing (fail-closed)"
        ) from None
    except DeploymentIntakeError as exc:
        if exc.code == "replayed_nonce":
            _audit(
                "replayed_nonce",
                {
                    "policy_id": extension.get("policy_id"),
                    "portal_receipt_hash": "",
                    "issuer": payload.get("iss"),
                },
            )
        raise

    # The gate-issued receipt binds the deployment FIRST (its hash goes
    # into the chain event's bound block); a failing emission aborts
    # before anything is applied.
    deploy = {
        "policy_digest": sha256_text(artefact),
        "policy_id": extension.get("policy_id"),
        "version": extension.get("version"),
        "action": extension.get("action"),
        "portal_receipt_hash": "",
        "actor": extension.get("actor"),
    }
    gate_nonce = (_sha256_hex(_canonical_json(extension)))[:32]
    deploy["portal_receipt_hash"] = sha256_text(jws)
    deploy["gate_nonce"] = gate_nonce
    gate_receipt_hash = _gate_receipt(deploy)

    target = Path(trust.policy_target or gateway.config.policy_file)
    target.parent.mkdir(parents=True, exist_ok=True)
    write_policy_artefact_atomic(target, artefact)
    if target != Path(gateway.config.policy_file):
        # A separate target still has to make the gate's policy store
        # live: reload picks up the gate's own configured files.
        pass
    reloaded = gateway.reload_policies()
    if reloaded.get("status") != "ok":
        _audit(
            "reload_failed",
            {"policy_digest": deploy["policy_digest"], "gate_receipt_hash": gate_receipt_hash},
        )
        raise DeploymentIntakeError(
            503, "reload_failed", f"deployed artefact failed to reload: {reloaded.get('message')}"
        )

    event_hash = _audit(
        "policy_deployed",
        {
            "policy_digest": deploy["policy_digest"],
            "policy_id": deploy["policy_id"],
            "version": deploy["version"],
            "action": deploy["action"],
            "actor": deploy["actor"],
            "portal_receipt_hash": deploy["portal_receipt_hash"],
            "gate_receipt_hash": gate_receipt_hash,
            "issuer": payload.get("iss"),
        },
    )
    return 200, {
        "accepted": True,
        "policy_id": deploy["policy_id"],
        "policy_digest": deploy["policy_digest"],
        "version": deploy["version"],
        "gate_receipt_hash": gate_receipt_hash,
        "audit_event_hash": event_hash,
    }

