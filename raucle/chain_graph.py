"""Chain reconstruction graph (P1.1a / Sprint 1, LASR).

Resolves the COMPLETE authority graph for one action receipt: the
originating authority, every delegation hop, the policy version in
force at decision time, and any lease/revocation events the chain
carries - bounded, deterministic, and honest about what could not
be resolved.

TRUST STATEMENT (docs/chain-graph.md): the graph is derived ONLY
from verified receipt links. A node whose signature cannot be
verified is an explicit node state ("key_absent" / "invalid"),
never a graph failure and never silently skipped; a reference the
resolver cannot resolve is an explicit unknown/pruned record in
the output, never an inferred link.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_DEFAULT_DEPTH = 5
_DEFAULT_BREADTH = 200
_MAX_DEPTH = 20
_MAX_BREADTH = 1000
_HASH_PREFIX = "sha256:"
_DELEGATION_PREFIX = "delegation:"

# Receipt extensions the resolver treats as inline chain events.
_LEASE_KEY = "x_lease"
_REVOCATION_KEY = "x_revocation"
_POLICY_DEPLOY_KEY = "x_policy_deploy"
_GATE_KEY = "x_gate"


@dataclass
class Receipt:
    """A decoded receipt: canonical payload plus its raw JWS."""

    receipt_hash: str
    payload: dict[str, Any]
    jws: str = ""
    profile: str = "v1"

    @property
    def kid(self) -> str:
        return str(self.payload.get("agent_key_id", ""))


def _b64d(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _signing_input(jws: str) -> bytes:
    parts = jws.split(".")
    return (parts[0] + "." + parts[1]).encode("ascii")


def _ed25519_verify(jws: str, key: Any) -> bool:
    """Verify the Ed25519 component of a receipt JWS. Never raises."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    try:
        if isinstance(key, str):
            key = key.encode("ascii")
        if not isinstance(key, Ed25519PublicKey):
            key = serialization.load_pem_public_key(key)
        key.verify(_b64d(jws.split(".")[2]), _signing_input(jws))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    except Exception:
        # Decode errors fail closed with the same explicit state.
        return False


class ReceiptCorpus:
    """A snapshot of receipt-store records, keyed by receipt hash."""

    def __init__(self, records: Iterable[dict[str, Any]]) -> None:
        self._records: dict[str, dict[str, Any]] = {}
        self._decoded: dict[str, Receipt] = {}
        for record in records:
            rid = str(record.get("receipt_hash", ""))
            if not rid:
                continue
            self._records[rid] = dict(record)
            receipt = _decode_receipt(record)
            if receipt is not None:
                parents = receipt.payload.get("parents")
                if isinstance(parents, list):
                    receipt.payload["parents"] = sorted(str(p) for p in parents)
                self._decoded[rid] = receipt

    def decoded(self, receipt_hash: str) -> Receipt | None:
        return self._decoded.get(receipt_hash)

    def __len__(self) -> int:
        return len(self._records)

    def signatures(self, receipt: Receipt, public_keys: dict[str, Any]) -> dict[str, Any]:
        """Explicit node state: verified / key_absent / invalid / malformed.

        Verification is per-profile: v1 (3-segment) and pq1 hybrid
        (4-segment; here the Ed25519 component is checked, with the
        profile recorded so assurance knows the ML-DSA half belongs to
        the offline hybrid verifier).
        """
        if len(receipt.jws.split(".")) not in (3, 4):
            return {"status": "malformed", "key_id": receipt.kid}
        key = public_keys.get(receipt.kid)
        if key is None:
            return {"status": "key_absent", "key_id": receipt.kid}
        if _ed25519_verify(receipt.jws, key):
            return {"status": "verified", "key_id": receipt.kid}
        return {"status": "invalid", "key_id": receipt.kid}


def _decode_receipt(record: dict[str, Any]) -> Receipt | None:
    """Decode a store record; None (never raise) when undecodable."""
    jws = str(record.get("jws", ""))
    parts = jws.split(".")
    if len(parts) not in (3, 4):
        return None
    try:
        header = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict) or not isinstance(header, dict):
        return None
    profile = "pq1" if len(parts) == 4 else "v1"
    return Receipt(
        receipt_hash=str(record.get("receipt_hash", "")),
        payload=payload,
        jws=jws,
        profile=profile,
    )


def load_receipt_records(path: str | Path) -> list[dict[str, Any]]:
    """Load ``{receipt_hash, jws}`` records from a receipt chain file."""
    out: list[dict[str, Any]] = []
    fp = Path(path)
    if not fp.exists():
        return out
    for line in fp.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("receipt_hash") and record.get("jws"):
            out.append(record)
    return out


def load_audit_events(path: str | Path) -> list[dict[str, Any]]:
    """Load wrapped audit records (``{"event": {...}}``) from a chain file."""
    out: list[dict[str, Any]] = []
    fp = Path(path)
    if not fp.exists():
        return out
    for line in fp.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and isinstance(record.get("event"), dict):
            out.append(record)
    return out


def _normalise_public_keys(keys: dict[str, Any] | None) -> dict[str, str]:
    """PEM values normalised to str (canonical JSON-safe mapping)."""
    return {
        str(kid): key.decode("utf-8") if isinstance(key, bytes) else str(key)
        for kid, key in (keys or {}).items()
    }


def _inline_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Lease/revocation/deployment events the receipt carries inline.

    Every event stamps the receipt's own ``iat`` - the recorded event
    time - so an assurance consumer reasons about state AT the
    decision, exactly as the receipt binds it. Nothing inferred.
    """
    events: list[dict[str, Any]] = []
    iat = payload.get("iat")
    lease = payload.get(_LEASE_KEY)
    if isinstance(lease, dict):
        action = str(lease.get("action") or "grant")
        events.append(
            {
                "type": "lease_" + ("redeemed" if action == "redeemed" else "grant"),
                "lease_id": str(lease.get("lease_id", "")),
                "iat": iat,
                "ttl": lease.get("ttl"),
                "scopes": lease.get("scopes") or {},
                "source": _LEASE_KEY,
            }
        )
    revocation = payload.get(_REVOCATION_KEY)
    if isinstance(revocation, dict):
        events.append(
            {
                "type": "revocation",
                "revoked_ids": [str(r) for r in (revocation.get("revoked_ids") or [])],
                "reason": revocation.get("reason", ""),
                "iat": iat,
                "source": _REVOCATION_KEY,
            }
        )
    deploy = payload.get(_POLICY_DEPLOY_KEY)
    if isinstance(deploy, dict):
        events.append(
            {
                "type": "policy_deploy",
                "policy_digest": str(deploy.get("policy_digest", "")),
                "policy_id": deploy.get("policy_id"),
                "version": deploy.get("version"),
                "action": deploy.get("action"),
                "iat": iat,
                "source": _POLICY_DEPLOY_KEY,
            }
        )
    return events


def _matching_deployments(
    payload: dict[str, Any],
    receipt_hash: str,
    audit_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """``policy_deployed`` audit events bound to this receipt BY DIGEST only.

    Two digest bindings exist (both recorded, both verified against the
    chain content, never by name coincidence):
    - the deployment gate receipt carries ``x_policy_deploy.policy_digest``
      - the hash chain event carries ``gate_receipt_hash`` naming it.
    """
    deploy = payload.get(_POLICY_DEPLOY_KEY)
    own_digest = str(deploy.get("policy_digest", "")) if isinstance(deploy, dict) else ""
    out: list[dict[str, Any]] = []
    for record in audit_records:
        event = record.get("event")
        if not isinstance(event, dict):
            continue
        if str(event.get("kind", "")) != "policy_deployed":
            continue
        digest = str(event.get("policy_digest", ""))
        gate_hash = str(event.get("gate_receipt_hash", ""))
        if not (digest and own_digest and digest == own_digest) and not (
            gate_hash and gate_hash == receipt_hash
        ):
            continue
        out.append(
            {
                "policy_digest": digest,
                "policy_id": event.get("policy_id"),
                "version": event.get("version"),
                "action": event.get("action"),
                "event_timestamp": record.get("timestamp"),
                "receipt_hash": record.get("hash", ""),
            }
        )
    out.sort(
        key=lambda d: (
            str(d["policy_digest"]),
            str(d["policy_id"]),
            str(d["version"]),
            str(d["event_timestamp"]),
            str(d["receipt_hash"]),
        )
    )
    return out


def _receipt_policy_node(
    payload: dict[str, Any],
    receipt_hash: str,
    audit_records: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """The policy node: the policy version in force at decision time.

    Binding states:

    - ``deployment_bound``: a ``policy_deployed`` chain event matched BY
      DIGEST (phase-5 intake) - the exact deployed artefact version.
    - ``receipt_rule_digest_only``: the receipt binds the rule content
      hash (``ruleset_hash``) + policy ref but no deployment event.
    - ``unbound``: no digest, no ref - stated, never inferred.
    """
    x_gate = payload.get(_GATE_KEY) if isinstance(payload.get(_GATE_KEY), dict) else {}
    deployments = _matching_deployments(payload, receipt_hash, audit_records)
    ruleset_hash = str(payload.get("ruleset_hash", ""))
    policy_ref = str(x_gate.get("policy", "") or "")
    rule_id = str(x_gate.get("rule_id", "") or "")
    if deployments:
        state = "deployment_bound"
    elif ruleset_hash:
        state = "receipt_rule_digest_only"
    else:
        state = "unbound"
    if not (ruleset_hash or policy_ref or rule_id or deployments):
        return None
    return {
        "id": "policy:" + receipt_hash,
        "kind": "policy",
        "policy_ref": policy_ref,
        "rule_id": rule_id,
        "ruleset_hash": ruleset_hash,
        "binding_state": state,
        "iat": payload.get("iat"),
        "deployments": deployments,
    }


def _receipt_node(
    receipt: Receipt,
    status: dict[str, Any],
) -> dict[str, Any]:
    payload = receipt.payload
    x_gate = payload.get(_GATE_KEY) if isinstance(payload.get(_GATE_KEY), dict) else None
    node: dict[str, Any] = {
        "id": receipt.receipt_hash,
        "kind": "receipt",
        "operation": str(payload.get("operation", "")),
        "agent_id": str(payload.get("agent_id", "")),
        "key_id": receipt.kid,
        "iat": payload.get("iat"),
        "profile": receipt.profile,
        "signature": status,
        "guardrail_verdict": str(payload.get("guardrail_verdict", "")),
        "tool": str(payload.get("tool", "")),
        "parents": [str(p) for p in (payload.get("parents") or [])],
        "ruleset_hash": str(payload.get("ruleset_hash", "")),
        "events": _inline_events(payload),
    }
    if x_gate is not None:
        node["gate"] = {
            "decision": x_gate.get("decision"),
            "reason": x_gate.get("reason"),
            "tool": x_gate.get("tool"),
            "agent_id": x_gate.get("agent_id"),
            "policy": x_gate.get("policy"),
            "rule_id": x_gate.get("rule_id") or "",
            "trace_id": x_gate.get("trace_id") or "",
        }
        auth = x_gate.get("authorization")
        if isinstance(auth, dict):
            node["delegation"] = {
                "token_id": str(auth.get("capability_id", "")),
                "parent_token_id": (
                    str(auth.get("parent_id")) if auth.get("parent_id") is not None else None
                ),
                "issuer": str(auth.get("issuer", "")),
                "attenuated": bool(auth.get("attenuated")),
                "chain_digest": str(auth.get("chain_digest", "")),
            }
    return node


def _delegation_node(rec: dict[str, Any]) -> dict[str, Any]:
    """One capability-token delegation hop from a ledger record."""
    cap = rec.get("capability")
    cap = cap if isinstance(cap, dict) else {}
    exp = cap.get("exp")
    return {
        "id": _DELEGATION_PREFIX + str(cap.get("token_id", "")),
        "kind": "delegation",
        "token_id": str(cap.get("token_id", "")),
        "issuer": str(cap.get("issuer", "")),
        "key_id": str(cap.get("key_id", "")),
        "delegated_to": str(rec.get("delegated_to_agent", "")),
        "parent_token_id": (
            str(cap.get("parent_id")) if cap.get("parent_id") is not None else None
        ),
        "expires_at": exp,
        "iat": cap.get("iat"),
        "record_hash": str(rec.get("record_hash", "")),
        "constraints": cap.get("constraints") or {},
    }


def _delegation_record_key(rec: dict[str, Any]) -> str:
    cap = rec.get("capability")
    cap = cap if isinstance(cap, dict) else {}
    return str(cap.get("token_id", ""))


class _GraphState:
    """Mutable working state for one chain-graph resolution."""

    def __init__(self, breadth: int) -> None:
        self.breadth = breadth
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []
        self.unknown: list[dict[str, Any]] = []
        self.pruned: list[dict[str, Any]] = []
        self.visited: set[str] = set()
        self.truncated = False

    def add_node(self, node: dict[str, Any]) -> bool:
        node_id = str(node["id"])
        if node_id in self.visited:
            return True
        if len(self.nodes) >= self.breadth:
            self.pruned.append(
                {"kind": node["kind"], "reference": node_id, "reason": "breadth_limit_exceeded"}
            )
            self.truncated = True
            return False
        self.visited.add(node_id)
        self.nodes[node_id] = node
        return True

    def add_edge(self, kind: str, src: str, dst: str, found: bool | None = None) -> None:
        edge: dict[str, Any] = {"kind": kind, "from": src, "to": dst}
        if found is not None:
            edge["found"] = found
        self.edges.append(edge)

    def prune(self, kind: str, reference: str, reason: str) -> None:
        self.truncated = True
        self.pruned.append({"kind": kind, "reference": reference, "reason": reason})

    def unknown_ref(self, kind: str, reference: str, reason: str = "not_found") -> None:
        self.unknown.append({"kind": kind, "reference": reference, "reason": reason})


def _walk_delegation(
    state: _GraphState,
    rec: dict[str, Any],
    src: str,
    hop: int,
    depth: int,
    delegations: dict[str, dict[str, Any]],
) -> None:
    """Chain of ``parent_id`` hops, bounded: unresolved = unknown."""
    kind = "delegation"  # receipt -> its capability; hops -> parent
    hops = depth - hop  # delegation hops share the receipt depth budget
    current: dict[str, Any] | None = rec
    while current is not None:
        node = _delegation_node(current)
        token_id = node["token_id"]
        edge_dst = _DELEGATION_PREFIX + token_id
        if hops <= 0 and token_id not in state.visited:
            state.prune("delegation", token_id, "depth_limit_exceeded")
            state.add_edge(kind, src, edge_dst, found=True)
            return
        if not state.add_node(node):
            state.add_edge(kind, src, edge_dst, found=True)
            return
        if src != node["id"]:
            state.add_edge(kind, src, edge_dst, found=True)
        parent_id = node["parent_token_id"]
        if parent_id is None:
            return
        parent_rec = delegations.get(parent_id)
        if parent_rec is None:
            state.unknown_ref("delegation", parent_id)
            state.add_edge(
                "delegation_parent", node["id"], _DELEGATION_PREFIX + parent_id, found=False
            )
            return
        src, kind, current, hops = node["id"], "delegation_parent", parent_rec, hops - 1


def _bind_policy_deployments(state: _GraphState, current: str, policy_node: dict[str, Any]) -> None:
    """Bind a receipt to its policy-digest-matched policy node and audits."""
    state.add_edge("policy_binding", current, policy_node["id"], found=True)
    state.add_node(policy_node)
    for dep in policy_node["deployments"]:
        audit_node = {
            "id": "audit:" + str(dep["receipt_hash"]),
            "kind": "audit_event",
            "type": "policy_deployed",
            "policy_digest": dep["policy_digest"],
            "policy_id": dep["policy_id"],
            "version": dep["version"],
            "event_timestamp": dep["event_timestamp"],
        }
        state.add_node(audit_node)
        state.add_edge("deployment", current, audit_node["id"], found=True)


def _process_receipt_node(
    state: _GraphState,
    corpus: ReceiptCorpus,
    current: str,
    hop: int,
    depth: int,
    keys: dict[str, Any],
    delegations: dict[str, dict[str, Any]],
    audits: list[dict[str, Any]],
) -> list[str]:
    """Resolve one receipt node; return the parent hashes still to visit."""
    receipt = corpus.decoded(current)
    if receipt is None:
        state.unknown_ref("receipt", current)
        return []
    node = _receipt_node(receipt, corpus.signatures(receipt, keys))
    if not state.add_node(node):
        return []
    # Chain links (parent-receipt hashes): the edge is recorded for
    # every cited link; its `found` state is settled after the walk -
    # an unresolvable link is a `not_found` unknown, never inferred.
    for parent in node["parents"]:
        state.add_edge("parent", current, parent)
    auth = node.get("delegation")
    if auth and auth.get("token_id"):
        rec = delegations.get(auth["token_id"])
        if rec is None:
            state.unknown_ref("delegation", str(auth["token_id"]))
            state.add_edge(
                "delegation", current, _DELEGATION_PREFIX + auth["token_id"], found=False
            )
        else:
            _walk_delegation(state, rec, current, hop, depth, delegations)
    policy_node = _receipt_policy_node(receipt.payload, receipt.receipt_hash, audits)
    if policy_node is not None:
        _bind_policy_deployments(state, current, policy_node)
    return list(node["parents"])


def resolve_chain_graph(
    receipt_hash: str,
    records: Iterable[dict[str, Any]],
    *,
    audit_records: Iterable[dict[str, Any]] = (),
    public_keys: dict[str, Any] | None = None,
    delegation_records: Iterable[dict[str, Any]] = (),
    depth: int = _DEFAULT_DEPTH,
    breadth: int = _DEFAULT_BREADTH,
) -> dict[str, Any]:
    """Resolve the complete authority graph for *receipt_hash*.

    Parameters
    ----------
    receipt_hash
        The action receipt to resolve (the graph root).
    records
        Receipt-store records (``{"receipt_hash", "jws"}``) - the corpus
        the graph is built from. Only receipt-chain links are followed;
        a link the corpus cannot resolve is an explicit unknown state.
    audit_records
        Hash-chained audit records (``{"event": {...}, "timestamp", ...``)
        matched BY DIGEST for ``policy_deployed`` policy bindings.
    public_keys
        Mapping key_id -> PEM public key (str or bytes). Nodes whose key
        is not present state ``key_absent`` - a node state, not a failure.
    delegation_records
        Ledger records (``{"capability": {...}, "delegated_to_agent"}``)
        resolving capability ``parent_id`` token links into explicit
        delegation hop nodes.
    depth, breadth
        Bounded resolution. Anything cut is recorded under ``pruned``
        with its reason, and ``truncated`` reflects either cap.

    Returns a deterministic graph dict (nodes/edges sorted; no wall-clock).
    """
    corpus = ReceiptCorpus(records)
    audits = [dict(r) for r in audit_records if isinstance(r, dict)]
    keys = _normalise_public_keys(public_keys)
    delegations: dict[str, dict[str, Any]] = {}
    for rec in delegation_records:
        token_id = _delegation_record_key(rec)
        if token_id:
            delegations[token_id] = dict(rec)

    depth = max(0, min(int(depth), _MAX_DEPTH))
    breadth = max(1, min(int(breadth), _MAX_BREADTH))

    state = _GraphState(breadth)

    root = corpus.decoded(receipt_hash)
    if root is None:
        return {
            "root": {
                "id": receipt_hash,
                "kind": "receipt",
                "state": "unknown",
            },
            "receipt_hash": receipt_hash,
            "nodes": [{"id": receipt_hash, "kind": "receipt", "state": "unknown"}],
            "edges": [],
            "unknown": [{"kind": "receipt", "reference": receipt_hash, "reason": "not_found"}],
            "pruned": [],
            "truncated": False,
            "depth_limit": depth,
            "breadth_limit": breadth,
            "derived_only_from_verified_receipt_links": True,
        }

    queue: deque[tuple[str, int]] = deque([(receipt_hash, 0)])
    while queue:
        current, hop = queue.popleft()
        if hop > depth:
            state.prune("receipt", current, "depth_limit_exceeded")
            continue
        queue.extend(
            (parent, hop + 1)
            for parent in _process_receipt_node(
                state, corpus, current, hop, depth, keys, delegations, audits
            )
        )

    # Parent edges: `found` states whether the cited link resolves in the
    # corpus - pruned-by-cap links still resolve, broken links read False
    # and appear in `unknown` as not_found.
    for edge in state.edges:
        if edge["kind"] == "parent":
            edge["found"] = corpus.decoded(edge["to"]) is not None

    return {
        "root": receipt_hash,
        "nodes": sorted(state.nodes.values(), key=lambda n: (n["kind"], n["id"])),
        "edges": sorted(state.edges, key=lambda e: (e["kind"], e["from"], e["to"])),
        "unknown": _dedupe(sorted(state.unknown, key=lambda u: (u["kind"], u["reference"]))),
        "pruned": _dedupe(sorted(state.pruned, key=lambda p: (p["reason"], p["reference"]))),
        "truncated": state.truncated,
        "depth_limit": depth,
        "breadth_limit": breadth,
        "derived_only_from_verified_receipt_links": True,
    }


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = json.dumps(item, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def resolve_chain_graph_for_gateway(
    gateway: Any,
    receipt_hash: str,
    *,
    depth: int = _DEFAULT_DEPTH,
    breadth: int = _DEFAULT_BREADTH,
) -> dict[str, Any]:
    """Resolve a chain graph from a live gateway's configured storage.

    Bounded work: the receipt chain is scanned once per request and the
    graph is capped by depth/breadth. Signature keys come from the gate
    identity and the trust registry when available; receipts whose key
    is not loadable state ``key_absent`` (never a failure).
    """
    records = _load_gateway_receipts(gateway)
    audit_records = load_audit_events(Path(gateway.config.audit_chain))
    keys = _gateway_public_keys(gateway)
    delegation_records: list[dict[str, Any]] = []
    ledger_path = str(getattr(gateway.config, "delegations_file", "") or "")
    if ledger_path and Path(ledger_path).exists():
        for line in Path(ledger_path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and isinstance(record.get("capability"), dict):
                delegation_records.append(record)
    return resolve_chain_graph(
        receipt_hash,
        records,
        audit_records=audit_records,
        public_keys=keys,
        delegation_records=delegation_records,
        depth=depth,
        breadth=breadth,
    )


def _load_gateway_receipts(gateway: Any) -> list[dict[str, Any]]:
    """Receipt records from the segmented store or the legacy flat file."""
    store = getattr(gateway, "_receipt_store", None)
    if store is not None:
        return _read_segments(store)
    return load_receipt_records(str(Path(gateway.config.receipt_store)))


def _read_segments(store: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for seg in sorted(store.segments()):
        out.extend(load_receipt_records(seg))
    active = store.active_segment()
    if active is not None:
        out.extend(load_receipt_records(active))
    return out


def _gateway_public_keys(gateway: Any) -> dict[str, str]:
    keys: dict[str, str] = {}
    identity = getattr(gateway, "_gate_identity", None)
    if identity is not None:
        keys[identity.key_id] = identity.public_key_pem().decode("ascii")
    return keys


def digest_of_text(text: str) -> str:
    """``sha256:<hex>`` over text - the deployment-intake digest spelling."""
    return _HASH_PREFIX + hashlib.sha256(text.encode("utf-8")).hexdigest()
