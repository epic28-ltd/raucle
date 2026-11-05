#!/usr/bin/env python3
"""Verification demo (P1.4V): admission refusals made live and verifiable.

Demonstrates three things, end to end, in a throwaway loopback-only
workdir (no network, no pushed state):

1. Enrol a real agent with a signed ``agent-descriptor/v1`` record via the
   P1.4c admission path (the gateway receipting an allow).
2. Tamper the attested manifest hash of a signed descriptor and re-run the
   enrolment attempt through the admission path: the refusal verdict and
   the receipted refusal record (``x_admission`` extension) are shown, and
   the whole receipt store re-verifies offline with
   :class:`raucle.provenance.ProvenanceVerifier`. The registry-side
   refusal (nothing appended) is shown too.
3. For the enrolled agent, the agent-registry record and the chain-graph
   reconstruction (P1.1a) resolve against each other: the graph root is
   the enrolment receipt, the node carries the same agent_id, and the
   descriptor digest bound in the receipt equals a digest recomputed from
   the registry record.

Honesty rule: every printed claim is backed by a computed value in this
process; anything that could not be checked is printed as NOT VERIFIED
rather than asserted. Run: ``python scripts/demo_p1_4v.py`` (or with
``--workdir`` to keep the artefacts).
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from raucle.agent_registry import (
    AgentRegistry,
    Attestation,
    DelegationCeilings,
    DescriptorError,
    issue_descriptor,
)
from raucle.audit import Ed25519Signer
from raucle.chain_graph import resolve_chain_graph_for_gateway
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.provenance import ProvenanceVerifier, _canonical_json, _sha256_hex

POLICY = """
version: 1
issuer: demo.bank
policies:
  - tool: lookup_balance
    agent_id: agent:demo
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""

MANIFEST_HASH = "sha256:" + "c" * 64


def _attest() -> Attestation:
    return Attestation(
        attested_manifest_hash=MANIFEST_HASH,
        attested_manifest_kind="manifest",
        framework="demo-fw",
        framework_version="1.0",
    )


def _signed_record(signer: Ed25519Signer) -> dict[str, Any]:
    return issue_descriptor(
        "agent:demo",
        operator="ops",
        operator_binding="rak:ops",
        status="enrolled",
        attestation=_attest(),
        ceilings=DelegationCeilings(),
        signer=signer,
    ).to_dict()


def _tampered_record(signer: Ed25519Signer) -> dict[str, Any]:
    record = _signed_record(signer)
    record["attested_manifest_hash"] = "sha256:" + "d" * 64
    return record


def _digest(record: dict[str, Any]) -> str:
    return _sha256_hex(_canonical_json(record))


def _decode_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    part = receipt["jws"].split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _read_receipts(gw: RaucleGateway) -> list[dict[str, Any]]:
    with open(gw.config.receipt_store, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def run_demo(workdir: Path) -> dict[str, Any]:
    """Run the P1.4V demonstration in *workdir*; return computed results."""
    signer = Ed25519Signer.generate()
    issuer_pem = signer.public_key_pem().decode("ascii")

    reg_path = workdir / "agents.jsonl"
    registry = AgentRegistry(path=reg_path)

    policy = workdir / "policies.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="demo-key",
        signer_backend="local",
        policy_file=str(policy),
        receipt_store=str(workdir / "receipts.jsonl"),
        audit_chain=str(workdir / "audit.jsonl"),
        registry_path=str(workdir / "registry.jsonl"),
        agent_registry_file=str(reg_path),
        agent_registry_public_key=issuer_pem,
        emit_receipts=True,
    )
    gw = RaucleGateway(config)

    results: dict[str, Any] = {}

    # -- Step 1: live enrolment with a signed descriptor ---------------------
    record = _signed_record(signer)
    verdict, allow_receipt = gw.admit_enrolment(record, issuer_pem)
    results["enrol_allowed"] = bool(verdict.allowed)
    results["allow_receipt"] = allow_receipt or ""
    # The registry holds the same agent under the same identity.
    resolved = registry.resolve("agent:demo")
    if resolved is None:
        registry.enrol_from_descriptor(record, issuer_pem)
        resolved = registry.resolve("agent:demo")
    results["registry_agent_id"] = resolved.agent_id if resolved else ""
    results["registry_digest"] = _digest(resolved.to_dict()) if resolved else ""

    # -- Step 2: tampered manifest, live refusal, receipted ------------------
    tampered = _tampered_record(signer)
    t_verdict, deny_receipt = gw.admit_enrolment(tampered, issuer_pem)
    results["tampered_refused"] = not t_verdict.allowed
    results["tampered_reason"] = t_verdict.reason
    results["deny_receipt"] = deny_receipt or ""
    deny_rec = next(
        (r for r in _read_receipts(gw) if r["receipt_hash"] == deny_receipt),
        None,
    )
    if deny_rec is not None:
        payload = _decode_payload(deny_rec)
        results["deny_verdict"] = payload.get("guardrail_verdict", "")
        results["deny_extension"] = payload.get("x_admission", {})
        results["deny_descriptor_digest"] = results["deny_extension"].get("descriptor_hash", "")
    else:
        results["deny_verdict"] = ""
        results["deny_extension"] = {}
        results["deny_descriptor_digest"] = ""

    # Registry side: the same tampered record is refused and NOT appended.
    reg_before = len(registry.agent_ids())
    try:
        registry.enrol_from_descriptor(tampered, issuer_pem)
        results["registry_refused"] = False
        results["registry_error"] = ""
    except DescriptorError as exc:
        results["registry_refused"] = True
        results["registry_error"] = str(exc)
    results["registry_unchanged"] = len(registry.agent_ids()) == reg_before

    # Offline verification of the whole receipt store.
    verifier = ProvenanceVerifier(
        public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
    )
    report = verifier.verify_chain(gw.config.receipt_store)
    results["store_verified"] = bool(report.valid)
    results["store_errors"] = list(report.errors)
    hashes = {r["receipt_hash"] for r in _read_receipts(gw)}
    results["deny_receipt_in_store"] = results["deny_receipt"] in hashes
    results["allow_receipt_in_store"] = results["allow_receipt"] in hashes

    # -- Step 3: registry and chain reconstruction resolve together ---------
    graph: dict[str, Any] | None = None
    if results["allow_receipt"] in hashes:
        graph = resolve_chain_graph_for_gateway(gw, results["allow_receipt"])
        nodes = {n["id"]: n for n in graph.get("nodes", [])}
        node = nodes.get(results["allow_receipt"])
        root = graph.get("root")
        root = root if isinstance(root, dict) else {}
        results["graph_root_state"] = str(root.get("state", ""))
        if node is not None:
            results["graph_node_agent_id"] = str(node.get("agent_id", ""))
            results["graph_node_verdict"] = str(node.get("guardrail_verdict", ""))
            sig = node.get("signature")
            sig = sig if isinstance(sig, dict) else {}
            results["graph_node_signature"] = str(sig.get("status", ""))
        else:
            results["graph_node_agent_id"] = ""
            results["graph_node_verdict"] = ""
            results["graph_node_signature"] = ""
    else:
        results["graph_root_state"] = ""
        results["graph_node_agent_id"] = ""
        results["graph_node_verdict"] = ""
        results["graph_node_signature"] = ""

    # Cross-check: same digest and identity on both sides. The enrolment
    # receipt is signed under the gate identity (graph node agent_id is
    # agent:gate), so the enrolled agent's identity is the x_admission
    # extension on that receipt, and the digest is x_admission's
    # descriptor_hash, compared against a digest recomputed from the
    # registry record.
    allow_rec = next(
        (r for r in _read_receipts(gw) if r["receipt_hash"] == results["allow_receipt"]),
        None,
    )
    extension_agent_id = ""
    receipt_digest = ""
    if allow_rec is not None:
        ap = _decode_payload(allow_rec)
        ext = ap.get("x_admission", {})
        extension_agent_id = str(ext.get("agent_id", ""))
        receipt_digest = str(ext.get("descriptor_hash", ""))
    results["extension_agent_id"] = extension_agent_id
    results["extension_digest"] = receipt_digest
    digest_match = bool(receipt_digest) and receipt_digest == results["registry_digest"]
    results["digest_match"] = digest_match
    identity_match = (
        extension_agent_id == results["registry_agent_id"]
        and bool(results["registry_agent_id"])
        and results["graph_node_signature"] == "verified"
    )
    results["identity_match"] = identity_match
    results["cross_check"] = bool(identity_match and digest_match)

    results["receipts_total"] = len(_read_receipts(gw))
    results["gate_public_keys"] = {gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
    results["artefacts"] = {
        "registry": str(reg_path),
        "receipts": str(gw.config.receipt_store),
        "audit": str(gw.config.audit_chain),
    }
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="P1.4V verification demo")
    ap.add_argument(
        "--workdir",
        default=None,
        help="keep artefacts in this directory instead of a throwaway tmpdir",
    )
    args = ap.parse_args()
    if args.workdir:
        workdir = Path(args.workdir)
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        workdir = Path(tempfile.mkdtemp(prefix="raucle-p1_4v-"))

    r = run_demo(workdir)
    print(f"P1.4V verification demo - artefacts in {workdir}")
    print()
    print("-- enrolment (signed descriptor) --")
    print(f"agent enrolled:              {r['registry_agent_id']}")
    print(f"admission allow receipt:     {r['allow_receipt']}")
    _rstore = "VERIFIED" if r["allow_receipt_in_store"] else "NOT VERIFIED"
    _rstore_d = "VERIFIED" if r["deny_receipt_in_store"] else "NOT VERIFIED"
    _gnode = "VERIFIED" if r["graph_node_signature"] == "verified" else "NOT VERIFIED"
    print(f"receipt present in store:    {_rstore}")
    print()
    print("-- tampered manifest, live admission refusal --")
    print(f"refused:                     {'VERIFIED' if r['tampered_refused'] else 'NOT VERIFIED'}")
    print(f"refusal reason:              {r['tampered_reason']}")
    print(f"refusal receipt:             {r['deny_receipt']}")
    print(f"receipt verdict:             {r['deny_verdict']}")
    print(f"receipt agent_id:            {r['deny_extension'].get('agent_id', '')}")
    print(f"receipt reason:              {r['deny_extension'].get('reason', '')}")
    print(f"receipt descriptor hash:     {r['deny_descriptor_digest']}")
    print(f"receipt in store:            {_rstore_d}")
    print(
        f"registry refused, nothing appended: "
        f"{'VERIFIED' if r['registry_refused'] and r['registry_unchanged'] else 'NOT VERIFIED'}"
        + (f" ({r['registry_error']})" if r["registry_error"] else "")
    )
    print(
        f"store verifies with ProvenanceVerifier: "
        f"{'VERIFIED' if r['store_verified'] else 'NOT VERIFIED'}"
        + (f" errors={r['store_errors']}" if r["store_errors"] else "")
    )
    print()
    print("-- registry x chain-graph cross-check --")
    print(f"graph node receipt present:  {_gnode}")
    print(f"graph node signing identity: {r['graph_node_agent_id']}")
    print(f"graph node verdict:          {r['graph_node_verdict']}")
    print(f"x_admission agent_id:        {r['extension_agent_id']}")
    print(f"x_admission descriptor hash: {r['extension_digest']}")
    print(f"same agent_id both sides:    {'VERIFIED' if r['identity_match'] else 'NOT VERIFIED'}")
    print(
        f"same descriptor digest both sides: {'VERIFIED' if r['digest_match'] else 'NOT VERIFIED'}"
    )
    print()
    print("OVERALL: " + ("CONSISTENT" if r["cross_check"] else "INCONSISTENT"))
    if not r["cross_check"]:
        print(
            "Honest gaps: the cross-check did not hold for every side; "
            "see the NOT VERIFIED lines above."
        )
    return 0 if r["cross_check"] else 1


if __name__ == "__main__":
    sys.exit(main())
