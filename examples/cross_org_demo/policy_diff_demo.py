"""S2 demo — the receipt-bound bilateral policy diff, cross-org.

No network, no plaintext. Org A suffers an incident (a too-loose policy
allowed an over-broad export), replays the chain against the stricter
alternative policy with :func:`raucle.counterfactual.replay_counterfactual`,
and SIGNS the resulting diff document with its Ed25519 key (which Org B
resolves from the shared trust registry — Org B has never held Org A's
key). Org B then verifies the verdict OFFLINE, given only the public key,
the referenced chain, both policy files and the input store: the replay is
RE-RUN and must match the signed summary exactly.

    pip install 'raucle[server,compliance]'
    python examples/cross_org_demo/policy_diff_demo.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from raucle.audit import Ed25519Signer
from raucle.capability import CapabilityIssuer
from raucle.counterfactual import replay_counterfactual
from raucle.policy_diff import (
    chain_head_from_file,
    sign_policy_diff_document,
    verify_policy_diff_document,
)
from raucle.replay import InputStore
from raucle.trust_registry import TrustRegistry

ORIGINAL_POLICY = """
version: 1
issuer: org-a.bank
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-999"]
"""

ALTERNATIVE_POLICY = """
version: 1
issuer: org-a.bank
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""


def run_incident(workdir: Path):
    """Run the incident with the ORIGINAL (too-loose) policy."""
    from raucle.gateway import GatewayConfig, RaucleGateway
    from raucle.gateway_app import create_gateway_app
    from raucle.provenance import _canonical_json

    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(workdir / "receipts.jsonl"),
        audit_chain=str(workdir / "audit.jsonl"),
        registry_path=str(workdir / "registry.jsonl"),
        agent_credentials_file=str(workdir / "agent-credentials.jsonl"),
    )
    original_policy = workdir / "original-policy.yaml"
    original_policy.write_text(ORIGINAL_POLICY)
    config.policy_file = str(original_policy)
    config.gate_auth = "off"
    gateway = RaucleGateway(config)
    from fastapi.testclient import TestClient

    client = TestClient(create_gateway_app(gateway))
    store_path = workdir / "inputs.jsonl"
    with InputStore(store_path) as store:
        for account in ("ACC-001", "ACC-999"):
            args = {"account": account}
            resp = client.post(
                "/gate", json={"tool": "export_records", "args": args, "agent_id": "agent:svc"}
            )
            assert resp.status_code == 200 and resp.json()["decision"] == "allow"
            store.add(_canonical_json(args).decode("utf-8"))
    return store_path


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="raucle-policy-diff-"))
    print("=" * 72)
    print("Org A - the incident and the counterfactual diff, signed")
    print("=" * 72)
    store_path = run_incident(workdir)
    original_policy = workdir / "original-policy.yaml"
    alternative_policy = workdir / "alternative-policy.yaml"
    alternative_policy.write_text(ALTERNATIVE_POLICY)
    chain = workdir / "receipts.jsonl"

    report = replay_counterfactual(
        chain, input_store_path=store_path, alternative_policy_path=alternative_policy
    )
    print(
        f"  replay: {report['prevented_by_alternative']} of "
        f"{report['prevented_by_alternative'] + report['still_allowed_by_alternative']} "
        f"incident actions prevented ({report['verdict']})"
    )

    # Org A's signing key: published to the shared trust registry, so Org B
    # resolves it — the two orgs have never exchanged keys directly.
    operator = Ed25519Signer.generate()
    registry = TrustRegistry(workdir / "trust-registry.jsonl", operator_signer=operator)
    issuer = CapabilityIssuer.generate(issuer="org-a.bank")
    registry.publish(issuer.public_key_pem, issuer=issuer.issuer)
    signer = Ed25519Signer.generate()
    signer_pem = signer.public_key_pem()
    # Ed25519Signer generates with no key_id; the registry publishes the PEM.
    import hashlib

    pem_bytes = signer_pem if isinstance(signer_pem, bytes) else signer_pem.encode()
    key_id = hashlib.sha256(pem_bytes).hexdigest()[:16]
    registry.publish(signer_pem, issuer="org-a.review")

    envelope = sign_policy_diff_document(
        signer,
        key_id=key_id,
        report=report,
        chain_path=str(chain),
        original_policy_path=str(original_policy),
        alternative_policy_path=str(alternative_policy),
    )
    print(
        f"  signed document {envelope['receipt_hash'][:20]}... binds chain head "
        f"{chain_head_from_file(str(chain))[:20]}..., both policy digests, the summary"
    )

    print("=" * 72)
    print("Org B - OFFLINE verification (public key + material only)")
    print("=" * 72)
    Path(workdir / "org-b-review-signed.pem").write_bytes(
        signer_pem if isinstance(signer_pem, bytes) else signer_pem.encode()
    )
    ok, errors = verify_policy_diff_document(
        envelope,
        public_key_pem=signer_pem if isinstance(signer_pem, bytes) else signer_pem.encode(),
        chain_path=str(chain),
        original_policy_path=str(original_policy),
        alternative_policy_path=str(alternative_policy),
        input_store_path=str(store_path),
    )
    print(
        f"  signature + chain_head + both policy digests + replay re-run: "
        f"{'VERIFIED' if ok else 'INVALID'}"
    )
    if errors:
        for e in errors:
            print(f"    - {e}")

    print("=" * 72)
    print("Dishonesty check - the retyped verdict fails closed")
    print("=" * 72)
    tampered = dict(envelope)
    tampered["jws"] = envelope["jws"][:-8] + ("AAAAAA==")
    ok2, errors2 = verify_policy_diff_document(
        tampered,
        public_key_pem=signer_pem if isinstance(signer_pem, bytes) else signer_pem.encode(),
        chain_path=str(chain),
        original_policy_path=str(original_policy),
        alternative_policy_path=str(alternative_policy),
        input_store_path=str(store_path),
    )
    print(
        f"  tampered document: {'VERIFIED (BAD!)' if ok2 else 'INVALID'} ({errors2[0] if errors2 else '-'})"
    )
    return 0 if (ok and not ok2) else 1


if __name__ == "__main__":
    raise SystemExit(main())
