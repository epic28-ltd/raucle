"""Rebuild the shipped demo bundle (docs/demo-bundle) from a real gate chain.

Run from the repo root:
    PYTHONPATH=. python scripts/build_demo_bundle.py

Produces the committed pack (chain.jsonl, manifest.json, PACK.json,
report.html, pubkeys/), verifies it fully offline, and prints the canonical
bundle digest. Keys and the chain clock are generated fresh each run — the
result is self-consistent but NOT byte-reproducible across runs, so after a
regeneration the published digest must be re-pinned (separate reviewable PR).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from raucle.audit_pack import build_pack, verify_pack  # noqa: E402
from raucle.broker import AWSEgressGate, CapabilityDenied  # noqa: E402
from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.demo_bundle import DIGEST_ALGO, bundle_digest, pack_index_summary  # noqa: E402
from raucle.provenance import AgentIdentity, ProvenanceLogger  # noqa: E402

OUT_DIR = REPO_ROOT / "docs" / "demo-bundle"
GENERATED_AT = 1_762_500_000  # pinned so PACK.json is stable for a given run


class _FakeTransport:
    def __call__(self, req: object) -> tuple[int, bytes]:
        return 200, b'{"Item":{"customer_id":{"S":"C-123"}}}'


def _audit_key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def build_gate_chain(chain_path: Path) -> AgentIdentity:
    """Produce a real gate chain (ALLOW: scan + tool call, DENY: attempt)."""
    issuer = CapabilityIssuer.generate(issuer="acme.bank")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="dynamodb.GetItem",
        constraints={"allowed_values": {"TableName": ["customers"]}},
        ttl_seconds=3600,
    )
    broker = AgentIdentity.generate(agent_id="agent:raucle-aws-egress-broker")
    writer = ProvenanceLogger(broker, sink_path=chain_path)
    egress = AWSEgressGate(
        gate,
        region="us-east-1",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        provenance_writer=writer,
        transport=_FakeTransport(),
        clock=lambda: GENERATED_AT - 60,
    )
    egress.get_item(
        token, table="customers", key={"customer_id": {"S": "C-123"}}, agent_id="agent:kyc-prod"
    )
    try:
        egress.get_item(
            token,
            table="forbidden",
            key={"customer_id": {"S": "C-9"}},
            agent_id="agent:kyc-prod",
        )
    except CapabilityDenied:
        print("  recorded DENY receipt (capability boundary demo)")
    writer.close()
    return broker


def main() -> int:
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="raucle-demo-bundle-"))
    try:
        chain = tmp / "custody.jsonl"
        broker = build_gate_chain(chain)
        out = tmp / "pack"
        build_pack(
            chain_path=chain,
            public_keys={broker.key_id: broker.public_key_pem()},
            audit_key_pem=_audit_key(),
            out_dir=out,
            generated_at=GENERATED_AT,
        )

        verdict = verify_pack(out)
        if not verdict.ok:
            for reason in verdict.reasons:
                print(f"  FAIL: {reason}", file=sys.stderr)
            print("rebuilt bundle failed offline verification", file=sys.stderr)
            return 1

        # Publish: replace the committed bundle atomically.
        if OUT_DIR.exists():
            shutil.rmtree(OUT_DIR)
        shutil.copytree(out, OUT_DIR)

        digest = bundle_digest(OUT_DIR)
        summary = pack_index_summary(OUT_DIR)
        print(
            f"demo bundle rebuilt and verified at {OUT_DIR}\n"
            f"  digest: {digest}\n"
            f"  algo:   {DIGEST_ALGO}\n"
            f"  index:  {json.dumps(summary, sort_keys=True)}\n"
            "Re-pin the published value in .github/workflows/ci.yml (separate PR)."
        )
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
