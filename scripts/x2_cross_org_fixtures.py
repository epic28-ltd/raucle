#!/usr/bin/env python3
"""Regenerate the X2 cross-org fixture set (assets/verifier/fixtures/cross-org/).

The committed fixture is what the offline acceptance tests exercise: a
registry operator-signed Trust Registry artifact publishing ORG A's agent
key with its capability statement, a real receipt chain minted under that
key, and a transparency-log inclusion proof binding the leaf receipt's
digest to a signed epoch checkpoint.

Everything is produced by the real production code paths (TrustRegistry,
ProvenanceLogger, the log profile's own compute_log_entry_hash), so the
fixture cannot drift from the wire formats. Regeneration rotates the
fixture keys: re-run this script, then scripts/x2_asset_hashes.py.

The two .pem files are the OUT-OF-BAND ANCHORS a third party pins: the
registry operator key (the registry artifact's trust anchor) and the log
operator key (the inclusion proof's trust anchor). They are committed so
the acceptance test can pin them; in a real cross-org verification each
anchor travels out of band, never inside the artifact it authenticates.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raucle.audit import Ed25519Signer  # noqa: E402
from raucle.provenance import (  # noqa: E402
    AgentIdentity,
    ProvenanceLogger,
    _b64url_encode,
    _canonical_json,
)
from raucle.trust_registry import TrustRegistry, _key_id_for  # noqa: E402
from raucle.transparency import LOG_GENESIS_PREV_HASH, compute_log_entry_hash  # noqa: E402

OUT_DEFAULT = ROOT / "assets" / "verifier" / "fixtures" / "cross-org"
FIXED_NOW = 1_760_000_000


def _checkpoint(private, *, org: str, size: int, head_hash: str, iat: int) -> str:
    """One epoch checkpoint in the exact wire format the log emits."""
    header = {
        "alg": "EdDSA",
        "typ": "transparency-epoch/v1",
        "kid": "raucle-portal-fixture",
        "crit": ["raucle/v1"],
        "raucle/v1": "transparency",
    }
    payload = {
        "iss": "raucle-portal",
        "org": org,
        "epoch": size,
        "size": size,
        "head_hash": head_hash,
        "iat": iat,
        "nonce": "crossorg-fixture",
    }
    signing_input = (
        _b64url_encode(_canonical_json(header)) + "." + _b64url_encode(_canonical_json(payload))
    ).encode("ascii")
    return signing_input.decode("ascii") + "." + _b64url_encode(private.sign(signing_input))


def build_fixture(out_dir: Path) -> dict[str, str]:
    """Write the fixture set; returns {relative path: sha256} of what was written."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # -- the registry: operator-signed, publishing org A's key + statement --
    operator = Ed25519Signer.generate()
    registry_path = out_dir / "registry.jsonl"
    if registry_path.exists():
        registry_path.unlink()
    registry = TrustRegistry(path=registry_path, operator_signer=operator)
    identity = AgentIdentity.generate(
        agent_id="agent:org-a-billing",
        allowed_tools=["tool.ledger.get"],
    )
    registry.publish(
        identity.public_key_pem(),
        issuer="org-a",
        metadata={
            "org": "org-a",
            "capability_statement": identity.statement.to_dict(),
        },
    )

    # -- org A's receipt chain: a user_input root + a permitted tool call --
    chain_path = out_dir / "chain.jsonl"
    if chain_path.exists():
        chain_path.unlink()
    writer = ProvenanceLogger(identity, sink_path=chain_path)
    root = writer.record_user_input("read ACC-1 ledger")
    leaf = writer.record_tool_call(
        parents=[root],
        tool="tool.ledger.get",
        input_args={"account": "ACC-1"},
        output={"ok": True},
    )
    writer.close()

    # -- the transparency log: one entry registering the leaf receipt -----
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    log_private = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    log_pem = (
        log_private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    entry = {
        "org": "org-a",
        "sequence": 1,
        "prev_hash": LOG_GENESIS_PREV_HASH,
        "receipt_digest": leaf,
        "payload_digest": None,
        "registered_at": FIXED_NOW,
        "entry_hash": "",
    }
    entry["entry_hash"] = compute_log_entry_hash(entry)
    checkpoint = _checkpoint(
        log_private, org="org-a", size=1, head_hash=entry["entry_hash"], iat=FIXED_NOW
    )
    proof = {
        "org": "org-a",
        "sequence": 1,
        "entries": [entry],
        "size": 1,
        "head_hash": entry["entry_hash"],
        "checkpoint_jws": checkpoint,
        # convenience material the verifier ignores: the riding key is never
        # verification input (a proof verified against its own key would be
        # self-attested)
        "receipt_digest": leaf,
        "payload_digest": None,
        "epoch": 1,
        "key_id": _key_id_for(log_pem),
        "operator_public_key_pem": log_pem,
    }

    (out_dir / "registry-operator.pem").write_text(
        operator.public_key_pem().decode("ascii"), encoding="ascii"
    )
    (out_dir / "log-operator.pem").write_text(log_pem, encoding="ascii")
    (out_dir / "log-inclusion.json").write_text(
        json.dumps(proof, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        "# X2 cross-org fixture set\n"
        "\n"
        "Inputs a third party holds in cross-org verification:\n"
        "\n"
        "- `chain.jsonl` — the receipt chain signed by ORG A's agent key.\n"
        "- `registry.jsonl` — the Trust Registry artifact (operator-signed\n"
        "  append-only log) publishing org A's key and capability statement.\n"
        "- `log-inclusion.json` — the transparency log's inclusion proof for\n"
        "  the leaf receipt's digest (the riding key is convenience material\n"
        "  only, never verification input).\n"
        "\n"
        "The out-of-band anchors (committed here so tests can pin them):\n"
        "\n"
        "- `registry-operator.pem` — the registry operator public key; pin it\n"
        "  to authenticate the registry artifact.\n"
        "- `log-operator.pem` — the log operator public key; pin it to\n"
        "  authenticate the inclusion proof's checkpoint.\n"
        "\n"
        "Regenerate with `scripts/x2_cross_org_fixtures.py`, then re-pin with\n"
        "`scripts/x2_asset_hashes.py`.\n",
        encoding="utf-8",
    )

    import hashlib

    written: dict[str, str] = {}
    for p in sorted(out_dir.iterdir()):
        if p.is_file():
            written[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=OUT_DEFAULT,
        help="fixture directory (default: the committed fixture set)",
    )
    args = parser.parse_args(argv)
    written = build_fixture(args.out)
    for name, digest in written.items():
        print(f"{digest}  {name}")
    print(f"wrote {len(written)} files to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
