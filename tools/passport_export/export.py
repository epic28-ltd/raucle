"""OV-23 — audit-pack-to-agent-passport export.

Converts a raucle audit pack (the assurance packet: PACK.json index, signed
manifest, capability statements, receipt chain) into `AgentPassport` documents
in the OSS raucle format, using ONLY raucle's own callables:

- `raucle.audit_pack.build_pack` produced the packet;
- `raucle.passport.issue_passport` signs the passport (issuer countersignature);
- `raucle.passport.verify_passport` verifies it against a
  `raucle.trust_registry.TrustRegistry` (the round trip in the tests).

Nothing here fabricates a passport format: the artifact handed to verifiers is
exactly what `raucle/passport.py` defines.

OV-21 — chain-graph linkage. When the pack carries `chain.jsonl`, the export
attaches an optional, explicit `chain_linkage` annotation (chain digest +
summary) to each saved passport file alongside the signed body. The linkage
lives OUTSIDE the signed body (`AgentPassport.body()` excludes it), so the
issuer signature over the canonical body remains byte-identical to a plain
`raucle.passport` passport and verification is unaffected — the extra key is
metadata an operator can audit, never something the signature vouches for.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from raucle.audit_pack import _CHAIN_JSONL, INDEX_NAME
from raucle.passport import issue_passport
from raucle.provenance import CapabilityStatement


def chain_linkage_from_pack(pack_dir: str | Path) -> dict[str, Any] | None:
    """Return the OV-21 chain-graph linkage annotation for a pack, or None.

    Computed with raucle's own primitives: the digest is the sha256 of the
    pack's receipt chain (`chain.jsonl`) bytes — the same member digest the
    signed manifest records — and the summary is read from the signed
    manifest's chain verdict/summary blocks.
    """
    pack = Path(pack_dir)
    chain = pack / _CHAIN_JSONL
    if not chain.exists():
        return None

    digest = hashlib.sha256(chain.read_bytes()).hexdigest()
    text = chain.read_text(encoding="utf-8")
    receipt_lines = sum(1 for line in text.splitlines() if line.strip())

    manifest = None
    manifest_path = pack / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except ValueError:
            manifest = None

    chain_verdict = {}
    summary = {}
    if isinstance(manifest, dict):
        chain_verdict = manifest.get("chain_verdict") or {}
        summary = manifest.get("summary") or {}

    return {
        "kind": "raucle-chain-linkage/v1",
        "reference": _CHAIN_JSONL,
        "chain_sha256": digest,
        "receipt_count": receipt_lines,
        "chain_verdict_summary": {
            key: chain_verdict[key]
            for key in sorted({"status", "receipts", "findings"}
                              & set(chain_verdict))
        },
        "export_summary": {key: summary[key] for key in sorted(summary)},
    }


def load_pack_statements(pack_dir: str | Path) -> list[CapabilityStatement]:
    """Load the capability statements stored in an audit pack.

    Parsed with `raucle.provenance.CapabilityStatement.from_dict` — raucle's
    own strict parser (unknown fields fail closed), no hand-rolled dict use.
    """
    pack = Path(pack_dir)
    stmt_dir = pack / "statements"
    if not stmt_dir.is_dir():
        return []
    out: list[CapabilityStatement] = []
    for path in sorted(stmt_dir.glob("*.json")):
        out.append(CapabilityStatement.from_dict(json.loads(path.read_text(encoding="utf-8"))))
    return out


def export_passports(
    pack_dir: str | Path,
    *,
    issuer_signer: Any,
    issuer: str,
    out_dir: str | Path,
    ttl_seconds: int | None = None,
) -> list[dict[str, Any]]:
    """Export every capability statement in an audit pack as a passport.

    Uses `raucle.passport.issue_passport` verbatim — the issuer key must be
    published to the shared `TrustRegistry` before any verifier can resolve it
    (fail-closed, per `verify_passport`).

    Returns the written passport dicts (each with the optional `chain_linkage`
    annotation when the pack carries a receipt chain).
    """
    pack = Path(pack_dir)
    if not (pack / INDEX_NAME).exists():
        raise ValueError(f"not a raucle audit pack: missing {INDEX_NAME} in {pack}")

    statements = load_pack_statements(pack)
    if not statements:
        raise ValueError(f"audit pack {pack} carries no capability statements to passport")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    linkage = chain_linkage_from_pack(pack)
    written: list[dict[str, Any]] = []
    for stmt in statements:
        passport = issue_passport(
            stmt, issuer_signer=issuer_signer, issuer=issuer, ttl_seconds=ttl_seconds
        )
        d = passport.to_dict()
        if linkage is not None:
            d["chain_linkage"] = linkage  # unsigned annotation; outside the signed body
        path = out / f"passport-{stmt.key_id}.json"
        path.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
        written.append({**d, "_path": str(path)})

    index = {
        "kind": "raucle-passport-export/v1",
        "source_pack": str(pack.resolve()),
        "issuer": issuer,
        "passports": [
            {
                "path": w["_path"],
                "agent_id": w["statement"].get("agent_id", ""),
                "key_id": w["statement"].get("key_id", ""),
            }
            for w in written
        ],
        "chain_linkage_present": linkage is not None,
    }
    (out / "passport_export.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return written


def main(argv: list[str] | None = None) -> int:
    """CLI: export passports from a pack. Private keys are NEVER CLI inputs."""
    import argparse

    from raucle.audit import Ed25519Signer

    ap = argparse.ArgumentParser(
        description="Export raucle audit-pack statements as agent passports (OV-23)"
    )
    ap.add_argument("pack_dir")
    ap.add_argument("out_dir")
    ap.add_argument("--issuer", required=True)
    ap.add_argument(
        "--issuer-key-pem", required=True, help="PEM file with the ISSUER private key (Ed25519)"
    )
    args = ap.parse_args(argv or sys.argv[1:])

    signer = Ed25519Signer.from_pem(Path(args.issuer_key_pem).read_bytes())
    written = export_passports(
        args.pack_dir, issuer_signer=signer, issuer=args.issuer, out_dir=args.out_dir
    )
    for w in written:
        print(f"wrote {w['_path']} (agent {w['statement'].get('agent_id', '')})")
    return 0


__all__ = [
    "chain_linkage_from_pack",
    "export_passports",
    "load_pack_statements",
    "main",
]
