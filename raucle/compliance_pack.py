"""The compliance evidence pack (E1b, spec docs/spec/compliance/pack-v1.md).

Turns a verified receipt chain into a named regime's artefact bundle:
the evidence map (report.md, coverage.json), bounded decision extracts,
the retention statement, and the verification certificate - a signed
x_compliance receipt the buyer's auditor can check offline with the
public verifier and the operator's public key. The pack never upgrades
bad evidence: a chain that fails verification gets verifier_result
"invalid", the report says so on its first line, and the caller exits
non-zero.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from raucle.compliance import (
    build_report,
    extract_evidence,
    render_markdown,
)

_HASH_PREFIX = "sha256:"
_RECEIPT_TYP = "provenance-receipt/v1"
_RECEIPT_CRIT = "raucle/v1"

#: Per-control regulation citations, keyed by framework then control id.
_FRAMEWORK_CITATIONS: dict[str, dict[str, str]] = {
    "dora": {
        "RTS-12(2)(c)": "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401774",
        "RTS-12(2)(d)": "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401774",
        "RTS-12(4)": "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401774",
        "FSB-ATTR": "https://www.fsb.org/uploads/P151026-1.pdf",
    }
}

#: Retention expectations per framework: (months | None, note).
_RETENTION_EXPECTATIONS: dict[str, tuple[int | None, str]] = {
    "eu-ai-act": (
        6,
        "Article 26(6) expects deployers of high-risk systems to keep logs "
        "for at least six months.",
    ),
    "dora": (
        None,
        "RTS 2024/1774 leaves the retention period to the entity's ICT risk "
        "assessment; the pack records the observed span only.",
    ),
}
_RETENTION_EXPECTATIONS.setdefault(
    "", (None, "No retention expectation defined for this framework.")
)


def _sha256_file(path: Path) -> str:
    return _HASH_PREFIX + hashlib.sha256(path.read_bytes()).hexdigest()


def _decision_rows(chain_path: str | Path) -> list[dict[str, Any]]:
    """The audit decision rows in the chain, in order (skip the header)."""
    rows: list[dict[str, Any]] = []
    for line in Path(chain_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or rec.get("chain_meta") or rec.get("checkpoint"):
            continue
        # hash-chain envelope: {"index", "prev_hash", "event": {...}, "hash"}
        event = rec.get("event") if isinstance(rec.get("event"), dict) else rec
        if str(event.get("decision", "")).upper() in {"ALLOW", "DENY"}:
            rows.append(event)
    return rows


def _bounded_extracts(chain_path: str | Path) -> list[dict[str, Any]]:
    """One bounded-disclosure extract per decision row.

    Fields and identifiers only: the decision, who acted, on what tool,
    under which rule and which authority chain. Never the call args,
    never the denial reason (it can quote constraint VALUES), never
    constraint sets. Each extract cites the receipt id (when the row has
    one) or its line, so the auditor can pull the full receipt from the
    chain."""
    extracts: list[dict[str, Any]] = []
    for line_no, rec in enumerate(_decision_rows(chain_path), start=1):
        extract: dict[str, Any] = {
            "ref": f"line-{line_no}",
            "decision": str(rec.get("decision", "")).upper(),
            "agent_id": rec.get("agent_id", ""),
            "tool": rec.get("tool", ""),
            "timestamp": rec.get("timestamp", ""),
        }
        if rec.get("receipt_id"):
            extract["receipt_id"] = rec["receipt_id"]
        if rec.get("rule_id"):
            extract["rule_id"] = rec["rule_id"]
        auth = rec.get("authorization")
        if isinstance(auth, dict):
            extract["authorization"] = {
                k: auth.get(k, "")
                for k in ("capability_id", "chain_digest", "issuer")
                if auth.get(k)
            }
        extracts.append(extract)
    return extracts


def _retention_statement(chain_path: str | Path, framework: str) -> dict[str, Any]:
    """The observed time span of the chain vs the regime's expectation."""
    months, note = _RETENTION_EXPECTATIONS.get(framework, (None, ""))
    stamps: list[str] = []
    for rec in _decision_rows(chain_path):
        ts = str(rec.get("timestamp", ""))
        if ts:
            stamps.append(ts)
    span: dict[str, Any] = {
        "decision_events": len(stamps),
        "framework": framework,
        "expectation_months": months,
        "expectation_note": note,
    }
    if stamps:
        span["first"] = min(stamps)
        span["last"] = max(stamps)
        if months is not None:
            import datetime as _dt

            try:
                first = _dt.datetime.fromisoformat(min(stamps))
                last = _dt.datetime.fromisoformat(max(stamps))
                observed_days = (last - first).total_seconds() / 86400
                span["observed_days"] = round(observed_days, 3)
                span["below_expectation"] = observed_days < months * 30
            except ValueError:
                span["observed_days"] = None
                span["below_expectation"] = None
    else:
        span["first"] = None
        span["last"] = None
        span["below_expectation"] = None
    return span


def _sign_certificate(
    payload: dict[str, Any], operator_private_pem: bytes
) -> tuple[str, str, bytes]:
    """Sign the x_compliance certificate with the operator's Ed25519 key.

    Returns (jws, receipt_hash, operator_public_pem). Same JWS shape the
    gate uses, so the standard ProvenanceVerifier checks it offline."""
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = serialization.load_pem_private_key(operator_private_pem, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("operator key must be an Ed25519 private PEM")
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = hashlib.sha256(pub_pem).hexdigest()[:16]
    payload = dict(payload)
    payload["agent_key_id"] = kid
    payload["agent_id"] = "raucle:compliance-pack"

    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    def _canon(obj: Any) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

    header = {
        "alg": "EdDSA",
        "typ": _RECEIPT_TYP,
        "kid": kid,
        "crit": [_RECEIPT_CRIT],
        _RECEIPT_CRIT: "provenance",
    }
    signing_input = f"{_b64(_canon(header))}.{_b64(_canon(payload))}".encode("ascii")
    sig = priv.sign(signing_input)
    jws = signing_input.decode("ascii") + "." + _b64(sig)
    receipt_hash = _HASH_PREFIX + hashlib.sha256(jws.encode("ascii")).hexdigest()
    return jws, receipt_hash, pub_pem


def build_pack(
    chain_path: str | Path,
    *,
    framework: str,
    out_dir: str | Path,
    verify_key_pem: bytes | None = None,
    operator_key_pem: bytes | None = None,
) -> dict[str, Any]:
    """Build the pack bundle. Returns the manifest; callers exit non-zero
    when manifest["verifier_result"] != "valid"."""
    chain_path = Path(chain_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    report = build_report(chain_path, framework=framework, public_key_pem=verify_key_pem)
    ev = extract_evidence(chain_path, public_key_pem=verify_key_pem)
    verifier_result = "valid" if ev.chain_valid else "invalid"

    # report.md - the failed chain says so on its first line
    md = render_markdown(report)
    if verifier_result != "valid":
        md = (
            "> **VERIFIER RESULT: INVALID.** The chain failed verification. "
            "This pack records the failure; it does not upgrade bad evidence.\n\n" + md
        )
    (out_dir / "report.md").write_text(md, encoding="utf-8")

    # coverage.json - control results + regulation citations
    citations = _FRAMEWORK_CITATIONS.get(framework, {})
    coverage = {
        "framework": report.framework,
        "framework_title": report.framework_title,
        "chain_path": str(chain_path),
        "verifier_result": verifier_result,
        "chain_signed": report.chain_signed,
        "controls": [
            {
                "id": c.id,
                "title": c.title,
                "requirement": c.requirement,
                "status": c.status.value,
                "evidence": c.evidence,
                "citation": citations.get(c.id, ""),
            }
            for c in report.controls
        ],
    }
    (out_dir / "coverage.json").write_text(json.dumps(coverage, indent=2), encoding="utf-8")

    # extracts.jsonl - bounded decision extracts
    with open(out_dir / "extracts.jsonl", "w", encoding="utf-8") as fh:
        for extract in _bounded_extracts(chain_path):
            fh.write(json.dumps(extract) + "\n")

    # retention.json - observed span vs the regime's expectation
    retention = _retention_statement(chain_path, framework)
    (out_dir / "retention.json").write_text(json.dumps(retention, indent=2), encoding="utf-8")

    # pack_hash binds the bundle files
    pack_hash = (
        _HASH_PREFIX
        + hashlib.sha256(
            (
                _sha256_file(out_dir / "coverage.json")
                + _sha256_file(out_dir / "extracts.jsonl")
                + _sha256_file(out_dir / "retention.json")
            ).encode("ascii")
        ).hexdigest()
    )
    chain_digest = _sha256_file(chain_path)

    manifest: dict[str, Any] = {
        "framework": report.framework,
        "out": str(out_dir),
        "chain_digest": chain_digest,
        "pack_hash": pack_hash,
        "verifier_result": verifier_result,
        "certificate": None,
    }

    if operator_key_pem is None:
        (out_dir / "report.md").write_text(
            md + "\n\n> Certificate NOT issued: no operator key supplied. "
            "Re-run with --operator-key to sign the verification certificate.\n",
            encoding="utf-8",
        )
        return manifest

    decision_rows = _decision_rows(chain_path)
    payload = {
        "iss": "raucle-compliance-pack",
        "typ": _RECEIPT_TYP,
        "iat": int(time.time()),
        "operation": "guardrail_scan",
        "parents": [],
        "taint": ["gate:observed"],
        "input_hash": pack_hash.removeprefix(_HASH_PREFIX),
        "ruleset_hash": chain_digest.removeprefix(_HASH_PREFIX),
        "guardrail_verdict": (
            "compliance_certified" if verifier_result == "valid" else "compliance_invalid"
        ),
        "x_compliance": {
            "action": "certified" if verifier_result == "valid" else "invalid",
            "pack_hash": pack_hash,
            "chain_digest": chain_digest,
            "framework": framework,
            "controls_covered": [c["id"] for c in coverage["controls"]],
            "receipt_count": len(decision_rows),
            "chain_span": {"first": retention.get("first"), "last": retention.get("last")},
            "verifier_result": verifier_result,
            "generated_at": int(time.time()),
        },
    }
    jws, receipt_hash, _pub = _sign_certificate(payload, operator_key_pem)
    cert_line = json.dumps({"receipt_hash": receipt_hash, "jws": jws})
    (out_dir / "certificate.json").write_text(cert_line + "\n", encoding="utf-8")
    manifest["certificate"] = str(out_dir / "certificate.json")
    manifest["certificate_receipt_hash"] = receipt_hash
    return manifest


def verify_pack_certificate(certificate_path: str | Path, operator_public_pem: bytes) -> bool:
    """The auditor's leg: verify the certificate offline with the public
    verifier. No account, no trust in raucle."""
    import hashlib as _h

    kid = _h.sha256(operator_public_pem).hexdigest()[:16]
    from raucle.provenance import ProvenanceVerifier

    report = ProvenanceVerifier(public_keys={kid: operator_public_pem}).verify_chain(
        Path(certificate_path)
    )
    return bool(report.valid)


def export_pack(pack_dir: str | Path, fmt: str = "csv") -> dict[str, Any]:
    """I3: auditor-facing exports over an existing pack bundle.

    csv writes coverage.csv (one row per control) and extracts.csv (one
    row per decision extract) beside the bundle; json writes a single
    pack-export.json combining coverage, extracts and retention. The
    exports derive from the bundle; they never restate what the bundle
    does not contain."""
    import csv

    pack_dir = Path(pack_dir)
    coverage = json.loads((pack_dir / "coverage.json").read_text(encoding="utf-8"))
    extracts = [
        json.loads(line)
        for line in (pack_dir / "extracts.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    retention = json.loads((pack_dir / "retention.json").read_text(encoding="utf-8"))

    if fmt == "csv":
        with open(pack_dir / "coverage.csv", "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["control_id", "title", "status", "evidence", "citation"])
            for c in coverage["controls"]:
                writer.writerow([c["id"], c["title"], c["status"], c["evidence"], c["citation"]])
        with open(pack_dir / "extracts.csv", "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["ref", "decision", "agent_id", "tool", "rule_id", "receipt_id"])
            for e in extracts:
                writer.writerow(
                    [
                        e.get("ref", ""),
                        e.get("decision", ""),
                        e.get("agent_id", ""),
                        e.get("tool", ""),
                        e.get("rule_id", ""),
                        e.get("receipt_id", ""),
                    ]
                )
        return {"format": "csv", "files": ["coverage.csv", "extracts.csv"]}
    if fmt == "json":
        export = {"coverage": coverage, "extracts": extracts, "retention": retention}
        (pack_dir / "pack-export.json").write_text(json.dumps(export, indent=2), encoding="utf-8")
        return {"format": "json", "files": ["pack-export.json"]}
    raise ValueError(f"unknown export format {fmt!r}; use csv or json")
