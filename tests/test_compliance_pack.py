"""E1b: the compliance evidence pack, acceptance-tested per the spec.

docs/spec/compliance/pack-v1.md, acceptance 1-6:
1. Green chain -> bundle; certificate verifies offline; pack_hash recomputes.
2. Tampered chain -> verifier_result "invalid", non-zero exit.
3. DORA RTS-12(2)(d) satisfied by signature verification, not assertion.
4. Extracts: bounded disclosure, every line cites a receipt/line ref.
5. Retention: the observed span vs the regime expectation (AI Act six
   months; DORA entity-decided).
6. The existing `compliance report` behaviour is unchanged.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from raucle.audit import Ed25519Signer, HashChainSink
from raucle.compliance import supported_frameworks
from raucle.compliance_pack import build_pack, verify_pack_certificate

ROWS = [
    {
        "timestamp": "2026-10-01T09:00:00+00:00",
        "source": "agent:svc",
        "destination": "tool:export_records",
        "tool": "export_records",
        "agent_id": "agent:svc",
        "policy": "demo.bank",
        "decision": "ALLOW",
        "reason": "policy allowed account=ACC-001",  # a value-quoting reason
        "rule_id": "export_records/agent:svc/0",
        "receipt_id": "sha256:" + "aa" * 32,
        "authorization": {
            "capability_id": "cap:root",
            "chain_digest": "sha256:" + "bb" * 32,
            "issuer": "demo-issuer",
        },
        "args": {"account": "ACC-001", "secret_token": "sk-live-DO-NOT-LEAK"},
    },
    {
        "timestamp": "2026-10-02T09:05:00+00:00",
        "source": "agent:svc",
        "destination": "tool:export_records",
        "tool": "export_records",
        "agent_id": "agent:svc",
        "policy": "demo.bank",
        "decision": "DENY",
        "reason": "constraint violated: account=ACC-999",
        "rule_id": "export_records/agent:svc/0",
        "receipt_id": "sha256:" + "cc" * 32,
        "authorization": {
            "capability_id": "cap:child",
            "chain_digest": "sha256:" + "dd" * 32,
            "issuer": "demo-issuer",
        },
        "args": {"account": "ACC-999"},
    },
]


def _signed_chain(tmp_path, rows=ROWS):
    from cryptography.hazmat.primitives import serialization

    path = tmp_path / "audit-chain.jsonl"
    signer = Ed25519Signer.generate()
    with HashChainSink(path, signer=signer, checkpoint_every=1) as sink:
        for row in rows:
            sink.append(row)
    pub_pem = signer._private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return path, signer, pub_pem


def _operator_key(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = tmp_path / "operator-private.pem"
    priv_path.write_bytes(pem)
    return pem, pub


def _recompute_pack_hash(out_dir):
    digest = hashlib.sha256
    parts = ""
    for name in ("coverage.json", "extracts.jsonl", "retention.json"):
        parts += "sha256:" + digest((out_dir / name).read_bytes()).hexdigest()
    return "sha256:" + digest(parts.encode("ascii")).hexdigest()


@pytest.fixture()
def stack(tmp_path):
    chain, signer, pub = _signed_chain(tmp_path)
    operator_priv, operator_pub = _operator_key(tmp_path)
    return {
        "chain": chain,
        "pub": pub,
        "operator_priv": operator_priv,
        "operator_pub": operator_pub,
        "tmp": tmp_path,
    }


def test_green_chain_bundle_certificate_verifies_pack_hash_recomputes(stack):
    out = stack["tmp"] / "pack-dora"
    manifest = build_pack(
        stack["chain"],
        framework="dora",
        out_dir=out,
        verify_key_pem=stack["pub"],
        operator_key_pem=stack["operator_priv"],
    )
    assert manifest["verifier_result"] == "valid"
    for name in (
        "report.md",
        "coverage.json",
        "extracts.jsonl",
        "retention.json",
        "certificate.json",
    ):
        assert (out / name).exists(), name

    # acceptance 1: the certificate verifies offline through the public verifier
    assert verify_pack_certificate(out / "certificate.json", stack["operator_pub"])

    # acceptance 1: pack_hash recomputes from the bundle files
    assert manifest["pack_hash"] == _recompute_pack_hash(out)

    # the certificate's own x_compliance block binds what it claims
    cert = json.loads((out / "certificate.json").read_text())
    payload = json.loads(
        __import__("base64").urlsafe_b64decode(
            cert["jws"].split(".")[1] + "==" * (-len(cert["jws"].split(".")[1]) % 4)
        )
    )
    assert payload["x_compliance"]["verifier_result"] == "valid"
    assert payload["x_compliance"]["framework"] == "dora"
    assert payload["x_compliance"]["receipt_count"] == 2


def test_tampered_chain_invalid_and_nonzero_exit(stack, tmp_path):
    # flip one payload row after the fact (bypass the hash chain)
    lines = (stack["chain"]).read_text().splitlines()
    recs = [json.loads(line) for line in lines if line.strip()]
    for rec in recs:
        if rec.get("event", {}).get("decision") == "ALLOW":
            rec["event"]["decision"] = "DENY"  # the tamper (payload flipped,
            # the envelope hash and signatures left as-were)
            break
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_text("\n".join(json.dumps(r) for r in recs) + "\n")

    out = tmp_path / "pack-bad"
    manifest = build_pack(
        tampered,
        framework="dora",
        out_dir=out,
        verify_key_pem=stack["pub"],
        operator_key_pem=stack["operator_priv"],
    )
    assert manifest["verifier_result"] == "invalid"

    # the report says so on its first line; the certificate records invalid
    assert (out / "report.md").read_text().startswith("> **VERIFIER RESULT: INVALID")
    cert = json.loads((out / "certificate.json").read_text())
    payload = json.loads(
        __import__("base64").urlsafe_b64decode(
            cert["jws"].split(".")[1] + "==" * (-len(cert["jws"].split(".")[1]) % 4)
        )
    )
    assert payload["guardrail_verdict"] == "compliance_invalid"
    assert payload["x_compliance"]["verifier_result"] == "invalid"

    # acceptance 2: the CLI exits non-zero on an invalid chain
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "raucle.cli",
            "compliance",
            "pack",
            "--chain",
            str(tampered),
            "--framework",
            "dora",
            "--pubkey",
            _write(tmp_path, "pub.pem", stack["pub"]),
            "--operator-key",
            str(tmp_path / "operator-private.pem"),
            "--out",
            str(tmp_path / "pack-bad-cli"),
        ],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)


def _write(tmp_path, name, data):
    (tmp_path / name).write_bytes(data)
    return str(tmp_path / name)


def test_dora_tamper_control_satisfied_by_signature_verification(stack):
    out = stack["tmp"] / "pack-dora-2"
    build_pack(
        stack["chain"],
        framework="dora",
        out_dir=out,
        verify_key_pem=stack["pub"],
        operator_key_pem=stack["operator_priv"],
    )
    coverage = json.loads((out / "coverage.json").read_text())
    by_id = {c["id"]: c for c in coverage["controls"]}
    # acceptance 3: satisfied by verification that RAN, not by assertion
    assert by_id["RTS-12(2)(d)"]["status"] == "SATISFIED"
    assert "verified against the provided key" in by_id["RTS-12(2)(d)"]["evidence"]
    assert by_id["RTS-12(2)(d)"]["citation"].startswith("https://eur-lex")
    assert by_id["RTS-12(2)(c)"]["status"] == "SATISFIED"
    assert "2 identity-attributed" in by_id["RTS-12(2)(c)"]["evidence"]


def test_extracts_are_bounded_and_cite_their_receipts(stack):
    out = stack["tmp"] / "pack-dora-3"
    build_pack(
        stack["chain"],
        framework="dora",
        out_dir=out,
        verify_key_pem=stack["pub"],
    )
    extracts = [
        json.loads(line)
        for line in (out / "extracts.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert len(extracts) == 2

    # acceptance 4: no secret material, no value-quoting reasons, no args
    blob = (out / "extracts.jsonl").read_text()
    assert "sk-live-DO-NOT-LEAK" not in blob
    assert "ACC-001" not in blob
    assert "ACC-999" not in blob
    assert "args" not in blob
    assert "reason" not in blob

    # every line cites a receipt id or a line ref present in the chain
    for extract in extracts:
        assert extract["ref"].startswith("line-")
        assert extract["receipt_id"].startswith("sha256:")
        assert extract["decision"] in {"ALLOW", "DENY"}
        assert extract["authorization"]["chain_digest"].startswith("sha256:")


def test_retention_span_and_expectations(stack, tmp_path):
    out = stack["tmp"] / "pack-dora-4"
    build_pack(stack["chain"], framework="dora", out_dir=out, verify_key_pem=stack["pub"])
    dora = json.loads((out / "retention.json").read_text())
    assert dora["expectation_months"] is None  # the entity's risk decision
    assert "risk assessment" in dora["expectation_note"]
    assert dora["first"] == "2026-10-01T09:00:00+00:00"
    assert dora["last"] == "2026-10-02T09:05:00+00:00"

    # acceptance 5: the AI Act flags a span under six months
    out_ai = tmp_path / "pack-aiact"
    build_pack(stack["chain"], framework="eu-ai-act", out_dir=out_ai, verify_key_pem=stack["pub"])
    ai = json.loads((out_ai / "retention.json").read_text())
    assert ai["expectation_months"] == 6
    assert ai["below_expectation"] is True  # one day of span


def test_existing_report_unchanged(stack):
    # acceptance 6: report still works, dora appears in the registry
    from raucle.compliance import build_report, render_markdown

    assert "dora" in supported_frameworks()
    report = build_report(stack["chain"], framework="eu-ai-act", public_key_pem=stack["pub"])
    md = render_markdown(report)
    assert "Compliance evidence map" in md
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "raucle.cli",
            "compliance",
            "report",
            str(stack["chain"]),
            "--framework",
            "soc2",
        ],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "SOC 2" in r.stdout or "CC" in r.stdout


def test_pack_without_operator_key_marks_unsigned(stack):
    out = stack["tmp"] / "pack-nokey"
    manifest = build_pack(
        stack["chain"], framework="dora", out_dir=out, verify_key_pem=stack["pub"]
    )
    assert manifest["certificate"] is None
    assert not (out / "certificate.json").exists()
    assert "no operator key" in (out / "report.md").read_text()
