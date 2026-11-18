#!/usr/bin/env python3
"""Cross-language conformance harness for Raucle Provenance Receipt v1.

Proves the five reference implementations are genuinely interoperable:

  1. For every vector in docs/spec/provenance/v1/test-vectors.json, each
     language EMITS the receipt from the shared fixed seed and MUST
     produce a byte-identical compact JWS and content-addressed id.
  2. Every emitted JWS is then VERIFIED by the canonical Python reference
     (a real A-emits / B-verifies cross-check), and its id recomputed.
  3. All five languages + the published vector MUST agree on both the
     JWS bytes and the receipt_hash.

The canonical Python reference (raucle/provenance.py) is the
source of truth; the ports conform to it.

Usage:  python reference/conformance.py
Exit 0 on full agreement, non-zero otherwise.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REF = ROOT / "reference"
VECTORS = ROOT / "docs" / "spec" / "provenance" / "v1" / "test-vectors.json"


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_vectors() -> dict:
    return json.loads(VECTORS.read_text())


def requests_for(vf: dict) -> list[dict]:
    """One emit request per vector: the decoded payload + the fixed seed."""
    seed = vf["fixed_seed_hex"]
    reqs = []
    for v in vf["vectors"]:
        payload = json.loads(b64u_decode(v["expected_jws"].split(".")[1]))
        reqs.append({"name": v["name"], "seed_hex": seed, "payload": payload})
    return reqs


# ── per-language drivers ───────────────────────────────────────────


def emit_python(reqs: list[dict]) -> list[dict]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from raucle.provenance import (
        AgentIdentity,
        CapabilityStatement,
        ProvenanceReceipt,
        _sha256_hex,
    )

    out = []
    for r in reqs:
        seed = bytes.fromhex(r["seed_hex"])
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = _sha256_hex(pub_pem)[:16]
        p = r["payload"]
        rec = ProvenanceReceipt.from_jws("x." + r_b64(p) + ".x")
        stmt = CapabilityStatement(
            agent_id=rec.agent_id,
            key_id=key_id,
            public_key_pem=pub_pem.decode("ascii"),
        )
        ident = AgentIdentity(agent_id=rec.agent_id, private_key=priv, statement=stmt)
        rec.sign(ident)
        out.append({"jws": rec.jws, "id": rec.receipt_hash})
    return out


def r_b64(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _run_lines(cmd: list[str], cwd: Path, reqs: list[dict]) -> list[dict]:
    stdin = "\n".join(json.dumps(r) for r in reqs) + "\n"
    proc = subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{cmd}: {proc.stderr.strip()}")
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def emit_go(reqs):
    return _run_lines(["go", "run", "./cmd/emit"], REF / "provenance-go", reqs)


def emit_rust(reqs):
    subprocess.run(
        ["cargo", "build", "--quiet", "--example", "emit"],
        cwd=REF / "provenance-rs",
        check=True,
        capture_output=True,
        text=True,
    )
    return _run_lines(
        ["cargo", "run", "--quiet", "--example", "emit"],
        REF / "provenance-rs",
        reqs,
    )


def emit_ts(reqs):
    return _run_lines(
        ["npx", "--no-install", "tsx", "src/emit-cli.ts"],
        REF / "provenance-ts",
        reqs,
    )


def emit_csharp(reqs):
    subprocess.run(
        ["dotnet", "build", "--nologo", "-v", "q", "interop/Interop.csproj"],
        cwd=REF / "provenance-cs",
        check=True,
        capture_output=True,
        text=True,
    )
    return _run_lines(
        ["dotnet", "run", "--no-build", "--project", "interop/Interop.csproj", "--", "--harness"],
        REF / "provenance-cs",
        reqs,
    )


def verify_python(jws: str, vf: dict) -> str:
    """Verify a JWS with the Python reference; return recomputed id."""
    from cryptography.hazmat.primitives import serialization

    from raucle.provenance import ProvenanceReceipt

    pub = serialization.load_pem_public_key(vf["public_key_pem"].encode())
    rec = ProvenanceReceipt.from_jws(jws)
    header_b, payload_b, sig_b = jws.split(".")
    signing_input = (header_b + "." + payload_b).encode("ascii")
    pub.verify(b64u_decode(sig_b), signing_input)  # raises on bad sig
    return rec.receipt_hash


# ── orchestration ──────────────────────────────────────────────────

LANGS = [
    ("python", emit_python, lambda: True),
    ("go", emit_go, lambda: shutil.which("go")),
    ("rust", emit_rust, lambda: shutil.which("cargo")),
    ("typescript", emit_ts, lambda: shutil.which("npx")),
    ("csharp", emit_csharp, lambda: shutil.which("dotnet")),
]


def _check_byte_identity(names, expected, results) -> bool:
    """Check byte-identity of emitted receipts vs published vectors."""
    ok = True
    print("\n=== emit byte-identity vs published vectors ===")
    for i, name in enumerate(names):
        exp_jws, exp_id = expected[name]
        row = []
        for lang in results:
            got = results[lang][i]
            jws_ok = got["jws"] == exp_jws
            id_ok = got["id"] == exp_id
            row.append(f"{lang}={'OK' if jws_ok and id_ok else 'DIFF'}")
            if not (jws_ok and id_ok):
                ok = False
        print(f"  {name}: {exp_id}")
        print(f"    {'  '.join(row)}")
    return ok


def _cross_verify(names, expected, results, vf) -> bool:
    """Cross-verify every emitted JWS using the Python verifier."""
    ok = True
    print("\n=== cross-verify: every emitted JWS verified by Python ===")
    for i, name in enumerate(names):
        for lang in results:
            jws = results[lang][i]["jws"]
            try:
                rid = verify_python(jws, vf)
            except Exception as exc:  # noqa: BLE001
                print(f"  {name}/{lang}: VERIFY FAILED: {exc}")
                ok = False
                continue
            if rid != expected[name][1]:
                print(f"  {name}/{lang}: id mismatch {rid}")
                ok = False
    if ok:
        print("  all languages verify in Python with matching ids")
    return ok


def main() -> int:
    vf = load_vectors()
    reqs = requests_for(vf)
    names = [r["name"] for r in reqs]
    expected = {v["name"]: (v["expected_jws"], v["expected_receipt_hash"]) for v in vf["vectors"]}

    all_langs = [lang for lang, _fn, _avail in LANGS]
    results: dict[str, list[dict]] = {}
    skipped: list[str] = []
    for lang, fn, avail in LANGS:
        if not avail():
            print(f"SKIP {lang} (toolchain not found)")
            skipped.append(lang)
            continue
        try:
            results[lang] = fn(reqs)
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL {lang}: {exc}")
            return 2

    ok = _check_byte_identity(names, expected, results)
    ok = _cross_verify(names, expected, results, vf) and ok

    print()
    ran = list(results)
    n_ran, n_total = len(ran), len(all_langs)
    if not ok:
        print("RESULT: FAIL — byte-identity mismatch")
        return 1
    if n_ran < n_total:
        # Only claim what was actually exercised. A green run on a subset (e.g.
        # Python-only in CI without Go/Rust/npx/dotnet) must NOT print the
        # five-language claim (round-3 #16). Exit non-zero so a CI that intends
        # to prove full parity fails loudly when a toolchain is missing.
        print(
            f"RESULT: PASS ({n_ran}/{n_total} languages: {', '.join(ran)}) — "
            f"byte-identity holds for the languages that ran; "
            f"SKIPPED: {', '.join(skipped)}. Full five-language parity NOT proven."
        )
        return 3
    print(f"RESULT: PASS — {n_total}-language byte-identity proven ({', '.join(ran)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
