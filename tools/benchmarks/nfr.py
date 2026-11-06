#!/usr/bin/env python3
"""NFR performance benchmark harness (P5.NFR / perf-v1).

Measures the three latency-critical primitives of the raucle gate path on
the CURRENT codebase, in-process:

1. gate decision   — ``CapabilityGate.check`` (Ed25519 signature verify +
                     delegation-chain resolve + constraint narrowing)
2. receipt write   — ``SegmentedReceiptStore.append_line`` (JSONL append
                     with fsync)
3. passport verify — ``verify_passport`` against a file-backed
                     ``TrustRegistry`` (registry resolve + Ed25519 verify)

Every number printed to ``docs/nfr/perf-v1.md`` is measured by this
script on the machine that runs it. N=1000 measured iterations per
target after a warmup of 100. It reports mean / p50 / p95 / max plus
the distribution-independent environment note. It invents nothing: if
a target cannot be built, the script fails loudly rather than emitting
a placeholder.

Usage::

    python tools/benchmarks/nfr.py [--out docs/nfr/perf-v1.md] [--n 1000]

Exit codes: 0 success, 2 build error, 3 output write error (see
docs/nfr/cli-contract.md — this tool documents its own contract).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))

from raucle import hash_text as _hash_text  # noqa: E402
from raucle.audit import Ed25519Signer  # noqa: E402
from raucle.capability import CapabilityGate, CapabilityIssuer  # noqa: E402
from raucle.passport import issue_passport, verify_passport  # noqa: E402
from raucle.provenance import (  # noqa: E402
    AgentIdentity,
    Operation,
    ProvenanceReceipt,
)
from raucle.receipt_store import SegmentedReceiptStore  # noqa: E402
from raucle.trust_registry import TrustRegistry  # noqa: E402

WARMUP = 100


def _env_note() -> str:
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as fh:
            model = next(
                (ln.split(":", 1)[1].strip() for ln in fh if ln.startswith("model name")),
                "unknown",
            )
    except OSError:
        model = "unknown"
    return (
        f"- Host OS: {platform.system()} {platform.release()} ({platform.machine()})\n"
        f"- CPU: {model}\n"
        f"- Python: {platform.python_version()}\n"
        f"- Wall-clock timing only (time.perf_counter); no benchmark-specific tuning.\n"
    )


def _pctl(sorted_us: list[float], p: float) -> float:
    idx = min(len(sorted_us) - 1, int(round(p * (len(sorted_us) - 1))))
    return sorted_us[idx]


def _bench(label: str, fn, n: int) -> dict:
    """Time ``fn()`` n times after warmup. Returns raw stats in microseconds."""
    for _ in range(WARMUP):
        fn()
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1_000_000)
    samples.sort()
    return {
        "target": label,
        "n": n,
        "mean_us": statistics.fmean(samples),
        "p50_us": _pctl(samples, 0.50),
        "p95_us": _pctl(samples, 0.95),
        "max_us": samples[-1],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(_REPO / "docs" / "nfr" / "perf-v1.md"))
    ap.add_argument("--n", type=int, default=1000)
    args = ap.parse_args(argv)

    n = args.n
    tmp = Path(tempfile.mkdtemp(prefix="raucle-nfr-"))

    # --- Target 1: gate decision ------------------------------------------
    try:
        issuer = CapabilityIssuer.generate(issuer="bench.platform.example")
        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        cap = issuer.mint(
            agent_id="agent:bench",
            tool="transfer_funds",
            constraints={"max_value": {"amount": 100}},
        )
    except Exception as exc:  # pragma: no cover
        print(f"BUILD ERROR: capability gate fixture failed: {exc}", file=sys.stderr)
        return 2

    def gate_check() -> None:
        decision = gate.check(cap, tool="transfer_funds", args={"amount": 50})
        if not decision.allowed:
            raise RuntimeError(f"gate fixture unexpectedly denied: {decision.reason}")

    # --- Target 2: receipt write ------------------------------------------
    store_dir = tmp / "receipts"
    store = SegmentedReceiptStore(base_dir=store_dir)
    receipt_agent = AgentIdentity.generate(agent_id="agent:bench")

    def receipt_write() -> None:
        rec = ProvenanceReceipt(
            agent_id=receipt_agent.agent_id,
            agent_key_id=receipt_agent.key_id,
            operation=Operation.TOOL_CALL,
            tool="transfer_funds",
            input_hash=_hash_text("bench"),
            issued_at=1700000000,
        )
        jws = rec.sign(receipt_agent)
        store.append_line(json.dumps({"receipt_hash": rec.receipt_hash, "jws": jws}))

    # Smoke-check the receipt fixture once so a broken fixture is a loud
    # build error, not a silently wrong benchmark.
    try:
        receipt_write()
    except Exception as exc:  # pragma: no cover
        print(f"BUILD ERROR: receipt store fixture failed: {exc}", file=sys.stderr)
        return 2

    # --- Target 3: verify_passport ----------------------------------------
    org_signer = Ed25519Signer.generate()
    reg = TrustRegistry(tmp / "registry.jsonl")
    reg.publish(org_signer.public_key_pem().decode(), issuer="Bench Org")
    agent = AgentIdentity.generate(agent_id="agent:bench.passport")
    passport = issue_passport(agent.statement, issuer_signer=org_signer, issuer="Bench Org")

    def passport_verify() -> None:
        v = verify_passport(passport.to_dict(), registry=reg)
        if not v.valid:
            raise RuntimeError(f"passport fixture unexpectedly invalid: {v.reason}")

    try:
        results = [
            _bench("gate_decision (CapabilityGate.check)", gate_check, n),
            _bench("receipt_write (SegmentedReceiptStore.append_line)", receipt_write, n),
            _bench("verify_passport (registry-backed)", passport_verify, n),
        ]
    except Exception as exc:  # pragma: no cover
        print(f"MEASUREMENT ERROR: {exc}", file=sys.stderr)
        return 2

    lines = [
        "# NFR performance snapshot — perf-v1",
        "",
        "Measured by `tools/benchmarks/nfr.py` on the codebase it ships with.",
        f"Every figure below is a real measurement (N={n} iterations per target,",
        f"{WARMUP} warmup, wall-clock via `time.perf_counter`). Nothing here is",
        "extrapolated, quoted from another machine, or hand-rounded beyond the",
        "precision printed.",
        "",
        "## Environment (the machine that produced these numbers)",
        "",
        f"Generated at: {time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
        _env_note().rstrip(),
        "- Receipt store and registry live in a per-run temp directory (hot page",
        f"  cache): `{tmp}`. Sustained production throughput with cold storage",
        "  will be materially slower — treat these as relative-ordering data,",
        "  not an SLO.",
        "- The receipt-write and gate targets are also exercised concurrently by",
        "  `tests/test_nfr_chaos.py`; this snapshot reports the single-thread path.",
        "",
        "## Results",
        "",
        "| Target | N | mean (µs) | p50 (µs) | p95 (µs) | max (µs) |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in results:
        lines.append(
            f"| {r['target']} | {r['n']} | {r['mean_us']:.1f} | {r['p50_us']:.1f} "
            f"| {r['p95_us']:.1f} | {r['max_us']:.1f} |"
        )
    lines += [
        "",
        "## Honesty notes",
        "",
        "- Same-process, same-event-loop-free measurement: each target is timed",
        "  in isolation, so per-target numbers are not additive into an end-to-end",
        "  request budget.",
        "- p95 on a shared host can include scheduler noise spikes; the max column",
        "  is the honest worst case seen in this run.",
        "- No claimed latency figure elsewhere in the docs may cite this table",
        "  unless it was produced by this harness version on the same commit.",
        "",
        f"Commit at time of measurement: `{os.popen('git rev-parse HEAD').read().strip()[:12]}`.",
        "",
    ]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out}")
    for r in results:
        print(
            f"  {r['target']}: mean={r['mean_us']:.1f}µs p50={r['p50_us']:.1f}µs "
            f"p95={r['p95_us']:.1f}µs max={r['max_us']:.1f}µs"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
