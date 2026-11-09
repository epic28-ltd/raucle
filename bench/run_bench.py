#!/usr/bin/env python
"""X5 performance bench for the raucle hot path.

Measures five paths end-to-end against the real production modules —
no mocks on the measured leg:

* ``gate_allow``       — CapabilityGate.check on a schema-valid call
* ``gate_deny``        — CapabilityGate.check on the type-confused call
* ``receipt_emit``     — VerdictSigner.issue (Ed25519 JWS receipt)
* ``receipt_append``   — SegmentedReceiptStore.append_line (sync write)
* ``index_append``     — ReceiptIndex.index_receipt (SQLite projection)
* ``siem_forward``     — SIEMSink.append (ECS JSONL line, flushed)
* ``sink_submit``      — submit into AsyncReceiptSink (async receipt path)

Reports p50/p99 latency and ceiling throughput (1/mean) per path. Method
and recorded runs: docs/nfr/x5-performance-bench.md. All numbers come from
the machine actually running this script — never copied from another run.

Usage: python bench/run_bench.py [--iter N] [--json PATH]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
import uuid
from pathlib import Path

from raucle.async_receipt_sink import AsyncReceiptSink
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.receipt_index import ReceiptIndex
from raucle.receipt_store import SegmentedReceiptStore
from raucle.siem import SIEMSink
from raucle.tool_schema import ToolSchemaRegistry
from raucle.verdicts import VerdictSigner

REPO = Path(__file__).resolve().parent.parent
_TMP = Path(uuid.uuid4().hex[:8])


def percentile(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    k = (len(s) - 1) * p
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def timed(call, *args, iters: int) -> dict[str, float]:
    """Run call(*args) iters times; return latency stats in microseconds."""
    xs: list[float] = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        call(*args)
        xs.append((time.perf_counter_ns() - t0) / 1000.0)
    mean = statistics.fmean(xs)
    return {
        "p50_us": round(percentile(xs, 0.50), 1),
        "p99_us": round(percentile(xs, 0.99), 1),
        "mean_us": round(mean, 1),
        "ceiling_ops_s": round(1e6 / mean, 0),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iter", type=int, default=2_000, help="iterations per path")
    ap.add_argument("--json", type=str, default="bench/results/latest.json")
    args = ap.parse_args()
    n = args.iter

    base = REPO / "bench" / ".tmp" / _TMP
    base.mkdir(parents=True, exist_ok=True)

    # --- environment: real gate, schema registry, signer, sinks ----------
    iss = CapabilityIssuer.generate(issuer="bench.example")
    reg = ToolSchemaRegistry()
    schema = {
        "type": "object",
        "properties": {"amount": {"type": "number"}},
        "required": ["amount"],
    }
    reg.register("send_money", schema)
    reg.bind_policy("send_money", {"required_present": ["amount"]})
    gate = CapabilityGate(trusted_issuers={iss.key_id: iss.public_key_pem}, tool_schemas=reg)
    cap = iss.mint(
        agent_id="agent:bench", tool="send_money", constraints={"required_present": ["amount"]}
    )

    signer = VerdictSigner.generate()
    store = SegmentedReceiptStore(base / "store")

    def append_receipt(envelope: dict) -> None:
        record = {
            "receipt_hash": hashlib.sha256(envelope["jws"].encode()).hexdigest(),
            "jws": envelope["jws"],
        }
        store.append_line(json.dumps(record))

    index = ReceiptIndex(base / "index.sqlite")
    siem = SIEMSink(base / "siem.jsonl")
    sink = AsyncReceiptSink(append_receipt, max_queue=4096, name="bench-sink")

    def emit_and_record() -> str:
        jws = signer.issue(
            input_text=f"bench-call-{uuid.uuid4().hex}",
            verdict="allow",
            confidence=1.0,
            ruleset_hash="bench",
        )
        append_receipt({"jws": jws})
        return jws

    # one real receipt to seed the index bench with a valid envelope
    seed_jws = emit_and_record()

    def allow_call() -> None:
        gate.check(cap, tool="send_money", agent_id="agent:bench", args={"amount": 42})

    def deny_call() -> None:
        gate.check(cap, tool="send_money", agent_id="agent:bench", args={"amount": "99999"})

    def emit_receipt() -> None:
        signer.issue(
            input_text=f"bench-{uuid.uuid4().hex}",
            verdict="allow",
            confidence=1.0,
            ruleset_hash="bench",
        )

    def append_prebuilt(envelope: dict | None = None) -> None:
        append_receipt({"jws": seed_jws})

    def index_record(record: dict) -> None:
        index.index_receipt(record)

    def make_record() -> dict:
        jws = signer.issue(
            input_text=f"bench-{uuid.uuid4().hex}",
            verdict="allow",
            confidence=1.0,
            ruleset_hash="bench",
        )
        return {"receipt_hash": hashlib.sha256(jws.encode()).hexdigest(), "jws": jws}

    def siem_forward() -> None:
        siem.append({"event": "gate_decision", "decision": "allow", "tool": "send_money"})

    def sink_submit(record: dict) -> None:
        sink.submit(record)

    results: dict[str, dict] = {}
    results["gate_allow"] = timed(allow_call, iters=n)
    results["gate_deny"] = timed(deny_call, iters=n)
    results["receipt_emit"] = timed(emit_receipt, iters=n)
    results["receipt_append"] = timed(append_prebuilt, iters=n)
    results["index_append"] = timed(index_record, make_record(), iters=n)
    results["siem_forward"] = timed(siem_forward, iters=n)
    # async sink: submit-side latency is the caller-visible cost
    rec = make_record()
    results["sink_submit"] = timed(sink_submit, rec, iters=n)

    # async-sink ceiling: feed N records, drain, measure wall-clock rate
    t0 = time.perf_counter()
    for _ in range(n):
        sink.submit(make_record())
    submit_wall = time.perf_counter() - t0
    done = sink.close(drain_timeout=30.0)
    drain_wall = time.perf_counter() - t0 - submit_wall
    if done["written"] < n:
        print(f"WARNING: drain incomplete: {done}", flush=True)
    results["sink_submit"]["async_submit_rate_ops_s"] = round(n / submit_wall, 0)
    results["sink_submit"]["async_drain_write_rate_ops_s"] = round(n / max(drain_wall, 1e-9), 0)
    results["sink_submit"]["overflow_events"] = len(sink.overflow_events)

    siem.close()
    index.close()

    env = {
        "python_path": sys.executable,
        "iterations_per_path": n,
    }
    print(json.dumps({"bench": "x5-hot-path", "env": env, "results": results}, indent=2))

    out = REPO / args.json
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"bench": "x5-hot-path", "env": env, "results": results}, indent=2))
    print(f"saved: {out}")


if __name__ == "__main__":
    main()
