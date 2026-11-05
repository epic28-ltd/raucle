"""Microbenchmarks for §6.3 — gate-path and proof latency.

Runs locally; no API spend; no external benchmarks needed. Captures p50/p95/p99
for:
  - Gate.check() with no parent chain
  - Gate.check() with a 3-link parent chain
  - JSONSchemaProver.prove() cold (no cache)
  - JSONSchemaProver.prove() cached

Hardware annotation is recorded so the paper can report numbers across the
Apple M-series, x86_64 Linux, and ARM-server hardware that S&P reviewers
expect to see.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.prove import JSONSchemaProver


SCHEMA = {
    "type": "object",
    "properties": {
        "to": {
            "type": "string",
            "enum": ["alice@example.com", "bob@example.com", "finance@example.com"],
        },
        "amount": {"type": "number", "minimum": 0, "maximum": 100},
        "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]},
    },
    "required": ["to", "amount", "currency"],
}
POLICY = {
    "max_value": {"amount": 100},
    "forbidden_values": {"to": ["attacker@evil.example"]},
}


def percentiles(samples: list[float]) -> dict[str, float]:
    s = sorted(samples)
    n = len(s)
    return {
        "n": n,
        "p50_ms": s[n // 2] * 1000,
        "p95_ms": s[int(n * 0.95)] * 1000,
        "p99_ms": s[int(n * 0.99)] * 1000,
        "mean_ms": statistics.mean(s) * 1000,
    }


def bench_gate_check_no_chain(iters: int) -> dict:
    issuer = CapabilityIssuer.generate(issuer="bench.example")
    token = issuer.mint(
        agent_id="agent:bench",
        tool="transfer_funds",
        constraints=POLICY,
        ttl_seconds=3600,
    )
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    args = {"to": "alice@example.com", "amount": 50, "currency": "USD"}

    samples: list[float] = []
    for _ in range(iters):
        t0 = time.perf_counter()
        decision = gate.check(token, tool="transfer_funds", args=args)
        samples.append(time.perf_counter() - t0)
        assert decision.allowed
    return percentiles(samples)


def bench_gate_check_chain(iters: int, chain_len: int = 3) -> dict:
    issuer = CapabilityIssuer.generate(issuer="bench.example")
    root = issuer.mint(
        agent_id="agent:bench",
        tool="transfer_funds",
        constraints=POLICY,
        ttl_seconds=3600,
    )
    current = root
    chain = [root]
    for _ in range(chain_len):
        current = issuer.attenuate(current)
        chain.append(current)

    by_id = {t.token_id: t for t in chain}
    gate = CapabilityGate(
        trusted_issuers={issuer.key_id: issuer.public_key_pem},
        parent_resolver=by_id.get,
    )
    args = {"to": "alice@example.com", "amount": 50, "currency": "USD"}

    samples: list[float] = []
    for _ in range(iters):
        t0 = time.perf_counter()
        decision = gate.check(current, tool="transfer_funds", args=args)
        samples.append(time.perf_counter() - t0)
        assert decision.allowed
    return percentiles(samples)


def bench_prove_cold(iters: int) -> dict:
    """Cold-path proof: fresh prover instance, no memoisation possible."""
    samples: list[float] = []
    for _ in range(iters):
        prover = JSONSchemaProver()
        t0 = time.perf_counter()
        result = prover.prove(SCHEMA, POLICY)
        samples.append(time.perf_counter() - t0)
        assert result.status == "PROVEN"
    return percentiles(samples)


def bench_prove_cached(iters: int) -> dict:
    prover = JSONSchemaProver()
    # warm
    prover.prove(SCHEMA, POLICY)
    samples: list[float] = []
    for _ in range(iters):
        t0 = time.perf_counter()
        # NOTE: the current reference impl doesn't memoise; this measures the
        # raw overhead of constructing the result object given a known answer.
        # When the memo cache is wired in, swap to the cached path.
        result = prover.prove(SCHEMA, POLICY)
        samples.append(time.perf_counter() - t0)
        assert result.status == "PROVEN"
    return percentiles(samples)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--iters", type=int, default=5000)
    p.add_argument("--prove-iters", type=int, default=200)
    p.add_argument("--output", default="latency.json")
    args = p.parse_args(argv)

    print(f"Platform: {platform.platform()} / {platform.machine()}")
    print("Warming up …")
    bench_gate_check_no_chain(200)

    results = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "iters_gate": args.iters,
        "iters_prove": args.prove_iters,
        "gate_no_chain": bench_gate_check_no_chain(args.iters),
        "gate_chain_3": bench_gate_check_chain(args.iters, 3),
        "prove_cold": bench_prove_cold(args.prove_iters),
        "prove_cached": bench_prove_cached(args.prove_iters),
    }
    Path(args.output).write_text(json.dumps(results, indent=2))
    for k, v in results.items():
        if isinstance(v, dict) and "p50_ms" in v:
            print(
                f"  {k:18s} p50={v['p50_ms']:.2f}ms  p95={v['p95_ms']:.2f}ms  p99={v['p99_ms']:.2f}ms"
            )
    print(f"\nWrote {args.output}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
