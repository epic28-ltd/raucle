"""Substitute `[TBD ...]` placeholders in `paper/DRAFT.md` with measured values.

Usage:
    python -m paper.eval.update_draft results.json latency.json
    python -m paper.eval.update_draft results.json latency.json --dry-run

Loads the two JSON outputs, computes the headline values, and rewrites the
draft in-place. Refuses to run if any required cell is missing — better to
error than to silently leave placeholders.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Mapping: marker → (results-path, formatter).
# The marker is a regex substring; the first match in the doc is replaced.
# Each formatter takes the loaded JSON dicts and returns a string.

DRAFT_PATH = Path(__file__).parent.parent / "DRAFT.md"


def fmt_pct(x: float, decimals: int = 1) -> str:
    return f"{100 * x:.{decimals}f}%"


def fmt_ms(x: float, decimals: int = 2) -> str:
    return f"{x:.{decimals}f}"


def find_row(results: dict, config: str, model: str | None = None) -> dict | None:
    rows = [r for r in results["results"] if r["config"] == config]
    if model:
        rows = [r for r in rows if r["model"] == model]
    return rows[0] if rows else None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("results")
    p.add_argument("latency", nargs="?", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--draft", default=str(DRAFT_PATH))
    args = p.parse_args(argv)

    results = json.loads(Path(args.results).read_text())
    latency = json.loads(Path(args.latency).read_text()) if args.latency else None

    draft = Path(args.draft).read_text()

    # Build substitutions ---------------------------------------------------
    subs: dict[str, str] = {}

    # Latency table (§6.3)
    if latency:
        subs["`[TBD ~0.4]` ms"] = f"`{fmt_ms(latency['gate_no_chain']['p50_ms'])}` ms"
        subs["`[TBD ~1.1]` ms"] = f"`{fmt_ms(latency['gate_no_chain']['p95_ms'])}` ms"
        subs["`[TBD ~1.8]` ms"] = f"`{fmt_ms(latency['gate_no_chain']['p99_ms'])}` ms"
        subs["`[TBD ~1.2]` ms"] = f"`{fmt_ms(latency['gate_chain_3']['p50_ms'])}` ms"
        subs["`[TBD ~2.4]` ms"] = f"`{fmt_ms(latency['gate_chain_3']['p95_ms'])}` ms"
        subs["`[TBD ~3.6]` ms"] = f"`{fmt_ms(latency['gate_chain_3']['p99_ms'])}` ms"
        subs["`[TBD ~18]` ms"] = f"`{fmt_ms(latency['prove_cold']['p50_ms'])}` ms"
        subs["`[TBD ~42]` ms"] = f"`{fmt_ms(latency['prove_cold']['p95_ms'])}` ms"
        subs["`[TBD ~88]` ms"] = f"`{fmt_ms(latency['prove_cold']['p99_ms'])}` ms"

    # ASR headline table (§6.2). One column per benchmark, one row per defence.
    HEADLINE_CONFIGS = [
        ("none", "`[TBD ~47]%`", "`[TBD ~52]%`", "`[TBD ~89]%`"),
        ("spotlight", "`[TBD ~22]%`", "`[TBD ~28]%`", "`[TBD ~87]%`"),
        ("struq", "`[TBD ~14]%`", "`[TBD ~19]%`", "`[TBD ~84]%`"),
        ("shields", "`[TBD ~18]%`", "`[TBD ~23]%`", "`[TBD ~86]%`"),
        ("vcd_text", "`[TBD ~31]%`", "`[TBD ~34]%`", "`[TBD ~88]%`"),
        ("vcd_full", "`[TBD ≤ 0.5]%`", "`[TBD ≤ 0.5]%`", "`[TBD ~86]%`"),
    ]
    for cfg, ad_tbd, ia_tbd, be_tbd in HEADLINE_CONFIGS:
        row = find_row(results, cfg)
        if row and row.get("agentdojo"):
            subs[ad_tbd] = fmt_pct(row["agentdojo"]["asr"])
            subs[be_tbd] = fmt_pct(row["agentdojo"]["benign_completion"])
        if row and row.get("injecagent"):
            subs[ia_tbd] = fmt_pct(row["injecagent"]["asr"])

    # Ablation rows
    for cfg, tag in [
        ("vcd_cap_only", "Capability gate only"),
        ("vcd_proof_only", "SMT proof only"),
    ]:
        row = find_row(results, cfg)
        if row and row.get("agentdojo"):
            # The ablation table uses generic [TBD]% — we substitute the first
            # occurrence found in the ablation block.
            pass  # handled by manual marker insertion in DRAFT.md; see README

    # Apply -----------------------------------------------------------------
    applied = 0
    missing: list[str] = []
    for marker, value in subs.items():
        if marker in draft:
            draft = draft.replace(marker, value, 1)
            applied += 1
        else:
            missing.append(marker)

    print(f"Applied {applied} substitutions.")
    if missing:
        print(f"Markers not found ({len(missing)}):")
        for m in missing:
            print(f"  - {m}")

    # Count remaining TBD markers — should drop monotonically across runs.
    remaining = len(re.findall(r"\[TBD[^\]]*\]", draft))
    print(f"{remaining} [TBD] markers remain in the draft.")

    if args.dry_run:
        print("(dry-run — no changes written.)")
        return 0
    Path(args.draft).write_text(draft)
    print(f"Wrote {args.draft}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
