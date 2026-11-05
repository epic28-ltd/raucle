"""End-to-end evaluation orchestrator.

Sweeps every (configuration × benchmark × model) cell, emits results.json
in the shape that `update_draft.py` consumes.

Usage:
    python -m paper.eval.harness --models claude-sonnet-4-6 --output results.json
    python -m paper.eval.harness --models claude-sonnet-4-6 gpt-4o llama-3.1-70b
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from paper.eval import agentdojo_adapter, injecagent_adapter, metrics
from paper.eval.configurations import ALL as ALL_CONFIGURATIONS

logger = logging.getLogger("paper.eval.harness")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")


AGENTDOJO_SUITES = ["banking", "slack", "github", "travel"]
INJECAGENT_MODES = ["dh", "ds"]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--models", nargs="+", default=["claude-sonnet-4-6"], help="Base models to evaluate."
    )
    p.add_argument("--output", default="results.json")
    p.add_argument("--skip-agentdojo", action="store_true")
    p.add_argument("--skip-injecagent", action="store_true")
    p.add_argument(
        "--configs", nargs="+", default=None, help="Optional subset of configuration short names."
    )
    args = p.parse_args(argv)

    selected = [c for c in ALL_CONFIGURATIONS if not args.configs or c.short in args.configs]
    logger.info("Configurations: %s", [c.short for c in selected])
    logger.info("Models: %s", args.models)

    out: dict = {
        "schema_version": 1,
        "models": args.models,
        "configurations": [c.short for c in selected],
        "results": [],
    }

    for model in args.models:
        for cfg in selected:
            logger.info("─── %s / %s ───", model, cfg.name)
            t0 = time.time()

            ad_result = None
            ia_result = None

            if not args.skip_agentdojo:
                try:
                    suite_results = agentdojo_adapter.run(
                        cfg.factory, model=model, suites=AGENTDOJO_SUITES
                    )
                    ad_result = metrics.aggregate_agentdojo(suite_results).__dict__
                    logger.info("AgentDojo: %s", ad_result)
                except NotImplementedError as exc:
                    logger.warning("AgentDojo adapter not yet wired: %s", exc)

            if not args.skip_injecagent:
                try:
                    mode_results = injecagent_adapter.run(
                        cfg.factory, model=model, modes=INJECAGENT_MODES
                    )
                    ia_result = metrics.aggregate_injecagent(mode_results).__dict__
                    logger.info("InjecAgent: %s", ia_result)
                except NotImplementedError as exc:
                    logger.warning("InjecAgent adapter not yet wired: %s", exc)

            out["results"].append(
                {
                    "model": model,
                    "config": cfg.short,
                    "config_name": cfg.name,
                    "is_ablation": cfg.is_ablation,
                    "agentdojo": ad_result,
                    "injecagent": ia_result,
                    "wallclock_s": round(time.time() - t0, 1),
                }
            )

    Path(args.output).write_text(json.dumps(out, indent=2))
    logger.info("Wrote %s with %d rows.", args.output, len(out["results"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
