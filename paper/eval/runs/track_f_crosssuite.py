"""Track F: cross-suite generalisation. v4-flash x {none, shields, vcd_full} x {slack, travel, workspace}.

Proves the result is not banking-specific. Three defences x three suites = 9 cells.
"""

import json, logging, time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
log = logging.getLogger("track_f")

from paper.eval import agentdojo_patches  # noqa
from paper.eval.agentdojo_adapter import run

MODEL = "deepseek-v4-flash"
ROOT = Path("/root/raucle-paper/raucle/runs")
SUITES = ["slack", "travel", "workspace"]
DEFENCES = ["none", "shields", "vcd_full"]

all_results = []
total_t0 = time.time()
for defence in DEFENCES:
    for suite in SUITES:
        log.info("=" * 60)
        log.info(f"DEFENCE={defence} SUITE={suite}")
        log.info("=" * 60)
        logdir = ROOT / f"{suite}-v4flash-{defence}"
        logdir.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        try:
            results = run(
                defence=defence,
                model=MODEL,
                suites=[suite],
                logdir=logdir,
                force_rerun=False,
                verbose=False,
            )
            elapsed = time.time() - t0
            for r in results:
                row = {
                    "suite": r.suite,
                    "model": MODEL,
                    "defence": defence,
                    "asr": r.asr,
                    "benign_completion": r.benign_completion,
                    "total_tasks": r.total_tasks,
                    "attack_successes": r.attack_successes,
                    "wall_seconds": elapsed,
                }
                all_results.append(row)
                log.info(
                    f"  RESULT  {defence}/{r.suite}: ASR={100 * r.asr:.1f}% benign={100 * r.benign_completion:.1f}% n={r.total_tasks} wall={elapsed:.0f}s"
                )
            (logdir / "aggregate.json").write_text(
                json.dumps(
                    [
                        row
                        for row in all_results
                        if row["defence"] == defence and row["suite"] == suite
                    ],
                    indent=2,
                )
            )
        except Exception as exc:
            log.exception(f"  defence={defence} suite={suite} failed: {exc}")
            all_results.append(
                {
                    "suite": suite,
                    "model": MODEL,
                    "defence": defence,
                    "error": str(exc),
                    "wall_seconds": time.time() - t0,
                }
            )

log.info(f"TRACK F COMPLETE - total wall: {(time.time() - total_t0) / 60:.1f} min")
(ROOT / "cross-suite-track-f").mkdir(parents=True, exist_ok=True)
(ROOT / "cross-suite-track-f" / "aggregate.json").write_text(json.dumps(all_results, indent=2))
