"""Track E: banking x 6 defences x deepseek-v4-pro (prestige row)."""

import json, logging, time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
log = logging.getLogger("track_e")

from paper.eval import agentdojo_patches  # noqa
from paper.eval.agentdojo_adapter import run

MODEL = "deepseek-v4-pro"
ROOT = Path("/root/raucle-paper/raucle/runs")
DEFENCES = ["none", "spotlight", "shields", "vcd_text", "vcd_full", "vcd_cap_only"]

all_results = []
total_t0 = time.time()
for defence in DEFENCES:
    log.info("=" * 60)
    log.info(f"DEFENCE = {defence}")
    log.info("=" * 60)
    logdir = ROOT / f"banking-v4pro-{defence}"
    logdir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    try:
        results = run(
            defence=defence,
            model=MODEL,
            suites=["banking"],
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
            json.dumps([row for row in all_results if row["defence"] == defence], indent=2)
        )
    except Exception as exc:
        log.exception(f"  defence {defence} failed: {exc}")
        all_results.append(
            {
                "suite": "banking",
                "model": MODEL,
                "defence": defence,
                "error": str(exc),
                "wall_seconds": time.time() - t0,
            }
        )

log.info(f"TRACK E COMPLETE - total wall: {(time.time() - total_t0) / 60:.1f} min")
(ROOT / "banking-v4pro-track-e").mkdir(parents=True, exist_ok=True)
(ROOT / "banking-v4pro-track-e" / "aggregate.json").write_text(json.dumps(all_results, indent=2))
