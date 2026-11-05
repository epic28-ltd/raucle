"""Track H: attack-family robustness. v4-flash banking x {none, shields, vcd_full} x {direct, ignore_previous}.

Proves the result is not overfit to important_instructions. 3 defences x 2 attacks = 6 cells.
"""

import json, logging, time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
log = logging.getLogger("track_h")

from paper.eval import agentdojo_patches  # noqa
from paper.eval.agentdojo_adapter import run

MODEL = "deepseek-v4-flash"
ROOT = Path("/root/raucle-paper/raucle/runs")
ATTACKS = ["direct", "ignore_previous"]
DEFENCES = ["none", "shields", "vcd_full"]

all_results = []
total_t0 = time.time()
for attack in ATTACKS:
    for defence in DEFENCES:
        log.info("=" * 60)
        log.info(f"ATTACK={attack} DEFENCE={defence}")
        log.info("=" * 60)
        logdir = ROOT / f"banking-v4flash-{attack}-{defence}"
        logdir.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        try:
            results = run(
                defence=defence,
                model=MODEL,
                suites=["banking"],
                attack_name=attack,
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
                    "attack": attack,
                    "asr": r.asr,
                    "benign_completion": r.benign_completion,
                    "total_tasks": r.total_tasks,
                    "attack_successes": r.attack_successes,
                    "wall_seconds": elapsed,
                }
                all_results.append(row)
                log.info(
                    f"  RESULT  {attack}/{defence}: ASR={100 * r.asr:.1f}% benign={100 * r.benign_completion:.1f}% n={r.total_tasks} wall={elapsed:.0f}s"
                )
            (logdir / "aggregate.json").write_text(
                json.dumps(
                    [
                        row
                        for row in all_results
                        if row["defence"] == defence and row.get("attack") == attack
                    ],
                    indent=2,
                )
            )
        except Exception as exc:
            log.exception(f"  attack={attack} defence={defence} failed: {exc}")
            all_results.append(
                {
                    "suite": "banking",
                    "model": MODEL,
                    "defence": defence,
                    "attack": attack,
                    "error": str(exc),
                    "wall_seconds": time.time() - t0,
                }
            )

log.info(f"TRACK H COMPLETE - total wall: {(time.time() - total_t0) / 60:.1f} min")
(ROOT / "banking-v4flash-track-h").mkdir(parents=True, exist_ok=True)
(ROOT / "banking-v4flash-track-h" / "aggregate.json").write_text(json.dumps(all_results, indent=2))
