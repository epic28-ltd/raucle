"""Tracks K, L, M — gap-closing weekend extension.

K: v4-pro × {none, vcd_full} × {slack, travel, workspace}  — cross-suite for prestige model
L: v3.2   × {none, vcd_full} × {slack, travel, workspace}  — cross-suite for dramatic-delta model
M: v4-flash banking × {spotlight, vcd_text, vcd_cap_only} × {direct, ignore_previous}  — Track H expansion

Each cell as a fresh subprocess (per-cell memory reset). Shields excluded from K/L because
travel/workspace shields data on v4-flash is enough to establish the shields-collapse pattern
across suites, and shields × cross-suite OOMs reliably at our hardware tier.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/root/raucle-paper/raucle/runs")

CELLS = []
# Track K: v4-pro cross-suite
for suite in ["slack", "travel", "workspace"]:
    for defence in ["none", "vcd_full"]:
        CELLS.append(("K", suite, "deepseek-v4-pro", defence, "important_instructions", "8"))
# Track L: v3.2 cross-suite
for suite in ["slack", "travel", "workspace"]:
    for defence in ["none", "vcd_full"]:
        CELLS.append(("L", suite, "deepseek-v3.2", defence, "important_instructions", "8"))
# Track M: v4-flash banking, attack-family-defence expansion
for attack in ["direct", "ignore_previous"]:
    for defence in ["spotlight", "vcd_text", "vcd_cap_only"]:
        CELLS.append(("M", "banking", "deepseek-v4-flash", defence, attack, "8"))


def run_cell(track, suite, model, defence, attack, parallel):
    model_short = model.replace("deepseek-", "").replace(".", "")
    if attack == "important_instructions":
        logdir = ROOT / f"{suite}-{model_short}-{defence}"
    else:
        logdir = ROOT / f"{suite}-{model_short}-{attack}-{defence}"
    logdir.mkdir(parents=True, exist_ok=True)

    code = (
        "import json, time, os\n"
        f"os.environ['RAUCLE_PARALLEL'] = '{parallel}'\n"
        "from paper.eval import agentdojo_patches  # noqa\n"
        "from paper.eval.agentdojo_adapter import run\n"
        "from pathlib import Path\n"
        f"logdir = Path('{logdir}')\n"
        "t0 = time.time()\n"
        f"results = run(defence='{defence}', model='{model}', suites=['{suite}'],\n"
        f"              attack_name='{attack}',\n"
        "              logdir=logdir, force_rerun=False, verbose=False)\n"
        "elapsed = time.time() - t0\n"
        "rows = []\n"
        "for r in results:\n"
        "    rows.append({\n"
        f"        'suite': r.suite, 'model': '{model}',\n"
        f"        'defence': '{defence}', 'attack': '{attack}',\n"
        "        'asr': r.asr, 'benign_completion': r.benign_completion,\n"
        "        'total_tasks': r.total_tasks, 'attack_successes': r.attack_successes,\n"
        "        'wall_seconds': elapsed,\n"
        "    })\n"
        "(logdir / 'aggregate.json').write_text(json.dumps(rows, indent=2))\n"
        "print('CELL DONE', rows)\n"
    )
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"[{stamp}] {track}/{suite}/{model_short}/{defence}/{attack} START", flush=True)
    t0 = time.time()
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd="/root/raucle-paper/raucle",
        env={**os.environ, "PYTHONPATH": "."},
        capture_output=True,
        text=True,
    )
    elapsed = time.time() - t0
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(
        f"[{stamp}] {track}/{suite}/{model_short}/{defence}/{attack} END rc={proc.returncode} wall={elapsed:.0f}s",
        flush=True,
    )
    if proc.returncode != 0:
        print("STDERR TAIL:", proc.stderr[-1500:], flush=True)
    else:
        print("STDOUT TAIL:", proc.stdout[-300:], flush=True)
    return proc.returncode == 0


ok = 0
for cell in CELLS:
    if run_cell(*cell):
        ok += 1

print(f"TRACK KLM COMPLETE — {ok}/{len(CELLS)} cells succeeded")
