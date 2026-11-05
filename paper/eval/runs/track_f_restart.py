"""Track F restart: only the 5 missing cells, each in a fresh subprocess.

The original Track F died OOM (workspace-shields, 21GB anon-rss) because
DeBERTa stays resident across cells and 8-way parallel workers multiply
memory. Fix: one subprocess per cell so memory resets, and RAUCLE_PARALLEL=2
for shields cells specifically.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/root/raucle-paper/raucle/runs")

# (suite, defence, parallel) -- shields gets RAUCLE_PARALLEL=2 (memory-bound), others 8
CELLS = [
    ("slack", "shields", "2"),
    ("slack", "vcd_full", "8"),
    ("travel", "vcd_full", "8"),
    ("workspace", "shields", "2"),
    ("workspace", "vcd_full", "8"),
]


def run_cell(suite, defence, parallel):
    logdir = ROOT / f"{suite}-v4flash-{defence}"
    logdir.mkdir(parents=True, exist_ok=True)
    code = (
        "import json, time, os\n"
        f"os.environ['RAUCLE_PARALLEL'] = '{parallel}'\n"
        "from paper.eval import agentdojo_patches  # noqa\n"
        "from paper.eval.agentdojo_adapter import run\n"
        "from pathlib import Path\n"
        f"logdir = Path('{logdir}')\n"
        "t0 = time.time()\n"
        f"results = run(defence='{defence}', model='deepseek-v4-flash', suites=['{suite}'],\n"
        "              logdir=logdir, force_rerun=False, verbose=False)\n"
        "elapsed = time.time() - t0\n"
        "rows = []\n"
        "for r in results:\n"
        "    rows.append({\n"
        "        'suite': r.suite, 'model': 'deepseek-v4-flash',\n"
        f"        'defence': '{defence}',\n"
        "        'asr': r.asr, 'benign_completion': r.benign_completion,\n"
        "        'total_tasks': r.total_tasks, 'attack_successes': r.attack_successes,\n"
        "        'wall_seconds': elapsed,\n"
        "    })\n"
        "(logdir / 'aggregate.json').write_text(json.dumps(rows, indent=2))\n"
        "print('CELL DONE', rows)\n"
    )
    stamp = time.strftime("%H:%M:%S")
    print(f"[{stamp}] CELL START suite={suite} defence={defence} parallel={parallel}", flush=True)
    t0 = time.time()
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd="/root/raucle-paper/raucle",
        env={**os.environ, "PYTHONPATH": "."},
        capture_output=True,
        text=True,
    )
    elapsed = time.time() - t0
    stamp = time.strftime("%H:%M:%S")
    print(f"[{stamp}] CELL END rc={proc.returncode} wall={elapsed:.0f}s", flush=True)
    if proc.returncode != 0:
        print("STDERR TAIL:", proc.stderr[-2000:], flush=True)
    else:
        print("STDOUT TAIL:", proc.stdout[-400:], flush=True)
    return proc.returncode == 0


ok_count = 0
for suite, defence, parallel in CELLS:
    if run_cell(suite, defence, parallel):
        ok_count += 1

print(f"TRACK F RESTART COMPLETE -- {ok_count}/{len(CELLS)} cells succeeded")
