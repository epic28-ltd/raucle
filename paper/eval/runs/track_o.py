"""Track O — multi-family banking row.

§6.2 currently covers three generations of one open-weight family
(deepseek-v3.2 / v4-flash / v4-pro). To pre-empt "your evidence is one
model family" reviewer objection without waiting on Anthropic credits,
add three frontier-class models from three other providers via Ollama
Cloud:

  - qwen3.5:397b      (Alibaba, MoE)
  - kimi-k2.6         (Moonshot, MoE)
  - mistral-large-3:675b (Mistral AI, dense)

Per model: banking × {none, shields, vcd_full} = 3 cells.
Total: 9 cells. Per-cell subprocess isolation; shields at RAUCLE_PARALLEL=2.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/root/raucle-paper/raucle/runs")

CELLS = []
MODELS = ["qwen3.5:397b", "kimi-k2.6", "mistral-large-3:675b"]
for model in MODELS:
    short = model.replace(":", "_").replace(".", "")
    for defence in ["none", "shields", "vcd_full"]:
        parallel = "2" if defence == "shields" else "8"
        CELLS.append((model, short, defence, parallel))


def run_cell(model, short, defence, parallel):
    logdir = ROOT / f"banking-{short}-{defence}"
    logdir.mkdir(parents=True, exist_ok=True)

    code = (
        "import json, time, os\n"
        f"os.environ['RAUCLE_PARALLEL'] = '{parallel}'\n"
        "from paper.eval import agentdojo_patches  # noqa\n"
        "from paper.eval.agentdojo_adapter import run\n"
        "from pathlib import Path\n"
        f"logdir = Path('{logdir}')\n"
        "t0 = time.time()\n"
        f"results = run(defence='{defence}', model='{model}', suites=['banking'],\n"
        "              logdir=logdir, force_rerun=False, verbose=False)\n"
        "elapsed = time.time() - t0\n"
        "rows = []\n"
        "for r in results:\n"
        "    rows.append({\n"
        f"        'suite': r.suite, 'model': '{model}', 'defence': '{defence}',\n"
        "        'asr': r.asr, 'benign_completion': r.benign_completion,\n"
        "        'total_tasks': r.total_tasks, 'attack_successes': r.attack_successes,\n"
        "        'wall_seconds': elapsed,\n"
        "    })\n"
        "(logdir / 'aggregate.json').write_text(json.dumps(rows, indent=2))\n"
        "print('CELL DONE', rows)\n"
    )
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"[{stamp}] O/{short}/{defence} START", flush=True)
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
    print(f"[{stamp}] O/{short}/{defence} END rc={proc.returncode} wall={elapsed:.0f}s", flush=True)
    if proc.returncode != 0:
        print("STDERR TAIL:", proc.stderr[-1500:], flush=True)
    else:
        print("STDOUT TAIL:", proc.stdout[-300:], flush=True)
    return proc.returncode == 0


ok = 0
for cell in CELLS:
    if run_cell(*cell):
        ok += 1

print(f"TRACK O COMPLETE -- {ok}/{len(CELLS)} cells succeeded")
