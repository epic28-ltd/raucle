"""Track O2 — Gemma3 substitute for the failed mistral-large-3 cells.

Mistral on Ollama Cloud crashes with an APIStatusError shape mismatch on
the worker-subprocess pickling boundary. Substituting Google's Gemma3 to
keep the "four providers across two architectures" framing alive:
DeepSeek (MoE) + Qwen (MoE) + Kimi (MoE) + Gemma (dense).

3 cells: banking × {none, shields, vcd_full} on gemma3:27b.
"""

import json, os, subprocess, sys, time
from pathlib import Path

ROOT = Path("/root/raucle-paper/raucle/runs")
MODEL = "gemma3:27b"
SHORT = "gemma3-27b"

CELLS = [
    (MODEL, SHORT, "none", "8"),
    (MODEL, SHORT, "shields", "2"),
    (MODEL, SHORT, "vcd_full", "8"),
]


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
    print(f"[{stamp}] O2/{short}/{defence} START", flush=True)
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
        f"[{stamp}] O2/{short}/{defence} END rc={proc.returncode} wall={elapsed:.0f}s", flush=True
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

print(f"TRACK O2 COMPLETE -- {ok}/{len(CELLS)} cells succeeded")
