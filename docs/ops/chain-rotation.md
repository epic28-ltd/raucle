# Chain rotation: operator runbook

The gateway's boot maps the whole audit chain and the receipt-store segment
index into memory (about two times the file size in resident memory).
Long-running deployments grow both stores, and a boot that does not fit the
box's memory is killed by the kernel (observed live on 18 November 2026 on
demo.raucle.com: gateway-audit.jsonl at 12.2 GB and index.sqlite at 15 GB,
23.4 GB resident, three kernel kills, the demo serving 502 until rotation).
This runbook is the operator response, and `rotate-chain` is the safe way to
execute it.

## When to rotate

- The boot memory preflight warns or refuses: the gateway states the projected
  memory and the exact command. Act on it before the next restart (a restart
  on the same stores will be OOM-killed again).
- The demo/traffic chain has grown past your box's comfortable boot budget.
- You are archiving a demo or evaluation period on purpose (the archive stays
  verifiable offline for ever; rotation is never data loss).

## What rotate-chain does

1. Refuses safely unless it owns three facts: a readable audit chain, a
   readable segment store, and an operator identity (`--operator` or
   `RAUCLE_OPERATOR`) plus a reason.
2. Archives the current stores (audit chain and receipt-store segments) under
   the same directory with a `.archived-<date>` suffix. It never deletes.
   Idempotent safety: an archive for today already existing is a named
   refusal, not a second move.
3. Mints a rotation receipt (a new link in the chain of record): what
   rotated, the archived files' digests, the operator identity, the reason,
   timestamps. Prior links are never rewritten.
4. Verifies the fresh stores boot.

## After rotation

- The live chain starts fresh; the archived chains stay on the box and remain
  offline-verifiable by any third party (they are hash-chained and signed
  exactly like the live one).
- Re-verify the deployment as you would after any restart: container health,
  `/health`, admin surface, then the public URL.
- The archived files still count against disk. Keep them while verification
  needs them; deleting an archive is an owner's explicit action and the
  receipt chain records exactly what was archived, so a deleted archive is
  always visible as a gap named in the rotation receipt's digests.

## The incident this encodes (18 November 2026, worked example)

demo.raucle.com served 502 after a routine deploy: the boot ballooned to
23.4 GB resident on a 24 GB box (the chain had crossed the wall between
restarts; the previous container had been up for six days, so the wall was
invisible until a rebuild). Two independent crash signatures followed: the
kernel OOM kill at boot, and receipt_index refusing to migrate on a
half-migrated store left by an OOM death mid-`ALTER` (see the receipt-index
operational note in the ops documentation). Rotation of both stores restored
service in minutes, with every archived byte kept on the box.
