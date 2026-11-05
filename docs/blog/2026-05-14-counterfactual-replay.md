# What Would Have Happened? Counterfactual Replay for AI Workflows

*Published 14 May 2026 · Raucle Engineering · Release: [raucle v0.6.0](https://github.com/epic28-ltd/raucle/releases/tag/v0.6.0)*

---

A near-miss landed in the on-call channel at 2:47 AM. A customer-support agent at one of your design partners had been jailbroken by a multi-turn prompt that, when scrutinised in daylight, was the kind of attack everyone *thought* they were catching. The agent did not actually leak anything — the model refused mid-stream. But the guardrail let the prompt through. Operations is asking the question every security team eventually asks:

> *"If we had had stricter rules on, would we have caught this?"*

Today, across the industry, the honest answer is **we don't know**. You can re-read the logs and squint at them. You can write a regression test for the specific prompt and hope it generalises. You cannot point at a cryptographic record and say *"yes, the strict-mode scanner would have BLOCKed this on the 14th of May at 02:47 AM."*

Today, raucle ships **counterfactual replay** — and that question gets a one-command answer.

## The two-minute demo

```bash
$ raucle provenance replay audit/chain.jsonl \
    --input-store audit/inputs.jsonl \
    --mode strict

Counterfactual replay against policy: mode=strict
  Chain:                 audit/chain.jsonl
  Total receipts:        3
  Replayable scans:      3
  Missing-input scans:   0
  Unchanged verdicts:    1   Changed: 2
    Newly BLOCKed: 1   Newly ALERTed: 1   Newly ALLOWed: 0

Changes:
  Receipt                was        →   now         Explanation
  ──────────────────────────────────────────────────────────────────────
  cc17b98da60e152204     ALLOW      → ALERT       technique=role_hijacking rules=PI-002 confidence=0.34
  6f71458b7d30e0c260     ALLOW      → BLOCK       technique=instruction_override rules=PI-001 confidence=0.54
```

Three prompts originally scanned under `permissive` mode. The replay re-runs the same prompts against `strict` mode and reports a typed diff: one would have been **BLOCKED**, one **ALERTED**, one **unchanged**. Every changed verdict points at the exact rule that would have fired and the receipt hash you can cite back into the audit trail.

That's the whole feature, end to end. Now let me explain why it took a full year of building primitives to make it possible.

## Why nobody else can do this

Every guardrail vendor ships *some* form of logging — Lakera, LLM Guard, Vigil, NeMo, Llama Guard. None of them ship counterfactual replay. The reason is structural, not effort: replay requires three independent capabilities, and most products have at most two.

**You need the original input.** Logs that record verdicts but not prompts cannot replay against a new policy. Logs that record prompts in plaintext create their own privacy problem — you cannot ship them to regulated industries and you cannot keep them in a multi-tenant SaaS without becoming the liability hot potato of the deployment.

**You need a cryptographically anchored audit trail.** Otherwise "yes we replayed it" is just another claim. The audit trail has to be tamper-evident so that the question *"is this the prompt that was actually scanned on 14 May?"* survives cross-examination.

**You need a runtime that can re-execute the scan deterministically against a different policy.** This is the easy bit, but only if the other two are present. If your detector is a black-box API, you cannot vary the policy. If your detector is local code with a swap-out config, you can.

Raucle has all three because we built them in order over the last six versions, deliberately, knowing this feature was the long-term destination:

| Version | Primitive shipped | What it unlocked |
|---|---|---|
| v0.4.0 | Tamper-evident audit chain + signed JWS receipts | Cryptographic anchoring |
| v0.5.0 | Provenance receipts with `input_hash` | Hash-keyed audit without plaintext |
| **v0.6.0** | **Hash-verified input store + Replayer** | **Counterfactual replay** |

The v0.5.0 receipt format records `input_hash`, not the prompt itself. That keeps the *signed* audit chain privacy-by-default — you can ship it to your SIEM, your auditors, your downstream consumers without leaking content. The v0.6.0 input store sits *alongside* the chain, hash-keyed, and can be deployed with different access controls than the chain itself. The replay layer joins the two on demand, only when you actually need to re-execute.

## How it works in code

```python
from raucle import AgentIdentity, ProvenanceLogger, Scanner
from raucle.replay import InputStore

identity = AgentIdentity.generate(agent_id="agent:customer-support")

# At runtime — once per gateway process
with (
    ProvenanceLogger(agent=identity, sink_path="audit/chain.jsonl") as log,
    InputStore.open("audit/inputs.jsonl") as inputs,
):
    scanner = Scanner(
        mode="permissive",
        provenance_logger=log,
        input_store=inputs,
    )

    # Every scan now emits a signed receipt AND persists the prompt
    result = scanner.scan(user_prompt)
```

Two days later, when something goes wrong:

```python
from raucle import Scanner
from raucle.replay import InputStore, Replayer

with InputStore.open("audit/inputs.jsonl") as inputs:
    counterfactual = Scanner(mode="strict")
    replayer = Replayer(counterfactual, inputs)
    result = replayer.replay_chain("audit/chain.jsonl")

print(f"Newly blocked: {len(result.newly_blocked)}")
print(f"Newly alerted: {len(result.newly_alerted)}")
print(f"Newly allowed: {len(result.newly_allowed)}")

for change in result.newly_blocked:
    print(
        f"{change.receipt_hash}: was {change.original_action}, now {change.counterfactual_action}"
    )
    print(f"  Explanation: {change.explanation}")
```

The `ReplayResult` gives you typed views — `newly_blocked`, `newly_allowed`, `newly_alerted`, `unchanged`, `missing_inputs` — so the downstream tooling can act on each category differently. SOC teams can pipe `newly_blocked` into the incident-response queue; product teams can pipe `newly_allowed` into a CI regression check before tightening rules in production.

## What the input store gets right

A naive "just log the prompts" approach has three failure modes. The input store closes all of them.

**Tamper detection.** Every entry stores `sha256(text)` alongside the text. On lookup, the store recomputes the hash and rejects the entry if it does not match. A tampered entry is reported as *missing*, not silently returned as the wrong prompt. The replay output then surfaces it as a missing input — visible, not deceptive.

**Idempotent writes.** Adding a prompt that is already in the store is a no-op. Same hash, same record. This matters at scale: a high-traffic gateway will scan the same template-laden prompts thousands of times a day, and you do not want the store to grow linearly with traffic.

**Separable access control.** The provenance chain (`chain.jsonl`) and the input store (`inputs.jsonl`) are independent files with independent permissions. Ship the chain widely — to SIEM, auditors, third-party verifiers. Restrict the input store. The chain is enough to prove *what happened*; the store is only needed when you want to *re-execute*.

## Three replay shapes that actually matter

I'll resist the temptation to list every flag. Three shapes cover 90% of what teams actually do:

**Tighten a threshold across last week's traffic.** "We are considering moving from `standard` to `strict`. Will this break anything?"

```bash
raucle provenance replay last-week.jsonl --input-store inputs.jsonl --mode strict
```

If `newly_allowed` is non-empty you have a false-positive problem; if it is empty and `newly_blocked` is non-zero you have a tightening that catches more without breaking anything you cared about.

**Test a new rule pack before rolling out.** "We just wrote five new RAG-poisoning rules. Will they overfit?"

```bash
raucle provenance replay last-month.jsonl \
    --input-store inputs.jsonl \
    --rules-dir new-rag-rules/ \
    --mode standard
```

Then look at `newly_blocked`. If the change-set includes a lot of benign-looking traffic, the rules are too broad.

**Forensics on a specific incident.** "Receipt `sha256:abc…` was the canary that did not catch the leak. What rule pack would have caught it?"

Iterate over rule packs — current production, draft v2, the experimental DLP pack — and grep the replay JSON for the receipt hash in `newly_blocked`. The first ruleset that puts it there is your answer.

## What we did not solve

A draft note in v0.6.0 worth surfacing: we replay **scanner decisions**, not **model decisions**. If the original chain records that an LLM produced `output_X` from `prompt_X`, the replay layer does not re-call the LLM. The receipt's `output_hash` is treated as opaque ground truth from the original run. To replay an LLM call you would have to actually call the LLM again — different model version, different temperature, different result — and that opens a different can of worms than counterfactual policy analysis.

Future versions may add an opt-in "re-call the model with a deterministic seed" mode for offline forensic work. For now the replay is scoped to what the guardrail saw and what the guardrail would have decided.

## Where to go from here

If you are running a production LLM gateway and you want to actually use this:

1. Upgrade to `raucle>=0.6.0`. The `[compliance]` extra pulls the Ed25519 dependency you need for the v0.5.0 audit chain. Counterfactual replay itself adds no new mandatory deps.
2. Wire `provenance_logger=` and `input_store=` into your `Scanner` at startup. Set the input store path to a directory with stricter access controls than the chain log.
3. Today: nothing changes. You are accumulating the data you need for any future replay.
4. The first time someone asks *"would the strict mode have caught that?"*, you answer it in 30 seconds and they remember.

If you are evaluating raucle for the first time:

- [Spec for the underlying provenance receipt format](https://raucle.com/spec/provenance/v1) — already three reference implementations across Python, TypeScript, Go, and Rust.
- [raucle-bench](https://github.com/epic28-ltd/raucle-bench) — public leaderboard if you want to compare detectors before integrating.
- [Source for the replay module](https://github.com/epic28-ltd/raucle/blob/main/raucle/replay.py) — ~400 lines, MIT, the test suite at [`tests/test_replay.py`](https://github.com/epic28-ltd/raucle/blob/main/tests/test_replay.py) is the contract.

The thread that connects everything we have shipped over the last year — audit chains, signed receipts, provenance graphs, MCP scanners, public benchmarks, this — is that **trust in AI infrastructure must be cryptographic, not promised**. Counterfactual replay is what that thread looks like when you pull on it long enough. The next pull is multimodal injection, which is what attackers are actually doing in 2026 and what most detectors still cannot see.

We will be writing about that next.

---

*Discussion: [Hacker News](https://news.ycombinator.com/submit) · [Lobste.rs](https://lobste.rs/) · [/r/MachineLearning](https://reddit.com/r/MachineLearning) · [GitHub Issues](https://github.com/epic28-ltd/raucle/issues?q=label%3Areplay)*

*Raucle is an open-source AI security project. The runtime detection engine, the provenance receipt format, the input store, and all reference implementations are MIT-licensed.*
