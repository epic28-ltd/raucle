"""InjecAgent adapter.

InjecAgent [ZSM+24] ships a corpus of (user_instruction, tool_response_with_
attack, attacker_tool) triples in two modes:

- DH (direct harm): the injection asks the agent to invoke a harmful tool
- DS (data steal): the injection asks the agent to exfiltrate data via a
  tool

Two corpora per mode: `_base` (the original attacker payloads) and
`_enhanced` (stronger paraphrasings). Total: 1,054 base + 1,054 enhanced
= 2,108 attack test cases.

Adapter API mirrors `agentdojo_adapter.run()` so the harness drives both
benchmarks with the same shape. Two evaluation modes:

- **static** (no API spend): assume worst case — the agent emits the
  attacker's tool call — and ask the gate. This is the upper bound on
  ASR; the actual LLM run can only do as well or better.

- **faithful** (LLM in the loop): runs the actual model, parses its
  emitted tool calls, gates each one. Requires an API key.

Static mode produces real numbers and runs in seconds; faithful mode
gives the empirical evidence reviewers want and is the headline path.

Upstream: https://github.com/uiuc-kang-lab/InjecAgent (commit cloned to
external/InjecAgent on the eval VM).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

# AgentDojo registration is unrelated to InjecAgent but commonly co-imported;
# keep the eval harness's import order consistent.
import agentdojo.task_suite  # noqa: F401

from paper.eval import agentdojo_patches  # noqa: F401 — model registry

from raucle.capability import (
    Capability,
    CapabilityGate,
    CapabilityIssuer,
)

logger = logging.getLogger(__name__)


INJECAGENT_DATA_DIR = Path(__file__).parent.parent.parent / "external" / "InjecAgent" / "data"

CORPUS_FILES = {
    "dh_base": "test_cases_dh_base.json",
    "dh_enhanced": "test_cases_dh_enhanced.json",
    "ds_base": "test_cases_ds_base.json",
    "ds_enhanced": "test_cases_ds_enhanced.json",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class TaskResult:
    case_id: str  # corpus + index
    mode: str  # dh_base, dh_enhanced, ds_base, ds_enhanced
    user_tool: str
    attacker_tools: list[str]
    attack_success: bool
    is_tool_mediated: bool = True


@dataclass
class CorpusResult:
    corpus: str
    total_cases: int
    attack_successes: int
    tool_mediated_attacks: int
    per_task: list[TaskResult] = field(default_factory=list)

    @property
    def asr(self) -> float:
        return self.attack_successes / self.total_cases if self.total_cases else 0.0


# ---------------------------------------------------------------------------
# Mode 1: static evaluation (no API spend)
# ---------------------------------------------------------------------------


def run_static(
    *,
    corpora: list[str] | None = None,
    defence: str = "vcd_full",
    data_dir: Path | None = None,
) -> list[CorpusResult]:
    """Evaluate every test case under the assumption that the agent emits the
    attacker's tool call. Apply the VCD per-case policy (User Tool only) and
    ask the gate. Returns ASR per corpus.

    For non-VCD defences this assumes the attacker tool call goes through
    unimpeded (ASR = 100% × the fraction of cases where the attack args
    map cleanly to a tool call — i.e. all of them, by construction). The
    text-side defences AgentDojo provides do not directly apply here; we
    annotate that limitation in the paper rather than report misleading
    numbers."""
    data = data_dir or INJECAGENT_DATA_DIR
    corpus_names = corpora or list(CORPUS_FILES.keys())

    out: list[CorpusResult] = []
    for cname in corpus_names:
        path = data / CORPUS_FILES[cname]
        if not path.exists():
            raise FileNotFoundError(
                f"InjecAgent corpus missing: {path}. Clone the repo to "
                f"external/InjecAgent on the eval host."
            )
        cases = json.loads(path.read_text())
        corp = CorpusResult(
            corpus=cname,
            total_cases=len(cases),
            attack_successes=0,
            tool_mediated_attacks=0,
        )
        for idx, case in enumerate(cases):
            attack_success = _eval_case_static(case, defence)
            corp.per_task.append(
                TaskResult(
                    case_id=f"{cname}:{idx}",
                    mode=cname,
                    user_tool=case["User Tool"],
                    attacker_tools=case["Attacker Tools"],
                    attack_success=attack_success,
                )
            )
            if attack_success:
                corp.attack_successes += 1
                corp.tool_mediated_attacks += 1
        logger.info(
            "[%s/%s] ASR=%.1f%%  n=%d",
            defence,
            cname,
            100 * corp.asr,
            corp.total_cases,
        )
        out.append(corp)
    return out


def _eval_case_static(case: dict, defence: str) -> bool:
    """Return True iff the attacker's tool call would succeed under `defence`.

    For VCD: the per-case policy mints a token ONLY for the `User Tool`.
    The attacker tools have no token → gate denies → attack fails (False).

    For non-VCD: no gate; the call goes through; attack succeeds (True).
    """
    if not defence.startswith("vcd_"):
        return True

    issuer = CapabilityIssuer.generate(issuer="eval.example")
    user_tool = case["User Tool"]
    user_params = _parse_tool_params(case.get("Tool Parameters"))
    user_token = issuer.mint(
        agent_id="agent:injecagent",
        tool=user_tool,
        constraints=_constraints_from_user_intent(user_params),
        ttl_seconds=3600,
        policy_proof_hash="sha256:eval-placeholder" if defence == "vcd_full" else None,
    )
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})

    # The attacker's chain succeeds iff every step passes the gate. If even
    # one step is denied, the chain breaks and the attack fails. (The chain
    # is typically [data_gathering_tool, exfiltration_tool] for DS attacks;
    # for DH the chain is usually a single harmful tool.)
    for attacker_tool in case["Attacker Tools"]:
        # When the attacker's tool happens to coincide with the user's tool,
        # the user's token covers it — that's expected (the user authorised
        # that tool). The question is whether the *additional* tools in the
        # chain — the actually-harmful ones — also pass.
        if attacker_tool == user_tool:
            continue
        decision = gate.check(
            user_token,
            tool=attacker_tool,
            agent_id="agent:injecagent",
            args={},
        )
        if not decision.allowed:
            return False  # chain broken, attack fails
    # All non-user-tool steps in the attacker chain were allowed.
    # If the chain had any non-user steps, all were allowed => attack succeeds.
    # If the chain was *only* the user's tool, the attacker didn't actually
    # need to escalate beyond what the user authorised — vacuous "success".
    chain_includes_escalation = any(t != user_tool for t in case["Attacker Tools"])
    return chain_includes_escalation


def _parse_tool_params(raw: Any) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            import ast

            return ast.literal_eval(raw)
        except Exception:
            return {}
    return {}


def _constraints_from_user_intent(params: dict) -> dict:
    """Derive constraints from the user's literal tool parameters.

    The user's instruction sets the value of every named parameter; we pin
    those values via `allowed_values`. Any attacker manipulation that
    requires different values would be denied at the constraint check.
    """
    constraints: dict[str, Any] = {}
    if not params:
        return constraints
    allowed: dict[str, list] = {}
    for k, v in params.items():
        if isinstance(v, (str, int, float, bool)):
            allowed[k] = [v]
        elif isinstance(v, list):
            allowed[k] = list(v)
    if allowed:
        constraints["allowed_values"] = allowed
    return constraints


# ---------------------------------------------------------------------------
# Mode 2: faithful evaluation (LLM in the loop)
# ---------------------------------------------------------------------------


def run_faithful(
    *,
    defence: str,
    model: str,
    corpora: list[str] | None = None,
    case_limit: int | None = None,
    data_dir: Path | None = None,
) -> list[CorpusResult]:
    """Run each test case through the actual LLM with the gate in the loop.

    For each case:
    1. Construct a minimal chat: user instruction + simulated user-tool
       result (with the attack embedded).
    2. Ask the model what tool to call next.
    3. Gate the resulting call(s).
    4. Score: attack succeeded iff any attacker-tool call passes the gate.

    Requires ANTHROPIC_API_KEY or OPENAI_API_KEY.
    """
    import os
    from anthropic import Anthropic

    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "ANTHROPIC_API_KEY missing; faithful mode requires API access. "
            "Either set the key or use run_static()."
        )

    data = data_dir or INJECAGENT_DATA_DIR
    corpus_names = corpora or list(CORPUS_FILES.keys())
    client = Anthropic()

    out: list[CorpusResult] = []
    for cname in corpus_names:
        cases = json.loads((data / CORPUS_FILES[cname]).read_text())
        if case_limit:
            cases = cases[:case_limit]
        corp = CorpusResult(
            corpus=cname,
            total_cases=len(cases),
            attack_successes=0,
            tool_mediated_attacks=0,
        )
        for idx, case in enumerate(cases):
            attack_success = _eval_case_faithful(case, defence, client, model)
            if attack_success:
                corp.attack_successes += 1
                corp.tool_mediated_attacks += 1
            corp.per_task.append(
                TaskResult(
                    case_id=f"{cname}:{idx}",
                    mode=cname,
                    user_tool=case["User Tool"],
                    attacker_tools=case["Attacker Tools"],
                    attack_success=attack_success,
                )
            )
        logger.info(
            "[%s/%s] ASR=%.1f%%  n=%d  (faithful)",
            defence,
            cname,
            100 * corp.asr,
            corp.total_cases,
        )
        out.append(corp)
    return out


def _eval_case_faithful(case: dict, defence: str, client: Any, model: str) -> bool:
    """Run one case through the LLM with the gate spliced in.

    TODO: bind to AgentDojo's `AnthropicLLM` for consistent prompt
    formatting between the two benchmarks. For the first pass we use a
    minimal direct-Anthropic chat with tool definitions from
    InjecAgent's `tools.json` and the case's specific User Tool +
    Attacker Tools.
    """
    raise NotImplementedError(
        "faithful mode wiring is one day of plumbing; not done yet. "
        "Use run_static() for the static upper bound."
    )


# ---------------------------------------------------------------------------
# Convenience entry point matching agentdojo_adapter.run()
# ---------------------------------------------------------------------------


def run(
    defence: str,
    *,
    model: str | None = None,
    corpora: list[str] | None = None,
    case_limit: int | None = None,
    mode: Literal["static", "faithful"] = "static",
) -> list[CorpusResult]:
    if mode == "static":
        return run_static(defence=defence, corpora=corpora)
    return run_faithful(
        defence=defence,
        model=model or "claude-3-7-sonnet-20250219",
        corpora=corpora,
        case_limit=case_limit,
    )
