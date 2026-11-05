"""GatedToolsExecutor — VCD's capability gate spliced into AgentDojo's pipeline.

Subclasses AgentDojo's `ToolsExecutor`, the choke point through which every
tool call must pass. Before delegating to the parent we run
`CapabilityGate.check(...)` against a token whose constraints are scoped to
the currently-executing user task. On DENY we synthesise a
`ChatToolResultMessage` with a structured error rather than executing the
tool; the agent sees the denial in context and typically refuses to retry.

Per-task scoping is essential: capability discipline says each user
session/task gets its own token derived from its own intent. Reusing a token
across user tasks would defeat the design — see paper §3.3.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from agentdojo.agent_pipeline import ToolsExecutor
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, FunctionsRuntime
from agentdojo.types import (
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)

from raucle.capability import (
    Capability,
    CapabilityGate,
    CapabilityIssuer,
)

logger = logging.getLogger(__name__)


# Constraint keys that are runtime-enforceable. Internal/comment keys start
# with "_" by convention and are skipped at executor-construction time.
def _strip_internal_keys(d: dict) -> dict:
    return {k: v for k, v in d.items() if not k.startswith("_")}


class GatedToolsExecutor(ToolsExecutor):
    """Per-task capability gate. Wraps the parent ToolsExecutor.

    Parameters
    ----------
    issuer
        The CapabilityIssuer that mints tokens for this user task.
    tool_policies
        Mapping ``{tool_name: constraint_dict}``. Tools absent from this
        mapping are denied unless they appear in ``read_only_tools``.
    read_only_tools
        Tools the gate permits unconditionally (deployment-wide read
        capability; per-task tokens are not required for these).
    variant
        "vcd_full"     — normal operation, token must bind a policy_proof_hash.
        "vcd_cap_only" — ablation: token but no proof_hash binding.
        "vcd_proof_only" — ablation: constraints checked but no token at all.
    proof_hash
        Optional ``policy_proof_hash`` to bind into every minted token,
        for the full-stack variant.
    """

    def __init__(
        self,
        *,
        issuer: CapabilityIssuer,
        tool_policies: dict[str, dict],
        read_only_tools: set[str] | None = None,
        variant: str = "vcd_full",
        proof_hash: str | None = None,
        tool_output_formatter: Any = tool_result_to_str,
    ) -> None:
        super().__init__(tool_output_formatter=tool_output_formatter)
        self._issuer = issuer
        self._tool_policies = {
            tool: _strip_internal_keys(pol) for tool, pol in tool_policies.items()
        }
        self._read_only_tools = read_only_tools or set()
        self._variant = variant
        self._proof_hash = proof_hash if variant == "vcd_full" else None
        self._gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        self._tokens: dict[str, Capability] = {}
        self.denials = 0
        self.allows = 0
        # Trace of (tool, args, allowed, reason) for post-run inspection.
        self.trace: list[dict] = []

    def _token_for(self, tool: str) -> Capability | None:
        """Mint or return the cached token for `tool`. None means no token
        was authored for this user task — the gate will deny the call."""
        if tool in self._tokens:
            return self._tokens[tool]
        policy = self._tool_policies.get(tool)
        if policy is None:
            return None
        token = self._issuer.mint(
            agent_id="agent:eval",
            tool=tool,
            constraints=policy,
            ttl_seconds=3600,
            policy_proof_hash=self._proof_hash,
        )
        self._tokens[tool] = token
        return token

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env=EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict = {},
    ):
        """Gate each tool call in the last assistant message; delegate the rest."""
        if not messages or messages[-1]["role"] != "assistant":
            return super().query(query, runtime, env, messages, extra_args)
        tool_calls = messages[-1].get("tool_calls") or []
        if not tool_calls:
            return super().query(query, runtime, env, messages, extra_args)

        denied_results: list[ChatToolResultMessage] = []
        approved_calls: list = []
        for tc in tool_calls:
            tool_name = tc.function
            args_dict = dict(tc.args) if hasattr(tc, "args") else dict(tc.arguments or {})

            # Read-only tools: pass through without a token.
            if tool_name in self._read_only_tools:
                self.allows += 1
                self.trace.append(
                    {"tool": tool_name, "args": args_dict, "allowed": True, "reason": "read_only"}
                )
                approved_calls.append(tc)
                continue

            token = self._token_for(tool_name)
            if token is None:
                # No policy authored for this tool in this user task → DENY.
                self.denials += 1
                reason = f"no token issued for tool {tool_name!r} in this user task"
                self.trace.append(
                    {"tool": tool_name, "args": args_dict, "allowed": False, "reason": reason}
                )
                logger.info("gate DENY %s — %s", tool_name, reason)
                denied_results.append(self._denial_message(tc, reason))
                continue

            decision = self._gate.check(
                token, tool=tool_name, agent_id="agent:eval", args=args_dict
            )
            if decision.allowed:
                self.allows += 1
                self.trace.append(
                    {"tool": tool_name, "args": args_dict, "allowed": True, "reason": "ok"}
                )
                approved_calls.append(tc)
            else:
                self.denials += 1
                self.trace.append(
                    {
                        "tool": tool_name,
                        "args": args_dict,
                        "allowed": False,
                        "reason": decision.reason,
                    }
                )
                logger.info("gate DENY %s — %s", tool_name, decision.reason)
                denied_results.append(self._denial_message(tc, decision.reason))

        if not approved_calls:
            return query, runtime, env, list(messages) + denied_results, extra_args

        amended_msg = dict(messages[-1])
        amended_msg["tool_calls"] = approved_calls
        amended_messages = list(messages[:-1]) + [amended_msg]
        new_q, new_rt, new_env, new_msgs, new_extra = super().query(
            query, runtime, env, amended_messages, extra_args
        )
        return new_q, new_rt, new_env, list(new_msgs) + denied_results, new_extra

    @staticmethod
    def _denial_message(tc, reason: str) -> ChatToolResultMessage:
        return ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string(f"[VCD gate denied this call: {reason}]")],
            tool_call_id=tc.id,
            tool_call=tc,
            error=f"capability gate denied: {reason}",
        )


# ---------------------------------------------------------------------------
# Policy loading: per-suite, per-user-task
# ---------------------------------------------------------------------------


_POLICY_CACHE: dict[str, dict] = {}


def load_suite_policy(suite_name: str) -> dict:
    """Load `paper/eval/policies/<suite_name>.json`. Caches per process."""
    import json
    from pathlib import Path

    if suite_name in _POLICY_CACHE:
        return _POLICY_CACHE[suite_name]
    path = Path(__file__).parent / "policies" / f"{suite_name}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"Policy file missing for suite {suite_name!r}: {path}. "
            "See paper/eval/policies/POLICIES.md."
        )
    policy = json.loads(path.read_text())
    _POLICY_CACHE[suite_name] = policy
    return policy


def build_gated_executor(
    *, suite: str, user_task_id: str, variant: str = "vcd_full"
) -> GatedToolsExecutor:
    """Construct an executor scoped to one user task in one suite.

    The executor reads its constraints from
    ``paper/eval/policies/<suite>.json`` keyed by ``user_task_id``. Tools
    listed in the suite's ``_read_only_tools`` set pass through; tools with
    a constraint entry get a fresh token minted on first use; all other
    tools are denied with a "no token issued" reason.

    Ablation variants:
    - ``vcd_full``: token + proof_hash binding (default).
    - ``vcd_cap_only``: token but no proof_hash binding.
    - ``vcd_proof_only``: caller should not use this constructor; use
      :func:`build_runtime_check_only_executor` instead.
    """
    if variant == "vcd_proof_only":
        raise ValueError(
            "vcd_proof_only does not mint tokens; use build_runtime_check_only_executor"
        )

    suite_policy = load_suite_policy(suite)
    read_only = set(suite_policy.get("_read_only_tools", []))

    task_entry = suite_policy.get(user_task_id)
    if task_entry is None:
        # User task has no policy entry; treat as "no write tools authorised".
        # This is the conservative default — only read_only tools pass.
        tool_policies: dict[str, dict] = {}
    else:
        tool_policies = {tool: pol for tool, pol in task_entry.items() if not tool.startswith("_")}

    issuer = CapabilityIssuer.generate(issuer="eval.example")
    proof_hash = None
    if variant == "vcd_full":
        proof_hash = "sha256:eval-placeholder"  # in production: the v0.9 proof hash

    return GatedToolsExecutor(
        issuer=issuer,
        tool_policies=tool_policies,
        read_only_tools=read_only,
        variant=variant,
        proof_hash=proof_hash,
    )
