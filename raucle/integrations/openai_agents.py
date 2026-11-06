"""raucle guardrails for the OpenAI Agents SDK (``openai-agents`` >= 0.1).

The OpenAI Agents SDK runs *guardrails* — user-supplied checks executed
before the model call (input guardrails) or before the agent's output is
delivered (output guardrails) — and trips a wire when the check fails.
This module adapts raucle's :class:`~raucle.scanner.Scanner` (prompt-
injection / jailbreak / exfiltration detection) to that contract:

- :func:`input_guardrail` scans the user prompt crossing into the agent.
- :func:`output_guardrail` scans the agent's final output.

Both emit a signed receipt for every scan when an audit sink is supplied
(whether clean or not — a clean scan you cannot evidence is worthless),
fail-closed: a scanner exception trips the wire rather than passing the
payload through.

Quick start
-----------

.. code-block:: python

    from agents import Agent, Runner
    from raucle.scanner import Scanner
    from raucle.integrations.openai_agents import (
        input_guardrail,
        output_guardrail,
    )

    scanner = Scanner()
    agent = Agent(
        name="assistant",
        input_guardrails=[input_guardrail(scanner)],
        output_guardrails=[output_guardrail(scanner)],
    )
    await Runner.run(agent, "hello world")
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any

from raucle.audit import HashChainSink, NullSink
from raucle.scanner import Scanner

logger = logging.getLogger(__name__)

try:  # pragma: no cover - import-time check
    from agents import GuardrailFunctionOutput, InputGuardrail, OutputGuardrail

    _HAS_OPENAI_AGENTS = True
except ImportError:  # narrowed by _require_sdk() at call time
    GuardrailFunctionOutput = InputGuardrail = OutputGuardrail = None  # type: ignore[assignment]
    _HAS_OPENAI_AGENTS = False

__all__ = ["has_openai_agents", "input_guardrail", "output_guardrail"]


def has_openai_agents() -> bool:
    """Whether the ``openai-agents`` package is importable."""
    return _HAS_OPENAI_AGENTS


def _require_sdk() -> None:
    if not _HAS_OPENAI_AGENTS:
        raise RuntimeError(
            "openai_agents guardrails require the 'openai-agents' package. "
            "Install with: pip install 'openai-agents'"
        )


def _receipt(
    *, stage: str, text_hash: str, verdict: str, action: str, agent_id: str
) -> dict[str, Any]:
    return {
        "kind": "guardrail_receipt",
        "agent_id": agent_id,
        "framework": "openai-agents",
        "stage": stage,
        "input_hash": text_hash,
        "verdict": verdict,
        "action": action,
    }


async def _scan_and_receipt(
    scanner: Scanner,
    sink: HashChainSink | NullSink,
    text: str,
    *,
    stage: str,
    agent_id: str,
) -> tuple[Any, bool]:
    """Scan ``text`` (raising through on scanner failure = fail-closed),
    append a receipt, and return the (ScanResult, tripwire) pair."""
    try:
        result = await asyncio.to_thread(scanner.scan, text)
    except Exception:
        # Fail-closed: an unusable guardrail must never pass traffic.
        logger.exception("raucle OpenAI-Agents guardrail scan failed (%s)", stage)
        raise
    try:
        await asyncio.to_thread(
            sink.append,
            _receipt(
                stage=stage,
                text_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                verdict=result.verdict,
                action=result.action,
                agent_id=agent_id,
            ),
        )
    except Exception:
        logger.exception("failed to append raucle guardrail receipt")
        raise
    tripwire = getattr(result, "action", "ALLOW") == "BLOCK"
    return result, tripwire


def _extract_text(payload: Any) -> str:
    """The guardrail callable receives a plain string (input guardrail) or
    the agent's output object (output guardrail) — coerce both to text."""
    if isinstance(payload, str):
        return payload
    for attr in ("output", "input", "message", "text"):
        value = getattr(payload, attr, None)
        if isinstance(value, str):
            return value
    return str(payload)


def input_guardrail(
    scanner: Scanner,
    *,
    sink: HashChainSink | NullSink | None = None,
    name: str = "raucle_input_guardrail",
) -> Any:
    """Return an OpenAI Agents SDK input guardrail backed by ``scanner``.

    The returned callable has the SDK's guardrail shape
    ``(ctx, agent, input) -> GuardrailFunctionOutput``; the tripwire fires
    on any scan action of ``BLOCK``.
    """
    _require_sdk()
    assert GuardrailFunctionOutput is not None and InputGuardrail is not None  # _require_sdk
    audit_sink: HashChainSink | NullSink = sink if sink is not None else NullSink()

    async def _guardrail(ctx: Any, agent: Any, prompt: Any) -> Any:
        result, tripwire = await _scan_and_receipt(
            scanner,
            audit_sink,
            _extract_text(prompt),
            stage="input",
            agent_id=getattr(agent, "name", "") or "",
        )
        return GuardrailFunctionOutput(
            output_info={
                "verdict": result.verdict,
                "categories": list(result.categories),
                "confidence": result.confidence,
            },
            tripwire_triggered=tripwire,
        )

    _guardrail.guardrail_name = name
    # The SDK is guaranteed importable here (_require_sdk raised otherwise),
    # so the plain-callable fallback branch is dead code and is not kept.
    return InputGuardrail(guardrail_function=_guardrail, name=name, run_in_parallel=False)


def output_guardrail(
    scanner: Scanner,
    *,
    sink: HashChainSink | NullSink | None = None,
    name: str = "raucle_output_guardrail",
) -> Any:
    """Return an OpenAI Agents SDK output guardrail backed by ``scanner``.

    Identical contract to :func:`input_guardrail` but runs the scanner's
    output-side detection over the agent's final output object.
    """
    _require_sdk()
    assert GuardrailFunctionOutput is not None and OutputGuardrail is not None  # _require_sdk
    audit_sink: HashChainSink | NullSink = sink if sink is not None else NullSink()

    async def _guardrail(ctx: Any, agent: Any, output: Any) -> Any:
        result, tripwire = await _scan_and_receipt(
            scanner,
            audit_sink,
            _extract_text(output),
            stage="output",
            agent_id=getattr(agent, "name", "") or "",
        )
        return GuardrailFunctionOutput(
            output_info={
                "verdict": result.verdict,
                "categories": list(result.categories),
                "confidence": result.confidence,
            },
            tripwire_triggered=tripwire,
        )

    _guardrail.guardrail_name = name
    return OutputGuardrail(guardrail_function=_guardrail, name=name)
