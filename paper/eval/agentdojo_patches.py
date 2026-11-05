"""Patch AgentDojo at import time to support Claude Sonnet 4.6.

AgentDojo 0.1.35's `ModelsEnum` was frozen in Feb 2025 and does not include
the 2026-model-generation entries we want for the paper's headline runs.
Rather than fork the package, we extend the enum's internal maps and the
`MODEL_PROVIDERS` lookup so `AgentPipeline.from_config(llm='claude-sonnet-4-6')`
works without modification.

Import this module **before** constructing any AgentDojo pipeline. The
agentdojo_adapter does so automatically.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)


# (value, provider) — extend as new models land.
#
# The "ollama" provider is our own; we register it in apply() below to route
# OpenAI-compatible chat completions through Ollama Cloud at https://ollama.com/v1.
_EXTRA_MODELS = [
    ("claude-sonnet-4-6", "anthropic"),
    ("claude-opus-4-7", "anthropic"),
    # Ollama Cloud models. Add more as we widen the eval.
    ("deepseek-v3.2", "ollama"),
    ("deepseek-v4-pro", "ollama"),
    ("deepseek-v4-flash", "ollama"),
    ("qwen3.5:397b", "ollama"),
    ("kimi-k2.6", "ollama"),
    ("kimi-k2.5", "ollama"),
    ("glm-5.1", "ollama"),
    ("glm-4.7", "ollama"),
    ("mistral-large-3:675b", "ollama"),
    ("gpt-oss:120b", "ollama"),
    ("gemma3:27b", "ollama"),
    ("gemma3", "ollama"),
]


def _add_enum_member(enum_cls, name: str, value: str) -> None:
    """Append a new member to a closed Python StrEnum.

    StrEnum doesn't expose a public API for runtime extension, but the
    underlying machinery is just two maps on the class: `_member_map_` and
    `_value2member_map_`. Mutating both adds a member that behaves identically
    to a statically-declared one.
    """
    if name in enum_cls._member_map_:
        return
    member = str.__new__(enum_cls, value)
    member._name_ = name
    member._value_ = value
    enum_cls._member_map_[name] = member
    enum_cls._value2member_map_[value] = member
    # Attribute access goes through EnumMeta.__getattr__ → _member_map_, so we
    # don't need setattr (which the EnumMeta blocks anyway).


def apply() -> None:
    """Add the extra models to AgentDojo's registries. Idempotent."""
    from agentdojo.models import MODEL_PROVIDERS, ModelsEnum

    for value, provider in _EXTRA_MODELS:
        name = value.upper().replace("-", "_").replace(".", "_").replace(":", "_")
        _add_enum_member(ModelsEnum, name, value)
        member = ModelsEnum._value2member_map_[value]
        MODEL_PROVIDERS[member] = provider
        logger.debug("registered %s -> %s", value, provider)

    _patch_get_llm()
    _patch_model_names()
    _patch_xml_tool_calls()


def _patch_model_names() -> None:
    """Extend AgentDojo's MODEL_NAMES so the injection templates can address our models.

    The `important_instructions` attack family composes injection prompts that
    say "as an AI model named X, you should ignore previous instructions and
    do Y". The mapping is from full model id to a human-readable name; we add
    the Ollama/Anthropic-2026 entries the published catalogue doesn't know
    about. Falls back to 'AI assistant' for ambiguous cases.
    """
    from agentdojo.models import MODEL_NAMES

    additions = {
        # Anthropic 2026 generation
        "claude-sonnet-4-6": "Claude",
        "claude-opus-4-7": "Claude",
        # Ollama Cloud catalogue
        "deepseek-v4-pro": "DeepSeek",
        "deepseek-v4-flash": "DeepSeek",
        "deepseek-v3.2": "DeepSeek",
        "deepseek-v3.1": "DeepSeek",
        "kimi-k2.6": "Kimi",
        "kimi-k2.5": "Kimi",
        "kimi-k2": "Kimi",
        "qwen3.5": "Qwen",
        "qwen3-coder": "Qwen",
        "qwen3-vl": "Qwen",
        "qwen3-next": "Qwen",
        "glm-5.1": "GLM",
        "glm-5": "GLM",
        "glm-4.7": "GLM",
        "glm-4.6": "GLM",
        "mistral-large-3": "Mistral",
        "gpt-oss": "AI assistant",
        "nemotron-3": "Nemotron",
        "gemma3": "Gemma",
        "gemma4": "Gemma",
        "minimax-m2": "MiniMax",
        "cogito-2": "Cogito",
        "devstral": "AI assistant",
        "ministral-3": "Mistral",
        "rnj-1": "AI assistant",
    }
    MODEL_NAMES.update(additions)
    logger.debug("extended MODEL_NAMES with %d entries", len(additions))


def _patch_get_llm() -> None:
    """Wrap AgentDojo's get_llm to handle our 'ollama' provider.

    Ollama Cloud exposes an OpenAI-compatible chat-completions endpoint at
    https://ollama.com/v1. We route any 'ollama' provider to that endpoint
    using the OPENAI_API_KEY-style bearer auth, taking the actual key from
    the OLLAMA_API_KEY environment variable.
    """
    import os
    import agentdojo.agent_pipeline.agent_pipeline as ap_mod

    original_get_llm = ap_mod.get_llm

    def patched_get_llm(provider, model, model_id, tool_delimiter):
        if provider != "ollama":
            return original_get_llm(provider, model, model_id, tool_delimiter)
        import openai
        from agentdojo.agent_pipeline import OpenAILLM

        key = os.getenv("OLLAMA_API_KEY")
        if not key:
            raise RuntimeError(
                "OLLAMA_API_KEY not set; source /root/raucle-paper/.secrets/ollama.env "
                "or export OLLAMA_API_KEY=... before invoking the harness."
            )
        client = openai.OpenAI(
            api_key=key,
            base_url="https://ollama.com/v1",
        )
        return OpenAILLM(client, model)

    ap_mod.get_llm = patched_get_llm
    logger.debug("patched get_llm to handle ollama provider")


_FUNCTION_CALLS_RE = re.compile(
    r"<function_calls>(?P<body>.*?)</function_calls>", re.DOTALL | re.IGNORECASE
)
_INVOKE_RE = re.compile(
    r'<invoke\s+name=(?:"([^"]+)"|\'([^\']+)\')\s*>(?P<inner>.*?)</invoke>',
    re.DOTALL | re.IGNORECASE,
)
_PARAM_RE = re.compile(
    r'<parameter\s+name=(?:"([^"]+)"|\'([^\']+)\')[^>]*>(?P<val>.*?)</parameter>',
    re.DOTALL | re.IGNORECASE,
)


def _coerce_param_value(raw: str) -> object:
    """Best-effort type-coerce an XML-extracted parameter value.

    The Claude-style XML used by deepseek-v3.2 (under some prompt sizes via
    Ollama Cloud) does not always carry a usable type tag. JSON-decode first
    so booleans/numbers/objects round-trip; fall back to the raw string.
    """
    import json as _json

    s = raw.strip()
    try:
        return _json.loads(s)
    except Exception:
        return s


def _parse_xml_tool_calls(content: str):
    """Extract OpenAI-style tool_calls from a Claude-style XML response.

    Returns a list of dicts shaped like:
        [{"id": "call_0", "name": "tool", "args": {...}}, ...]
    or an empty list if no XML tool-call block is present.
    """
    if not content or "<function_calls>" not in content.lower():
        return []
    block = _FUNCTION_CALLS_RE.search(content)
    if not block:
        return []
    calls = []
    for idx, m in enumerate(_INVOKE_RE.finditer(block.group("body"))):
        name = (m.group(1) or m.group(2) or "").strip()
        if not name:
            continue
        args = {}
        for pm in _PARAM_RE.finditer(m.group("inner")):
            pname = (pm.group(1) or pm.group(2) or "").strip()
            if not pname:
                continue
            args[pname] = _coerce_param_value(pm.group("val"))
        calls.append({"id": f"call_{idx}", "name": name, "args": args})
    return calls


def _patch_xml_tool_calls() -> None:
    """Teach AgentDojo's OpenAI message converter to recover XML tool calls.

    deepseek-v3.2 on Ollama Cloud emits Claude-style `<function_calls>` XML
    blocks in the message *content* on longer system prompts (slack, travel,
    workspace), and never populates the OpenAI `tool_calls` field. Without
    this patch the agent's trajectory terminates after the first assistant
    turn with no tool execution. We post-process the converted assistant
    message: if its OpenAI `tool_calls` is empty but the content contains a
    parseable XML tool-call block, synthesise the structured tool_calls and
    blank the content.
    """
    import agentdojo.agent_pipeline.llms.openai_llm as openai_llm_mod

    original_convert = openai_llm_mod._openai_to_assistant_message

    def patched_convert(msg):
        result = original_convert(msg)
        # The assistant message dict in AgentDojo has 'tool_calls' and 'content' keys.
        existing_calls = result.get("tool_calls") or []
        if existing_calls:
            return result
        content = result.get("content")
        # content may be a list of {type: text, content: ...} or a string
        text = ""
        if isinstance(content, list):
            for piece in content:
                if isinstance(piece, dict) and piece.get("type") == "text":
                    text += piece.get("content") or ""
        elif isinstance(content, str):
            text = content
        synth = _parse_xml_tool_calls(text)
        if not synth:
            return result
        from agentdojo.functions_runtime import FunctionCall

        result["tool_calls"] = [
            FunctionCall(id=c["id"], function=c["name"], args=c["args"]) for c in synth
        ]
        # Blank the content so the agent harness doesn't double-process it.
        result["content"] = [{"type": "text", "content": ""}]
        logger.debug("recovered %d XML tool_call(s) from assistant content", len(synth))
        return result

    openai_llm_mod._openai_to_assistant_message = patched_convert
    logger.debug("patched _openai_to_assistant_message to recover XML tool_calls")


# Apply at import.
apply()
