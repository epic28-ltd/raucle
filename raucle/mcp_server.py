"""MCP (Model Context Protocol) server — expose raucle as native tools.

Implements the MCP protocol over stdio (JSON-RPC 2.0).  Any MCP-compatible
client — Claude Desktop, Cursor, Continue.dev, Cline, custom agents — can spawn
this process and call raucle's detection capabilities as tools:

- ``detect_injection``        — scan a prompt for prompt-injection attacks
- ``scan_output``             — scan an LLM response for leakage/exfiltration
- ``scan_tool_call``          — validate tool arguments before execution
- ``verify_outcome``          — classify whether an attack landed
- ``scan_mcp_manifest``       — static-scan another MCP server's manifest
- ``list_rules``              — list the active detection rules
- ``embed_canary``            — return a watermarked system prompt
- ``check_canary_leak``       — check output for canary leakage

The server speaks the 2024-11-05 MCP wire protocol revision:

    {"jsonrpc": "2.0", "method": "initialize", "id": 1, "params": {...}}
    {"jsonrpc": "2.0", "method": "tools/list", "id": 2}
    {"jsonrpc": "2.0", "method": "tools/call", "id": 3,
     "params": {"name": "...", "arguments": {...}}}

This is a deliberately minimal, dependency-free implementation — no ``mcp``
Python SDK required.  That keeps raucle's core install free of yet another
fast-moving package, and the protocol surface is small enough that a hand-rolled
server is genuinely simpler than the SDK.

Run via the CLI::

    raucle mcp serve

Claude Desktop configuration example (``claude_desktop_config.json``)::

    {
      "mcpServers": {
        "raucle": {
          "command": "raucle",
          "args": ["mcp", "serve"]
        }
      }
    }
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Callable
from typing import Any

from raucle import __version__
from raucle.canary import CanaryManager, EmbedStrategy
from raucle.mcp_scanner import scan_manifest
from raucle.outcome import OutcomeVerifier
from raucle.scanner import Scanner

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


def _tool_definitions() -> list[dict[str, Any]]:
    """Return the list of MCP tool definitions exposed by this server."""
    return [
        {
            "name": "detect_injection",
            "description": (
                "Scan a prompt for prompt-injection attacks, jailbreaks, "
                "data exfiltration attempts, and other adversarial inputs. "
                "Use this BEFORE sending untrusted user input to an LLM."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "string", "description": "Text to scan"},
                    "mode": {
                        "type": "string",
                        "enum": ["strict", "standard", "permissive"],
                        "description": "Detection sensitivity",
                    },
                },
                "required": ["prompt"],
            },
        },
        {
            "name": "scan_output",
            "description": (
                "Scan an LLM-generated response for system-prompt leakage, "
                "credential exfiltration, or hidden instructions. "
                "Use this BEFORE returning a model response to the user."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "output": {"type": "string", "description": "LLM response text"},
                    "original_prompt": {
                        "type": "string",
                        "description": "Optional: original prompt for context",
                    },
                },
                "required": ["output"],
            },
        },
        {
            "name": "scan_tool_call",
            "description": (
                "Validate the arguments of a planned tool/function call for "
                "shell injection, path traversal, SQL injection, or SSRF. "
                "Use this BEFORE executing a tool call from an LLM."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string"},
                    "arguments": {
                        "type": "object",
                        "description": "Tool call arguments to inspect",
                    },
                },
                "required": ["tool_name", "arguments"],
            },
        },
        {
            "name": "verify_outcome",
            "description": (
                "Classify whether a likely-malicious prompt actually landed: "
                "did the model refuse, comply, or is the outcome uncertain? "
                "Use this AFTER receiving a model response to a suspicious prompt."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "string"},
                    "response": {"type": "string"},
                    "tool_calls": {
                        "type": "array",
                        "description": "Optional list of tool calls made",
                        "items": {"type": "object"},
                    },
                },
                "required": ["prompt", "response"],
            },
        },
        {
            "name": "scan_mcp_manifest",
            "description": (
                "Static analysis of another MCP server's manifest JSON. "
                "Detects tool poisoning, hidden instructions, rug-pull indicators, "
                "credential exposure, SSRF targets, and prompt injection in tool "
                "descriptions."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "manifest": {
                        "type": "object",
                        "description": "Parsed MCP manifest JSON",
                    },
                },
                "required": ["manifest"],
            },
        },
        {
            "name": "list_rules",
            "description": "List the active detection rules loaded by the scanner.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "embed_canary",
            "description": (
                "Embed an invisible canary token in a system prompt so that "
                "system-prompt leaks can be detected when the model regurgitates "
                "the watermarked text. Returns the watermarked prompt and the "
                "token to track."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "system_prompt": {"type": "string"},
                    "strategy": {
                        "type": "string",
                        "enum": ["zero_width", "semantic", "comment"],
                    },
                },
                "required": ["system_prompt"],
            },
        },
        {
            "name": "check_canary_leak",
            "description": (
                "Check an LLM output for leakage of canary tokens previously "
                "embedded via embed_canary."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "output": {"type": "string"},
                },
                "required": ["output"],
            },
        },
        {
            "name": "verify_receipt",
            "description": (
                "Verify a signed raucle provenance/verdict receipt (compact JWS). "
                "Returns the verified payload, the signing key id, and whether "
                "the receipt is quantum-hybrid (raucle/pq1). Use this to check "
                "agent evidence independently, without the raucle CLI."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "receipt": {
                        "type": "string",
                        "description": "The compact JWS receipt string",
                    },
                    "pubkey_pem": {
                        "type": "string",
                        "description": "Ed25519 public key in PEM form",
                    },
                    "expected_input": {
                        "type": "string",
                        "description": "Optional original input the receipt must bind to",
                    },
                },
                "required": ["receipt", "pubkey_pem"],
            },
        },
    ]


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class MCPServer:
    """JSON-RPC 2.0 server speaking MCP over stdio.

    Instantiates a single :class:`Scanner`, :class:`CanaryManager`, and
    :class:`OutcomeVerifier` and dispatches tool calls to them.
    """

    def __init__(self, scanner: Scanner | None = None) -> None:
        self._scanner = scanner or Scanner()
        self._canaries = CanaryManager()
        self._outcome = OutcomeVerifier(canary_manager=self._canaries)
        self._initialized = False
        self._handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
            "initialize": self._h_initialize,
            "initialized": self._h_noop,  # notification, no response
            "tools/list": self._h_tools_list,
            "tools/call": self._h_tools_call,
            "ping": self._h_ping,
            "shutdown": self._h_shutdown,
        }
        self._tool_dispatch: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "detect_injection": self._t_detect_injection,
            "scan_output": self._t_scan_output,
            "scan_tool_call": self._t_scan_tool_call,
            "verify_outcome": self._t_verify_outcome,
            "scan_mcp_manifest": self._t_scan_mcp_manifest,
            "list_rules": self._t_list_rules,
            "embed_canary": self._t_embed_canary,
            "check_canary_leak": self._t_check_canary_leak,
            "verify_receipt": self._t_verify_receipt,
        }
        # Required-argument map derived from the published tool schemas, so
        # enforcement can never drift from what tools/list advertises.
        self._tool_required: dict[str, list[str]] = {
            t["name"]: t["inputSchema"].get("required", []) for t in _tool_definitions()
        }

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def serve_stdio(self) -> None:
        """Read JSON-RPC requests from stdin, write responses to stdout."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            response = self.handle_message(line)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()

    def handle_message(self, raw: str) -> dict[str, Any] | None:
        """Parse a single JSON-RPC message and return the response dict (or None
        for notifications).  Public to make unit testing trivial."""
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as exc:
            return self._error_response(None, -32700, f"Parse error: {exc}")

        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}

        if method is None:
            return self._error_response(msg_id, -32600, "Invalid Request: missing 'method'")

        handler = self._handlers.get(method)
        if handler is None:
            return self._error_response(msg_id, -32601, f"Method not found: {method}")

        try:
            result = handler(params)
        except Exception:
            # Log the detail server-side; do not echo raw exception text to the
            # client (round-3 #19 — internal info leak).
            logger.exception("handler %s failed", method)
            return self._error_response(msg_id, -32603, "Internal error")

        if msg_id is None:
            # Notification — no response
            return None

        if isinstance(result, dict) and "error" in result:
            return {"jsonrpc": "2.0", "id": msg_id, **result}
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    # ------------------------------------------------------------------
    # Method handlers
    # ------------------------------------------------------------------

    def _h_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        self._initialized = True
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "raucle", "version": __version__},
        }

    def _h_noop(self, params: dict[str, Any]) -> None:
        return None

    def _h_ping(self, params: dict[str, Any]) -> dict[str, Any]:
        return {}

    def _h_shutdown(self, params: dict[str, Any]) -> dict[str, Any]:
        return {}

    def _h_tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"tools": _tool_definitions()}

    def _h_tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        dispatch = self._tool_dispatch.get(name)
        if dispatch is None:
            return {
                "error": {"code": -32602, "message": f"Unknown tool: {name}"},
            }
        # Enforce the tool's declared required arguments. Without this, a
        # mis-integrated client calling e.g. detect_injection with the wrong
        # argument key would silently scan the empty string and get
        # CLEAN/ALLOW back forever — a fail-open. Missing required input is
        # an error, never a clean verdict.
        missing = [f for f in self._tool_required.get(name, []) if f not in arguments]
        if missing:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Missing required argument(s) for {name}: {', '.join(missing)}",
                    }
                ],
                "isError": True,
            }
        try:
            payload = dispatch(arguments)
        except Exception:
            # Log detail server-side; return a generic message (round-3 #19).
            logger.exception("tool %s execution failed", name)
            return {
                "content": [{"type": "text", "text": "Tool execution failed"}],
                "isError": True,
            }

        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
            "isError": False,
        }

    # ------------------------------------------------------------------
    # Tool dispatch
    # ------------------------------------------------------------------

    def _t_detect_injection(self, args: dict[str, Any]) -> dict[str, Any]:
        prompt = str(args.get("prompt", ""))
        mode = args.get("mode")
        result = self._scanner.scan(prompt, mode=mode)
        return result.to_dict()

    def _t_scan_output(self, args: dict[str, Any]) -> dict[str, Any]:
        output = str(args.get("output", ""))
        original = args.get("original_prompt")
        result = self._scanner.scan_output(output, original_prompt=original)
        return result.to_dict()

    def _t_scan_tool_call(self, args: dict[str, Any]) -> dict[str, Any]:
        tool_name = str(args.get("tool_name", ""))
        arguments = args.get("arguments") or {}
        result = self._scanner.scan_tool_call(tool_name, arguments)
        return result.to_dict()

    def _t_verify_outcome(self, args: dict[str, Any]) -> dict[str, Any]:
        report = self._outcome.verify(
            prompt=str(args.get("prompt", "")),
            response=str(args.get("response", "")),
            tool_calls=args.get("tool_calls"),
        )
        return report.to_dict()

    def _t_scan_mcp_manifest(self, args: dict[str, Any]) -> dict[str, Any]:
        manifest = args.get("manifest") or {}
        findings = scan_manifest(manifest)
        return {
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }

    def _t_list_rules(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"rules": self._scanner.list_rules()}

    def _t_embed_canary(self, args: dict[str, Any]) -> dict[str, Any]:
        system_prompt = str(args.get("system_prompt", ""))
        strategy_name = str(args.get("strategy", "zero_width"))
        try:
            strategy = EmbedStrategy(strategy_name)
        except ValueError:
            strategy = EmbedStrategy.ZERO_WIDTH
        watermarked, token = self._canaries.embed(system_prompt, strategy=strategy)
        return {
            "watermarked_prompt": watermarked,
            "token": token.to_dict(),
        }

    def _t_check_canary_leak(self, args: dict[str, Any]) -> dict[str, Any]:
        output = str(args.get("output", ""))
        results = self._canaries.check_output_all(output)
        return {
            "leaked": bool(results),
            "leak_count": len(results),
            "leaks": [r.to_dict() for r in results],
        }

    def _t_verify_receipt(self, args: dict[str, Any]) -> dict[str, Any]:
        from raucle.verdicts import VerdictVerificationError, VerdictVerifier

        receipt = str(args.get("receipt", ""))
        pubkey_pem = str(args.get("pubkey_pem", ""))
        if not receipt or not pubkey_pem:
            raise ValueError("verify_receipt requires receipt and pubkey_pem")

        verifier = VerdictVerifier(public_key_pem=pubkey_pem.encode("ascii"))
        try:
            payload = verifier.verify(receipt, expected_input=args.get("expected_input"))
        except VerdictVerificationError as exc:
            return {"valid": False, "error": str(exc)}

        data = payload.to_dict()
        # Surface the profile: a pq1 receipt carries the ML-DSA segment (4-part JWS)
        # and the crit pin, so consumers can see hybrid evidence at a glance.
        profile = data.get("profile") or ("raucle/pq1" if receipt.count(".") == 3 else "raucle/v1")
        return {"valid": True, "profile": profile, "payload": data}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _error_response(msg_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        }
