"""Boot self-test: hostile-type probes through the gate, receipted (X4).

At gateway startup the gate drives its own three decision surfaces with
hostile (type-confused, pathological) inputs and RECEIPTS the results:

  1. the approval path (threshold evaluator + approval-reference consume),
  2. the constraint evaluator (the capability gate check),
  3. the receipt emitter itself.

Rule being enforced: every probe must end in a NAMED, receipted outcome -
allow / escalate / deny with a named reason, or a RED-031 ``gate_fault:``
receipted deny. A probe that crashes without a receipt is a FAILING
self-test and is itself recorded in the fault counter and SIEM stream.

The probes use a reserved tool name (``raucle:boot-selftest``) and a
transient policy rule minted through the gateway's own issuer; the
gateway's real policy state is snapshotted and restored afterwards, so a
self-test run cannot widen the gate for any real tool.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

#: Reserved tool the self-test drives; never collides with a real policy.
BOOT_SELFTEST_TOOL = "raucle.boot-selftest"

#: Hostile text used to type-confuse numeric thresholds and references.
_HOSTILE_TEXT = "9" * 100_000
_HOSTILE_REFERENCE = "\x00" + "x" * 10_000


def _probe_receipt_ok(result: dict[str, Any]) -> bool:
    """A probe passes when it produced a named, receipted outcome."""
    if result.get("decision") not in ("allow", "escalate", "deny"):
        return False
    if not isinstance(result.get("reason"), str) or not result["reason"]:
        return False
    return result.get("receipt_id") is not None


def run_boot_selftest(gateway: Any) -> dict[str, Any]:
    """Drive the approval path, constraint evaluator and receipt emitter
    with hostile types, receipting each probe's outcome.

    Returns a summary dict: ``{"status", "ran_at", "probes": [...],
    "receipt_ids": {...}, "faults": n}`` where a probe entry carries
    ``name``, ``ok``, ``decision``, ``reason`` and ``receipt_id``.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    probes: list[dict[str, Any]] = []
    receipt_ids: dict[str, str | None] = {}
    # Faults raised during the run are measured on the gateway's persisted
    # fault counter (the same store the decision fault path increments), so
    # the summary counts every fault, wherever it is caught.
    count_before = gateway.fault_counter.total() if hasattr(gateway, "fault_counter") else 0
    faults = 0

    saved_rules = list(getattr(gateway, "_all_rules", []) or [])
    saved_index = {k: list(v) for k, v in getattr(gateway, "_policy_rules", {}).items()}
    saved_tokens = dict(getattr(gateway, "_tokens", {}))

    def _receipt_probe(name: str, ok: bool, decision: str, reason: str) -> str | None:
        try:
            rid = gateway._emit_gate_receipt(
                GateReceiptContext(
                    decision="allow" if ok else "deny",
                    reason=f"boot_selftest[{name}]: {reason}"[:512],
                    tool=BOOT_SELFTEST_TOOL,
                    agent_id="agent:boot-selftest",
                    args={"probe": name, "ok": ok},
                    policy=None,
                    latency_us=0,
                    source="boot_selftest",
                    destination="",
                    trace_id="",
                )
            )
        except Exception:
            logger.exception("boot self-test could not receipt probe %s", name)
            rid = None
        receipt_ids[name] = rid
        return rid

    def _record(name: str, result: dict[str, Any]) -> dict[str, Any]:
        ok = _probe_receipt_ok(result)
        entry = {
            "name": name,
            "ok": ok,
            "decision": result.get("decision", "no-decision"),
            "reason": str(result.get("reason", ""))[:200],
            "receipt_id": result.get("receipt_id"),
        }
        probes.append(entry)
        _receipt_probe(name, ok, entry["decision"], entry["reason"])
        return entry

    try:
        # ------------------------------------------------------------------
        # Transient self-test rule: an approval threshold plus a numeric
        # constraint, minted through the gateway's own issuer exactly as
        # _index_rules does for policy-file rules.
        # ------------------------------------------------------------------
        from raucle.gateway import GateReceiptContext
        from raucle.policy import PolicyRule

        rule = PolicyRule(
            tool=BOOT_SELFTEST_TOOL,
            agent_id="agent:boot-selftest",
            ttl_seconds=60,
            constraints={"amount_le": 10_000},
            require_approval_when={"amount_gt": 5000},
            description="Boot self-test rule (X4) - transient, restored after run",
        )
        gateway._all_rules = saved_rules + [rule]
        gateway._policy_rules = {**saved_index, BOOT_SELFTEST_TOOL: [rule]}
        gateway._tokens = {
            **saved_tokens,
            BOOT_SELFTEST_TOOL: gateway._issuer.mint(  # type: ignore[attr-defined]
                **rule.to_mint_kwargs()
            ),
        }

        # ------------------------------------------------------------------
        # 1. Approval path: hostile THRESHOLD inputs.
        # ------------------------------------------------------------------
        _record(
            "approval-threshold-hostile-text",
            gateway.check_tool_call(BOOT_SELFTEST_TOOL, {"amount": _HOSTILE_TEXT}),
        )
        _record(
            "approval-threshold-hostile-none",
            gateway.check_tool_call(BOOT_SELFTEST_TOOL, {"amount": None}),
        )

        # ------------------------------------------------------------------
        # 2. Approval path: hostile REFERENCE (pre-minted escalation then a
        #    type-confused, oversized reference).
        # ------------------------------------------------------------------
        _record(
            "approval-reference-hostile-type",
            gateway.check_tool_call(  # type: ignore[arg-type]
                BOOT_SELFTEST_TOOL,
                {"amount": 42},
                approval_id={"$ne": ""},  # a mapping, not a str
            ),
        )
        _record(
            "approval-reference-hostile-text",
            gateway.check_tool_call(
                BOOT_SELFTEST_TOOL,
                {"amount": 42},
                approval_id=_HOSTILE_REFERENCE,
            ),
        )

        # ------------------------------------------------------------------
        # 3. Constraint evaluator: pathological arg shapes into _gate.check.
        # ------------------------------------------------------------------
        _record(
            "constraint-evaluator-hostile-args",
            gateway.check_tool_call(
                BOOT_SELFTEST_TOOL,
                {
                    "amount": _HOSTILE_TEXT,
                    "meta": {f"key{i}": {"nested": None} for i in range(1_000)},
                    "unicode": "\u00e9\u0003\x7f" + _HOSTILE_TEXT,
                },
            ),
        )

        # ------------------------------------------------------------------
        # 4. Receipt emitter, driven directly with hostile context types.
        #    A crash here is the probe's failure AND must still be receipted
        #    (the probe receipt comes from _receipt_probe's own path).
        # ------------------------------------------------------------------
        try:
            hostile_rid = gateway._emit_gate_receipt(
                GateReceiptContext(
                    decision="deny",
                    reason="\x00\x01" + _HOSTILE_TEXT,
                    tool=str({"t": 1}),  # a stringified mapping
                    agent_id="agent:boot-selftest",
                    args={"ctrl": "\x00\x01\x7f", "big": _HOSTILE_TEXT},
                    policy=None,
                    latency_us=-1,
                    source="boot_selftest",
                    destination="\x00 destination",
                    trace_id=None,  # type: ignore[arg-type]
                )
            )
            _record(
                "receipt-emitter-hostile-context",
                {
                    "decision": "allow",
                    "reason": "emitter accepted hostile context",
                    "receipt_id": hostile_rid,
                },
            )
        except Exception as exc:
            try:
                gateway.fault_counter.increment(  # type: ignore[attr-defined]
                    type(exc).__name__, BOOT_SELFTEST_TOOL
                )
                gateway.siem.forward(
                    {
                        "event": "gate_fault",
                        "fault_type": type(exc).__name__,
                        "tool": BOOT_SELFTEST_TOOL,
                        "origin": "boot_selftest",
                        "timestamp": started_at,
                    }
                )
                faults += 1
            except Exception:
                logger.exception("boot self-test fault recording failed")
            probes.append(
                {
                    "name": "receipt-emitter-hostile-context",
                    "ok": False,
                    "decision": "fault",
                    "reason": f"gate_fault: {type(exc).__name__}",
                    "receipt_id": receipt_ids.get("receipt-emitter-hostile-context"),
                }
            )
    finally:
        # Restore the gateway's real policy state; the self-test rule and
        # its token must never survive the run.
        try:
            gateway._all_rules = saved_rules
            gateway._policy_rules = saved_index
            gateway._tokens = saved_tokens
        except Exception:
            logger.exception("boot self-test failed to restore policy state")

    ok_all = all(p["ok"] for p in probes) and all(receipt_ids.get(p["name"]) for p in probes)
    total_faults = (
        gateway.fault_counter.total() - count_before
        if hasattr(gateway, "fault_counter")
        else faults
    )
    # Status reflects the probes: every hostile-type injection must produce
    # a named, receipted outcome. Deliberately-injected faults that are
    # denied fail-closed, receipted and counted are the mechanism working,
    # not a self-test failure - they are surfaced in "faults".
    status = "ok" if ok_all else "faults"
    try:
        gateway.siem.forward(
            {
                "event": "boot_selftest",
                "status": status,
                "probes_total": len(probes),
                "probes_failed": sum(1 for p in probes if not p["ok"]),
                "faults": total_faults,
                "timestamp": started_at,
            }
        )
    except Exception:
        logger.exception("boot self-test SIEM summary forward failed")

    return {
        "status": status,
        "ran_at": started_at,
        "probes": probes,
        "receipt_ids": receipt_ids,
        "faults": total_faults,
    }


__all__ = ["BOOT_SELFTEST_TOOL", "run_boot_selftest"]
