"""Persistent fault counter (X4 / RED-031 extension).

RED-031 made every gateway-internal fault a *receipted* deny. X4 adds the
evidence half: every fault is COUNTED and those counts are persisted, so a
restart cannot launder the record and an operator can query how many faults
the gate hit, by fault type and by tool.

Design mirrors the other persisted stores (RED-038): counts live in a small
JSON file, written atomically (tmp + rename) under a lock, and reloaded on
construction. A corrupt or missing file starts empty rather than refusing to
boot - the counter is evidence plumbing, never a launch blocker.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class FaultCounter:
    """Persisted per-type, per-tool counter for receipted gate faults."""

    def __init__(self, persist_path: str | Path | None = None) -> None:
        self._lock = threading.Lock()
        self._persist_path = Path(persist_path) if persist_path else None
        self._counters: dict[str, dict[str, int]] = {}
        self._per_tool: dict[str, dict[str, dict[str, int]]] = {}
        if self._persist_path is not None:
            self._load()

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def increment(self, fault_type: str, tool: str = "") -> int:
        """Count one fault of *fault_type* (the exception TYPE name).

        Returns the new total for that (fault_type, tool) pair.
        """
        fault_type = str(fault_type) or "Unknown"
        tool = str(tool) if isinstance(tool, str) else "Unknown"
        with self._lock:
            slot = self._counters.setdefault(fault_type, {})
            slot["total"] = slot.get("total", 0) + 1
            if tool:
                tools = self._per_tool.setdefault(fault_type, {})
                tools.setdefault(tool, {})
                tools[tool]["count"] = tools[tool].get("count", 0) + 1
            self._persist()
            return slot["total"]

    def counts(self) -> dict[str, Any]:
        """Queryable snapshot: per-fault-type totals and per-tool breakdown."""
        with self._lock:
            return {
                "by_type": {k: dict(v) for k, v in sorted(self._counters.items())},
                "by_type_and_tool": {
                    k: {t: dict(c) for t, c in sorted(v.items())}
                    for k, v in sorted(self._per_tool.items())
                },
                "total": sum(s.get("total", 0) for s in self._counters.values()),
            }

    def total(self) -> int:
        with self._lock:
            return sum(s.get("total", 0) for s in self._counters.values())

    # ------------------------------------------------------------------
    # Persistence (RED-038 pattern: write, reload, compare observable state)
    # ------------------------------------------------------------------

    def _persist(self) -> None:
        if self._persist_path is None:
            return
        payload = {
            "counters": self._counters,
            "per_tool": self._per_tool,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(self._persist_path.parent), suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh)
                os.replace(tmp_name, self._persist_path)
            finally:
                if os.path.exists(tmp_name):
                    with contextlib.suppress(OSError):
                        os.unlink(tmp_name)
        except OSError:
            logger.exception("failed to persist fault counter to %s", self._persist_path)

    def _load(self) -> None:
        assert self._persist_path is not None
        if not self._persist_path.exists():
            return
        try:
            data = json.loads(self._persist_path.read_text(encoding="utf-8"))
            counters = data.get("counters", {})
            per_tool = data.get("per_tool", {})
            if isinstance(counters, dict) and isinstance(per_tool, dict):
                self._counters = {k: v for k, v in counters.items() if isinstance(v, dict)}
                self._per_tool = {k: v for k, v in per_tool.items() if isinstance(v, dict)}
        except (OSError, ValueError):
            logger.exception("corrupt fault counter at %s; starting empty", self._persist_path)


__all__ = ["FaultCounter"]
