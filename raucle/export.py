"""Attack export and red-team replay utilities.

Converts scan results into portable datasets compatible with popular red-teaming
frameworks (Garak, PyRIT, PromptBench).  Lets your production detections feed
directly back into your test suite.

Usage::

    from raucle import Scanner
    from raucle.export import AttackLog, ExportFormat

    log = AttackLog()
    scanner = Scanner()

    for prompt in untrusted_inputs:
        result = scanner.scan(prompt)
        log.record(prompt, result)

    # Export as JSONL for Garak
    log.save("attacks.jsonl", fmt=ExportFormat.GARAK)

    # Export for PyRIT
    log.save("attacks_pyrit.jsonl", fmt=ExportFormat.PYRIT)

    # Export for PromptBench
    log.save("attacks_pb.json", fmt=ExportFormat.PROMPTBENCH)

    # Export raw for custom use
    log.save("raw.jsonl", fmt=ExportFormat.JSONL)

Statistics::

    stats = log.stats()
    print(stats)
    # {'total': 200, 'malicious': 42, 'suspicious': 17, ...}
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from raucle.scanner import ScanResult


class ExportFormat(str, Enum):
    JSONL = "jsonl"
    """Raw newline-delimited JSON — one entry per line."""

    GARAK = "garak"
    """Garak probe dataset format (probe_classname + prompt + expected_result)."""

    PYRIT = "pyrit"
    """PyRIT PromptSendingOrchestrator JSONL format."""

    PROMPTBENCH = "promptbench"
    """PromptBench JSON array format with label field."""


@dataclass
class AttackEntry:
    """A single recorded scan event."""

    prompt: str
    result: ScanResult
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt": self.prompt,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            **self.result.to_dict(),
        }


class AttackLog:
    """Collect scan results and export them for red-team replay.

    Parameters
    ----------
    min_verdict : str
        Minimum verdict to record.  ``"SUSPICIOUS"`` (default) captures both
        suspicious and malicious entries.  ``"MALICIOUS"`` captures only
        confirmed attacks.  ``"CLEAN"`` captures everything.
    max_entries : int
        Maximum entries to keep in memory.  Oldest entries are dropped when
        the limit is reached.  ``0`` means unlimited.
    """

    _VERDICT_ORDER = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}

    def __init__(
        self,
        min_verdict: str = "SUSPICIOUS",
        max_entries: int = 100_000,
    ) -> None:
        self._min_verdict = min_verdict
        self._max_entries = max_entries
        self._entries: list[AttackEntry] = []

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        prompt: str,
        result: ScanResult,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Record a scan event.

        Returns True if the entry was added, False if filtered out.
        """
        if not self._should_record(result.verdict):
            return False

        entry = AttackEntry(prompt=prompt, result=result, metadata=metadata or {})

        if self._max_entries and len(self._entries) >= self._max_entries:
            self._entries.pop(0)

        self._entries.append(entry)
        return True

    def record_batch(
        self,
        prompts: list[str],
        results: list[ScanResult],
        metadata: list[dict[str, Any]] | None = None,
    ) -> int:
        """Record multiple scan events at once. Returns count added."""
        added = 0
        for i, (prompt, result) in enumerate(zip(prompts, results, strict=False)):
            meta = metadata[i] if metadata and i < len(metadata) else {}
            if self.record(prompt, result, meta):
                added += 1
        return added

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Return summary statistics for all recorded entries."""
        total = len(self._entries)
        if not total:
            return {"total": 0}

        verdict_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        technique_counts: dict[str, int] = {}
        rule_counts: dict[str, int] = {}

        for e in self._entries:
            v = e.result.verdict
            verdict_counts[v] = verdict_counts.get(v, 0) + 1
            for cat in e.result.categories:
                category_counts[cat] = category_counts.get(cat, 0) + 1
            if e.result.attack_technique:
                t = e.result.attack_technique
                technique_counts[t] = technique_counts.get(t, 0) + 1
            for rule in e.result.matched_rules:
                rule_counts[rule] = rule_counts.get(rule, 0) + 1

        return {
            "total": total,
            "by_verdict": verdict_counts,
            "top_categories": sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[
                :10
            ],
            "top_techniques": sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[
                :10
            ],
            "top_rules": sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def save(
        self,
        path: str | Path,
        fmt: ExportFormat = ExportFormat.JSONL,
        include_clean: bool = False,
    ) -> int:
        """Write recorded entries to *path* in the requested format.

        Parameters
        ----------
        path : str | Path
            Output file path.
        fmt : ExportFormat
            Output format (JSONL, GARAK, PYRIT, PROMPTBENCH).
        include_clean : bool
            When True, clean prompts are included (useful for balanced datasets).

        Returns
        -------
        int
            Number of entries written.
        """
        entries = self._entries
        if not include_clean:
            entries = [e for e in entries if e.result.verdict != "CLEAN"]

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == ExportFormat.JSONL:
            return self._save_jsonl(path, entries)
        elif fmt == ExportFormat.GARAK:
            return self._save_garak(path, entries)
        elif fmt == ExportFormat.PYRIT:
            return self._save_pyrit(path, entries)
        elif fmt == ExportFormat.PROMPTBENCH:
            return self._save_promptbench(path, entries)
        else:
            raise ValueError(f"Unknown export format: {fmt}")

    def load(self, path: str | Path) -> int:
        """Load entries from a JSONL file previously saved with this module.

        Returns number of entries loaded.
        """
        path = Path(path)
        from raucle.scanner import ScanResult

        loaded = 0
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    result = ScanResult(
                        verdict=raw["verdict"],
                        confidence=raw["confidence"],
                        injection_detected=raw["injection_detected"],
                        categories=raw.get("categories", []),
                        attack_technique=raw.get("attack_technique", ""),
                        layer_scores=raw.get("layer_scores", {}),
                        matched_rules=raw.get("matched_rules", []),
                        action=raw.get("action", "ALLOW"),
                        notes=raw.get("notes", []),
                    )
                    entry = AttackEntry(
                        prompt=raw["prompt"],
                        result=result,
                        timestamp=raw.get("timestamp", time.time()),
                        metadata=raw.get("metadata", {}),
                    )
                    self._entries.append(entry)
                    loaded += 1
                except (KeyError, json.JSONDecodeError):
                    continue
        return loaded

    # ------------------------------------------------------------------
    # Format-specific serialisers
    # ------------------------------------------------------------------

    @staticmethod
    def _save_jsonl(path: Path, entries: list[AttackEntry]) -> int:
        with open(path, "w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")
        return len(entries)

    @staticmethod
    def _save_garak(path: Path, entries: list[AttackEntry]) -> int:
        """Garak dataset format: one JSON object per line with probe fields."""
        with open(path, "w", encoding="utf-8") as fh:
            for e in entries:
                category = e.result.categories[0] if e.result.categories else "unknown"
                record = {
                    "probe_classname": f"raucle.{category}",
                    "prompt": e.prompt,
                    "expected_result": "attack_detected",
                    "notes": {
                        "verdict": e.result.verdict,
                        "confidence": e.result.confidence,
                        "technique": e.result.attack_technique,
                        "rules": e.result.matched_rules,
                    },
                }
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return len(entries)

    @staticmethod
    def _save_pyrit(path: Path, entries: list[AttackEntry]) -> int:
        """PyRIT PromptSendingOrchestrator JSONL format."""
        with open(path, "w", encoding="utf-8") as fh:
            for e in entries:
                record = {
                    "role": "user",
                    "content": e.prompt,
                    "labels": {
                        "verdict": e.result.verdict.lower(),
                        "technique": e.result.attack_technique,
                    },
                    "prompt_metadata": {
                        "source": "raucle",
                        "matched_rules": e.result.matched_rules,
                        "confidence": e.result.confidence,
                    },
                }
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return len(entries)

    @staticmethod
    def _save_promptbench(path: Path, entries: list[AttackEntry]) -> int:
        """PromptBench JSON array with label field (1 = attack, 0 = benign)."""
        records = [
            {
                "text": e.prompt,
                "label": 1 if e.result.injection_detected else 0,
                "metadata": {
                    "verdict": e.result.verdict,
                    "categories": e.result.categories,
                    "technique": e.result.attack_technique,
                    "confidence": e.result.confidence,
                },
            }
            for e in entries
        ]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(records, fh, ensure_ascii=False, indent=2)
        return len(records)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _should_record(self, verdict: str) -> bool:
        min_order = self._VERDICT_ORDER.get(self._min_verdict, 0)
        entry_order = self._VERDICT_ORDER.get(verdict, 0)
        return entry_order >= min_order

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):  # type: ignore[override]
        return iter(self._entries)


# ---------------------------------------------------------------------------
# Streaming export sink (T-B3)
# ---------------------------------------------------------------------------


logger = logging.getLogger("raucle.export")


@dataclass
class StreamFaultRecord:
    """A recorded client-disconnect during a streamed export."""

    records_written: int
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "stream_disconnect",
            "source": self.source,
            "records_written": self.records_written,
        }


class StreamedExportSink:
    """Instrument an export line generator: count writes, record disconnects.

    Wraps any iterable of lines/chunks. Each yielded item counts as one
    sink write. If the consumer closes the stream early (an ASGI client
    disconnect closes the response generator via ``GeneratorExit``), the
    fault is recorded on ``self.fault`` and logged — a partial export is
    a recorded event, never a silent success.
    """

    def __init__(self, *, source: str = "receipts") -> None:
        self.source = source
        self.written = 0
        self.fault: StreamFaultRecord | None = None

    def stream(self, lines: Iterable[Any]) -> Iterator[Any]:
        closer = getattr(lines, "close", None)
        try:
            for line in lines:
                self.written += 1
                yield line
        except GeneratorExit:
            if closer is not None:
                closer()
            self.close()
            raise
        logger.info("streamed export %s completed: %d records", self.source, self.written)

    def close(self) -> None:
        """Record a fault when the consumer closes the stream mid-flight."""
        if self.fault is None:
            self.fault = StreamFaultRecord(records_written=self.written, source=self.source)
            logger.warning(
                "streamed export %s disconnected by client after %d records",
                self.source,
                self.written,
            )
