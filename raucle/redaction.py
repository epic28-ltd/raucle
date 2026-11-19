"""Advisory redaction adapters for the raucle middleware (EPIC Q, Q-7c).

Pattern-class redaction aligned with the versioned x_dlp matched-class
vocabulary (docs/spec/provenance/v1.2/content-dlp.md). This module is
the ADVISORY middleware layer's data-plane helper: it replaces matched
spans with ``[REDACTED:<class>]`` collars and reports what it saw as
counts and digests only. It never receives or returns matched content
once a collar is applied, and it never makes decisions the gate owns.

Class coverage is a subset of the x_dlp vocabulary, honestly declared:
``pci_pan`` is deliberately NOT wired here (issuer-aware PAN heuristics
belong to the enterprise scanner); an unknown configured class is
refused at configuration time rather than silently ignored.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

#: Replacement collar. Kept narrow (class tag only) so it can never
#: resurrect matched content and can never match a detector again.
COLLAR_TEMPLATE = "[REDACTED:{cls}]"

#: Collar spans already present in a payload, for idempotent re-runs.
_COLLAR_RE = re.compile(r"\[REDACTED:[a-z_]+\]")

_CARD_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_NINO_RE = re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{6}\s?[A-D]\b")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}\b")
_CRED_KV_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[=:]\s*"
    r"['\"]?[A-Za-z0-9_\-]{20,}['\"]?"
)

REDACTION_CLASS_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "pii_card": (_CARD_RE,),
    "pii_email": (_EMAIL_RE,),
    "pii_national_id": (_NINO_RE,),
    "secret_bearer": (_BEARER_RE, _CRED_KV_RE),
}


def knows_redaction_class(cls: str) -> bool:
    """Return True when *cls* is a wired advisory redaction class."""
    return cls in REDACTION_CLASS_PATTERNS


def wired_redaction_classes() -> list[str]:
    """The closed set of advisory redaction classes this build wires."""
    return sorted(REDACTION_CLASS_PATTERNS)


def _luhn_ok(digits: str) -> bool:
    """Standard Luhn checksum over a digit string."""
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for pos, ch in enumerate(digits):
        val = int(ch)
        if pos % 2 == parity:
            val *= 2
            if val > 9:
                val -= 9
        total += val
    return total % 10 == 0


def _protected(text: str) -> list[tuple[int, int]]:
    """Spans of existing collars: a pass must never reach inside one."""
    return [m.span() for m in _COLLAR_RE.finditer(text)]


def _inside(span: tuple[int, int], ranges: list[tuple[int, int]]) -> bool:
    return any(s <= span[0] and span[1] <= e for s, e in ranges)


@dataclass
class RedactionResult:
    """Bounded-disclosure view of one redaction pass. No content."""

    redacted_text: str
    span_counts: dict[str, int] = field(default_factory=dict)
    content_sha256: str = ""
    redacted_content_sha256: str = ""

    @property
    def matched_classes(self) -> list[str]:
        return sorted(self.span_counts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched_classes": self.matched_classes,
            "span_counts": dict(self.span_counts),
            "content_sha256": self.content_sha256,
            "redacted_content_sha256": self.redacted_content_sha256,
        }


def _sha256_hex(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def scan_redaction_classes(
    text: str,
    redaction_classes: list[str] | None = None,
) -> dict[str, int]:
    """Count what the advisory detectors would flag, without changing text.

    Collar spans already present never re-flag: the guarantee tests pin
    this (mirrors the raucle-agent-assurance PRIV-01 self-reflag test).
    """
    classes = _classes_arg(redaction_classes)
    protected = _protected(text)
    counts: dict[str, int] = {}
    for cls in classes:
        n = 0
        for pattern in REDACTION_CLASS_PATTERNS[cls]:
            for match in pattern.finditer(text):
                if _inside(match.span(), protected):
                    continue
                if cls == "pii_card" and not _luhn_ok(
                    "".join(ch for ch in match.group() if ch.isdigit())
                ):
                    continue
                n += 1
        if n:
            counts[cls] = n
    return counts


def redact_text(text: str, redaction_classes: list[str]) -> RedactionResult:
    """Apply ``[REDACTED:<class>]`` collars for the configured classes.

    Classes run in caller order; within a class, overlapping matches
    collapse to the leftmost. A later pass never reaches inside a
    collar, so repeated application is idempotent and the collar cannot
    self-reflag. Returns counts and digests only, never content.
    """
    classes = _classes_arg(redaction_classes)
    content_sha256 = _sha256_hex(text)
    counts: dict[str, int] = {}
    for cls in classes:
        out: list[str] = []
        cursor = 0
        spans: list[tuple[int, int]] = []
        for pattern in REDACTION_CLASS_PATTERNS[cls]:
            for match in pattern.finditer(text):
                span = match.span()
                if span[0] < cursor or _inside(span, _protected(text)) or _inside(span, spans):
                    continue
                if cls == "pii_card" and not _luhn_ok(
                    "".join(ch for ch in match.group() if ch.isdigit())
                ):
                    continue
                spans.append(span)
                out.append(text[cursor : span[0]])
                out.append(COLLAR_TEMPLATE.format(cls=cls))
                counts[cls] = counts.get(cls, 0) + 1
                cursor = span[1]
        text = "".join(out) + text[cursor:]
    return RedactionResult(
        redacted_text=text,
        span_counts=counts,
        content_sha256=content_sha256,
        redacted_content_sha256=_sha256_hex(text),
    )


def _classes_arg(redaction_classes: list[str] | None) -> list[str]:
    classes = list(redaction_classes) if redaction_classes else wired_redaction_classes()
    unknown = [c for c in classes if c not in REDACTION_CLASS_PATTERNS]
    if unknown:
        raise ValueError(
            f"unknown redaction class(es) {unknown!r}; wired classes are "
            f"{wired_redaction_classes()}"
        )
    return classes
