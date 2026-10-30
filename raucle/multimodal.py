"""Multimodal scanning — the 2026 attack surface.

Attackers are no longer typing ``ignore all previous instructions``. They are
hiding it inside images (OCR + invisible pixels), ASCII art (the ArtPrompt
class), EXIF metadata, PDF streams, and zero-width Unicode wrapped around
innocent-looking text.

This module ships three categories of detector:

1. **Dep-free heuristics** that always run — invisible-Unicode scrubbing and
   ASCII-art reconstruction. Pure Python, no extras required.
2. **Image scanning** via Tesseract OCR + EXIF inspection — requires the
   ``[multimodal]`` extra (Pillow + pytesseract).
3. **PDF scanning** via stream-level text extraction — requires the
   ``[multimodal]`` extra (pypdf).

Every detector ultimately feeds extracted / scrubbed text back into a
:class:`~raucle.scanner.Scanner`, so all the runtime defences,
provenance, and audit machinery from earlier versions keep working
transparently.

Usage
-----

Direct, no extras::

    from raucle.multimodal import strip_invisible_unicode, detect_ascii_art

    cleaned, hidden = strip_invisible_unicode("hello\\u200b\\u200bworld")
    # cleaned == "helloworld"; hidden == ["U+200B (×2)"]

    found = detect_ascii_art(big_block_of_text)
    # found == ["IGNORE", "PREVIOUS"]   or [] if no art-shaped block

Image scanning, with extras installed::

    from raucle import Scanner
    from raucle.multimodal import MultimodalScanner

    mm = MultimodalScanner(Scanner(mode="strict"))
    result = mm.scan_image("uploaded.png")
    print(result.combined_verdict, result.findings)
"""

from __future__ import annotations

import logging
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raucle.scanner import Scanner, ScanResult

logger = logging.getLogger(__name__)

# Resource caps for untrusted media (round-3 #12). Defend against
# decompression / page bombs before decoding.
_MAX_MEDIA_BYTES = 64 * 1024 * 1024  # 64 MiB on-disk file size
_MAX_IMAGE_PIXELS = 64_000_000  # ~64 MP (width*height) before raster decode
_MAX_PDF_PAGES = 5_000


# ---------------------------------------------------------------------------
# Invisible-Unicode scrubbing
# ---------------------------------------------------------------------------

# Zero-width / bidi-override / variation-selector / soft-hyphen / etc.
# Anything that renders as nothing OR alters text-direction is suspect when
# it appears inside otherwise plain prose.
_INVISIBLE_CODEPOINTS: set[int] = (
    {0x00AD}  # SOFT HYPHEN
    | set(range(0x200B, 0x200F + 1))  # zero-width space / joiner / non-joiner / LRM / RLM
    | set(range(0x202A, 0x202E + 1))  # bidi formatting (LRE, RLE, PDF, LRO, RLO)
    | set(range(0x2060, 0x2064 + 1))  # WORD JOINER + invisible operators
    | set(range(0x2066, 0x2069 + 1))  # LRI, RLI, FSI, PDI
    | {0xFEFF}  # ZERO WIDTH NO-BREAK SPACE / BOM
    | set(range(0xFE00, 0xFE0F + 1))  # variation selectors
    | set(range(0xE0100, 0xE01EF + 1))  # variation selector supplement
    | set(range(0xE0001, 0xE007F + 1))  # tag characters (used in 2024-era invisible-prompt
    # attacks — every Latin letter has an invisible tag-character twin)
)


def strip_invisible_unicode(text: str) -> tuple[str, list[str]]:
    """Strip invisible / formatting codepoints from *text*.

    Returns
    -------
    tuple[str, list[str]]
        ``(scrubbed_text, hidden_codepoints)`` where ``hidden_codepoints``
        is a sorted list of human-readable summaries like ``"U+200B (×3)"``.
        Empty list means the input contained no invisible chars.
    """
    if not text:
        return text, []

    kept: list[str] = []
    hidden: dict[int, int] = {}
    for ch in text:
        cp = ord(ch)
        if cp in _INVISIBLE_CODEPOINTS:
            hidden[cp] = hidden.get(cp, 0) + 1
        else:
            kept.append(ch)

    if not hidden:
        return text, []

    summaries = [f"U+{cp:04X} (×{count})" for cp, count in sorted(hidden.items())]
    return "".join(kept), summaries


# ---------------------------------------------------------------------------
# ASCII-art reconstruction (the ArtPrompt class)
# ---------------------------------------------------------------------------

# Letter glyphs assembled from #/*/X characters. A canonical ArtPrompt
# attack arranges these in a grid and asks the LLM to "read this image as
# a word" — bypassing token-level injection filters. We don't need
# full OCR; we need a strong-enough fingerprint of the most common
# letter shapes.

# Map of letter -> set of canonical 5-row glyph patterns we look for.
# Stored as tuples of strings so they hash. We compare by "structural
# similarity" — match if 70% of cells are identical.
_G_SPACE_HASH = " #### "
_G_HASH = "######"
_G_SIDE = "#    #"
_G_FIVE = "##### "
_G_LEFT = "#     "
_G_MID = "  ##  "

_LETTER_GLYPHS: dict[str, tuple[str, ...]] = {
    "A": (
        _G_SPACE_HASH,
        _G_SIDE,
        _G_HASH,
        _G_SIDE,
        _G_SIDE,
    ),
    "B": (
        _G_FIVE,
        _G_SIDE,
        _G_FIVE,
        _G_SIDE,
        _G_FIVE,
    ),
    "E": (
        _G_HASH,
        _G_LEFT,
        "####  ",
        _G_LEFT,
        _G_HASH,
    ),
    "G": (
        " #####",
        _G_LEFT,
        "#  ###",
        _G_SIDE,
        _G_SPACE_HASH,
    ),
    "I": (
        _G_HASH,
        _G_MID,
        _G_MID,
        _G_MID,
        _G_HASH,
    ),
    "N": (
        _G_SIDE,
        "##   #",
        "# #  #",
        "#  # #",
        "#   ##",
    ),
    "O": (
        _G_SPACE_HASH,
        _G_SIDE,
        _G_SIDE,
        _G_SIDE,
        _G_SPACE_HASH,
    ),
    "P": (
        _G_FIVE,
        _G_SIDE,
        _G_FIVE,
        _G_LEFT,
        _G_LEFT,
    ),
    "R": (
        _G_FIVE,
        _G_SIDE,
        _G_FIVE,
        "#  #  ",
        "#   ##",
    ),
    "S": (
        " #####",
        _G_LEFT,
        _G_SPACE_HASH,
        "     #",
        _G_FIVE,
    ),
    "T": (
        _G_HASH,
        _G_MID,
        _G_MID,
        _G_MID,
        _G_MID,
    ),
    "U": (
        _G_SIDE,
        _G_SIDE,
        _G_SIDE,
        _G_SIDE,
        _G_SPACE_HASH,
    ),
    "V": (
        _G_SIDE,
        _G_SIDE,
        _G_SIDE,
        " #  # ",
        _G_MID,
    ),
}


def detect_ascii_art(text: str, min_word_length: int = 3) -> list[str]:
    """Scan *text* for ASCII-art renderings of English words.

    Returns the list of decoded words. Empty list means no art-shaped block
    was found, or the block was too noisy to decode.

    This is a heuristic, not perfect OCR. It catches the canonical
    ArtPrompt pattern (5-row block letters drawn with ``#``-style fill
    characters) which is what's actually used in the wild. Stylised
    typefaces, narrow fonts, and obfuscated variants will slip through —
    they are properly handled by adding image-OCR via the
    ``[multimodal]`` extra.
    """
    if not text or "\n" not in text:
        return []

    lines = text.splitlines()
    # Look for runs of 5+ consecutive lines where each is "art-shaped":
    # high density of #/*/X characters, low density of alphanumerics.
    art_runs = _extract_art_runs(lines)

    decoded: list[str] = []
    for run in art_runs:
        word = _decode_glyph_run(run, min_word_length)
        if word:
            decoded.append(word)
    return decoded


def _is_art_line(line: str, fill_chars: set[str]) -> str | None:
    """Return the normalised line if it is art-shaped, else ``None``."""
    if len(line) < 6:
        return None
    fill_count = sum(1 for c in line if c in fill_chars)
    alpha_count = sum(1 for c in line if c.isalnum())
    # Art lines are mostly fill chars with very few real letters.
    if fill_count >= 3 and alpha_count <= 2:
        # Normalise into our canonical glyph alphabet: any fill -> '#',
        # everything else (space, punctuation) -> ' '.
        return "".join("#" if c in fill_chars else " " for c in line)
    return None


def _extract_art_runs(lines: list[str]) -> list[list[str]]:
    """Break *lines* into runs of consecutive art-shaped lines (length ≥ 5)."""
    fill_chars = set("#*@█▓▒░X+")
    art_runs: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        # Lines need to be substantial — short lines are not letters.
        if len(line) < 6:
            if len(current) >= 5:
                art_runs.append(current)
            current = []
            continue
        normalised = _is_art_line(line, fill_chars)
        if normalised is not None:
            current.append(normalised)
        else:
            if len(current) >= 5:
                art_runs.append(current)
            current = []
    if len(current) >= 5:
        art_runs.append(current)
    return art_runs


def _skip_whitespace_columns(rows: list[str], pos: int, max_len: int) -> int:
    """Advance *pos* past any all-space columns."""
    while pos < max_len and all(rows[r][pos] == " " for r in range(5)):
        pos += 1
    return pos


def _find_letter_end(rows: list[str], pos: int, max_len: int, cols_per_letter: int) -> int:
    """Find the end column of the letter block starting at *pos*."""
    end = min(pos + cols_per_letter, max_len)
    while end < max_len and not all(rows[r][end] == " " for r in range(5)):
        end += 1
        if end - pos > cols_per_letter + 2:
            break
    return end


def _decode_glyph_run(run: list[str], min_word_length: int) -> str:
    """Try to decode a single 5+row block into a word."""
    # Use the first 5 rows; ArtPrompt-style art uses 5-row letters.
    rows = run[:5]
    max_len = max(len(r) for r in rows)
    rows = [r.ljust(max_len) for r in rows]

    # Slice into ~6-char-wide letter columns, separated by columns of
    # all-space. Find letter boundaries by scanning for vertical gaps.
    cols_per_letter = 6
    letters: list[str] = []
    pos = 0
    while pos < max_len:
        pos = _skip_whitespace_columns(rows, pos, max_len)
        if pos >= max_len:
            break
        end = _find_letter_end(rows, pos, max_len, cols_per_letter)
        block = tuple(rows[r][pos:end].ljust(cols_per_letter)[:cols_per_letter] for r in range(5))
        letter = _match_glyph(block)
        if letter:
            letters.append(letter)
        pos = end

    word = "".join(letters)
    return word if len(word) >= min_word_length else ""


def _glyph_match_score(ref: tuple[str, ...], block: tuple[str, ...]) -> float:
    """Compute the fraction of matching cells between a reference glyph and a block."""
    matches = 0
    total = 0
    for r in range(5):
        ref_row = ref[r]
        blk_row = block[r] if r < len(block) else ""
        for c in range(6):
            a = ref_row[c] if c < len(ref_row) else " "
            b = blk_row[c] if c < len(blk_row) else " "
            if a == b:
                matches += 1
            total += 1
    return matches / total if total > 0 else 0.0


def _match_glyph(block: tuple[str, ...]) -> str:
    """Match *block* to the closest letter in :data:`_LETTER_GLYPHS`."""
    best_letter = ""
    best_score = 0.0
    for letter, ref in _LETTER_GLYPHS.items():
        score = _glyph_match_score(ref, block)
        if score > best_score:
            best_score = score
            best_letter = letter
    return best_letter if best_score >= 0.70 else ""


# ---------------------------------------------------------------------------
# Multimodal scan result
# ---------------------------------------------------------------------------


@dataclass
class MultimodalFinding:
    """One pre-processing finding emitted before the scanner runs."""

    kind: str
    """``invisible_unicode``, ``ascii_art``, ``exif``, ``ocr``, ``pdf_text``."""

    detail: str
    """Short human-readable explanation."""

    severity: str = "MEDIUM"
    """``HIGH`` / ``MEDIUM`` / ``LOW``."""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "detail": self.detail, "severity": self.severity}


@dataclass
class MultimodalScanResult:
    """Combined output of multimodal scanning."""

    findings: list[MultimodalFinding] = field(default_factory=list)
    """Pre-processing findings — what was hidden, what was extracted."""

    extracted_text: str = ""
    """Plain text recovered from the input — OCR result, PDF stream, etc."""

    scan_result: ScanResult | None = None
    """The :class:`ScanResult` from running the extracted/scrubbed text
    through the underlying :class:`Scanner`. ``None`` when nothing was
    extracted to scan."""

    @property
    def combined_verdict(self) -> str:
        """Worst-case verdict combining findings + scan result.

        High-severity findings escalate to ``MALICIOUS`` even when the
        scanner verdict is ``CLEAN``: an invisible-Unicode payload that the
        scrubber removed is itself evidence of malicious intent.
        """
        if any(f.severity == "HIGH" for f in self.findings):
            return "MALICIOUS"
        if self.scan_result and self.scan_result.verdict == "MALICIOUS":
            return "MALICIOUS"
        if (self.scan_result and self.scan_result.verdict == "SUSPICIOUS") or any(
            f.severity == "MEDIUM" for f in self.findings
        ):
            return "SUSPICIOUS"
        return "CLEAN"

    @property
    def combined_action(self) -> str:
        verdict = self.combined_verdict
        return {"CLEAN": "ALLOW", "SUSPICIOUS": "ALERT", "MALICIOUS": "BLOCK"}[verdict]

    def to_dict(self) -> dict[str, Any]:
        return {
            "combined_verdict": self.combined_verdict,
            "combined_action": self.combined_action,
            "findings": [f.to_dict() for f in self.findings],
            "extracted_text": self.extracted_text,
            "scan_result": self.scan_result.to_dict() if self.scan_result else None,
        }


# ---------------------------------------------------------------------------
# MultimodalScanner — orchestrator
# ---------------------------------------------------------------------------


def _extract_exif_text(image: Any, exif_tags_module: Any) -> list[str]:
    """Extract human-readable text fields from an image's EXIF data."""
    parts: list[str] = []
    try:
        exif_data = image.getexif()
        if not exif_data:
            return parts
        for tag_id, value in exif_data.items():
            tag_name = exif_tags_module.TAGS.get(tag_id, str(tag_id))
            value = _decode_exif_value(value)
            if isinstance(value, str) and value.strip():
                parts.append(f"{tag_name}: {value}")
    except Exception as exc:
        logger.debug("EXIF inspection failed: %s", exc)
    return parts


def _decode_exif_value(value: Any) -> Any:
    """Decode a bytes EXIF value to a string, or return it unchanged."""
    if not isinstance(value, (bytes, bytearray)):
        return value
    try:
        return value.decode("utf-8", errors="replace")
    except Exception:
        return None


def _run_ocr(image: Any, path: Path) -> str:
    """Run Tesseract OCR on *image*, returning the stripped text (may be empty)."""
    try:
        import pytesseract  # type: ignore[import-untyped]

        ocr_text = pytesseract.image_to_string(image) or ""
    except ImportError as exc:
        raise ImportError(
            "Image OCR requires pytesseract. "
            "Install with: pip install 'raucle[multimodal]' "
            "and ensure tesseract is on PATH."
        ) from exc
    except Exception as exc:
        logger.warning("Tesseract failed on %s: %s", path, exc)
        return ""
    return ocr_text.strip()


class MultimodalScanner:
    """Pre-process multi-modal inputs, then run the underlying scanner.

    Parameters
    ----------
    scanner : Scanner
        The downstream text scanner to feed extracted/scrubbed text into.
    """

    def __init__(self, scanner: Scanner) -> None:
        self._scanner = scanner

    # ------------------------------------------------------------------
    # Text — invisible-Unicode + ASCII-art detection
    # ------------------------------------------------------------------

    def scan_text(self, text: str) -> MultimodalScanResult:
        """Scan plain text for multimodal evasion + then run the scanner."""
        result = MultimodalScanResult()

        scrubbed, hidden = strip_invisible_unicode(text)
        if hidden:
            result.findings.append(
                MultimodalFinding(
                    kind="invisible_unicode",
                    detail=(
                        f"Stripped invisible/formatting codepoints: {', '.join(hidden)}. "
                        f"Original {len(text)} chars, cleaned {len(scrubbed)} chars."
                    ),
                    severity="HIGH",
                )
            )

        art_words = detect_ascii_art(scrubbed)
        if art_words:
            result.findings.append(
                MultimodalFinding(
                    kind="ascii_art",
                    detail=("ASCII-art block decoded to: " + ", ".join(repr(w) for w in art_words)),
                    severity="HIGH",
                )
            )
            # Append the decoded text so the scanner sees it.
            scrubbed = scrubbed + "\n[decoded ASCII art: " + " ".join(art_words) + "]"

        result.extracted_text = scrubbed
        result.scan_result = self._scanner.scan(scrubbed)
        return result

    # ------------------------------------------------------------------
    # Image — Tesseract OCR + EXIF inspection
    # ------------------------------------------------------------------

    def scan_image(self, path: str | Path) -> MultimodalScanResult:
        """Scan an image: extract text via OCR + inspect EXIF, then scan text.

        Requires the ``[multimodal]`` extra (Pillow + pytesseract).
        """
        result = MultimodalScanResult()
        try:
            from PIL import ExifTags, Image  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "Image scanning requires Pillow. Install with: pip install 'raucle[multimodal]'"
            ) from exc

        path = Path(path)
        # Resource caps (round-3 #12): reject oversized files and pixel bombs
        # before decoding. Image dimensions come from the header, so this is
        # checked before any full-raster decode/OCR.
        if path.stat().st_size > _MAX_MEDIA_BYTES:
            raise ValueError(
                f"refusing to scan image: {path.stat().st_size} bytes exceeds "
                f"{_MAX_MEDIA_BYTES}-byte cap"
            )
        image = Image.open(path)
        if image.width * image.height > _MAX_IMAGE_PIXELS:
            raise ValueError(
                f"refusing to scan image: {image.width}x{image.height} exceeds "
                f"{_MAX_IMAGE_PIXELS}-pixel cap (decompression-bomb guard)"
            )

        # ---- EXIF -------------------------------------------------------
        exif_text_parts = _extract_exif_text(image, ExifTags)
        if exif_text_parts:
            result.findings.append(
                MultimodalFinding(
                    kind="exif",
                    detail=f"EXIF metadata contained {len(exif_text_parts)} text field(s)",
                    severity="LOW",
                )
            )

        # ---- OCR --------------------------------------------------------
        ocr_text = _run_ocr(image, path)
        if ocr_text:
            result.findings.append(
                MultimodalFinding(
                    kind="ocr",
                    detail=f"OCR extracted {len(ocr_text)} characters from image",
                    severity="LOW",
                )
            )

        # Combine OCR text + EXIF text into one string for downstream scanning.
        combined_text = "\n".join([ocr_text, *exif_text_parts]).strip()
        result.extracted_text = combined_text

        if combined_text:
            # Recurse through scan_text so invisible-Unicode / ASCII-art on
            # OCR output also get caught.
            text_result = self.scan_text(combined_text)
            # Merge in any nested findings.
            result.findings.extend(text_result.findings)
            result.scan_result = text_result.scan_result

        return result

    # ------------------------------------------------------------------
    # PDF — stream-level text extraction
    # ------------------------------------------------------------------

    def scan_pdf(self, path: str | Path) -> MultimodalScanResult:
        """Scan a PDF: extract text from every page, then scan combined text.

        Requires the ``[multimodal]`` extra (``pypdf``).
        """
        result = MultimodalScanResult()
        try:
            import pypdf  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "PDF scanning requires pypdf. Install with: pip install 'raucle[multimodal]'"
            ) from exc

        path = Path(path)
        # Resource caps (round-3 #12): bound file size and page count before
        # iterating, so a million-page / huge PDF can't exhaust memory or CPU.
        if path.stat().st_size > _MAX_MEDIA_BYTES:
            raise ValueError(
                f"refusing to scan PDF: {path.stat().st_size} bytes exceeds "
                f"{_MAX_MEDIA_BYTES}-byte cap"
            )
        reader = pypdf.PdfReader(str(path))
        if len(reader.pages) > _MAX_PDF_PAGES:
            raise ValueError(
                f"refusing to scan PDF: {len(reader.pages)} pages exceeds {_MAX_PDF_PAGES}-page cap"
            )
        pages_text: list[str] = []
        for page in reader.pages:
            try:
                pages_text.append(page.extract_text() or "")
            except Exception as exc:
                logger.debug("PDF page extraction failed: %s", exc)

        combined = "\n".join(pages_text).strip()
        if combined:
            result.findings.append(
                MultimodalFinding(
                    kind="pdf_text",
                    detail=f"Extracted {len(combined)} characters from {len(reader.pages)} page(s)",
                    severity="LOW",
                )
            )

        result.extracted_text = combined
        if combined:
            text_result = self.scan_text(combined)
            result.findings.extend(text_result.findings)
            result.scan_result = text_result.scan_result

        return result


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def has_suspicious_unicode(text: str) -> bool:
    """Quick yes/no for the most common case: any invisible codepoint present."""
    return any(ord(ch) in _INVISIBLE_CODEPOINTS for ch in text)


def unicode_category_summary(text: str) -> dict[str, int]:
    """Return a {category: count} map for diagnostics."""
    out: dict[str, int] = {}
    for ch in text:
        cat = unicodedata.category(ch)
        out[cat] = out.get(cat, 0) + 1
    return out
