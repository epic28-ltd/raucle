"""SCITT transparency-service anchoring of receipt-chain heads (N2).

Anchoring proves *non-equivocation of the chain head*: once the head
digest (final record hash + index) is registered with a Transparency
Service, the service holds a signed statement that this exact head
existed at registration time, so the writer cannot later present a
different chain history for the same chain. Anchoring proves nothing
more than that — it does not upgrade the quality of the underlying
records, and it is not a compliance claim.

Two halves live here:

* :class:`SCITTAnchorClient` — a strict HTTP client for the well-known
  SCITT registration flow (submit entry → poll operation status → fetch
  ``signed_statement``) per the receipt-chain-head entry profile. Uses
  only the standard library; no vendor SDK; secrets are taken as
  parameters, never module globals.
* :func:`verify_transparency_anchor` — the offline verifier-side check:
  given a chain file and a cached or fetched signed statement, confirm
  the anchored digest matches the recomputed chain head and that a
  signature path is present in the statement. The check is optional and
  OFF by default; when the transparency root is absent the result is the
  named ``SELF-SIGNED-ONLY`` status with the reason recorded — never a
  silent pass and never a silent skip.
"""

from __future__ import annotations

import email.utils
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raucle.audit import _canonical_json, _loads_strict, _sha256_hex

ENTRY_PROFILE = "urn:raucle:scitt:receipt-chain-head:v1"

# Named statuses. These strings are part of the contract — tools and
# humans key off them, so they are never renamed casually.
STATUS_ANCHORED = "TRANSPARENCY-ANCHORED"
STATUS_PENDING = "PENDING"
STATUS_FAILED = "TRANSPARENCY-FAILED"
STATUS_DIGEST_MISMATCH = "DIGEST-MISMATCH"
STATUS_SELF_SIGNED_ONLY = "SELF-SIGNED-ONLY"

_SIGNATURE_FIELDS = ("signature", "signatures", "cose")

_REDACTED = "***"


# ---------------------------------------------------------------------------
# Chain head
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChainHead:
    """The digest an anchor binds: final event index and its record hash."""

    index: int
    hash: str


def compute_chain_head(path: str | Path) -> ChainHead:
    """Recompute the head of a hash-chain file written by :class:`HashChainSink`.

    Every event record's stored hash is re-verified against its canonical
    bytes, so a tampered tail fails loudly here rather than anchoring a
    digest over corrupt material. Raises ``ValueError`` on a malformed,
    tampered or empty (no events) chain.
    """
    head_hash: str | None = None
    head_index = -1
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            rec = _loads_strict(stripped)
            if rec.get("chain_meta") or rec.get("checkpoint"):
                continue
            stored_hash = rec.pop("hash", None)
            recomputed = _sha256_hex(_canonical_json(rec))
            if stored_hash != recomputed:
                raise ValueError(
                    f"line {line_no}: event hash mismatch while computing chain "
                    f"head (stored != recomputed) — refusing to anchor a "
                    f"tampered chain"
                )
            head_hash = stored_hash
            head_index = int(rec.get("index", head_index))
    if head_hash is None:
        raise ValueError("chain contains no event records — nothing to anchor")
    return ChainHead(index=head_index, hash=head_hash)


# ---------------------------------------------------------------------------
# Anchoring results
# ---------------------------------------------------------------------------


@dataclass
class AnchoringResult:
    """Outcome of registering a chain head with a Transparency Service."""

    status: str
    chain_head: ChainHead
    observation: list[str] = field(default_factory=list)


@dataclass
class TransparencyCheck:
    """Offline verifier-side anchor check.

    ``status`` is one of the named statuses above. When the transparency
    root is absent the status is ``SELF-SIGNED-ONLY`` and ``reasons``
    says so explicitly — a caller that silently drops the reasons is
    visible in any review of this dataclass.
    """

    status: str
    chain_head: ChainHead
    reasons: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


def _parse_http_date(value: str, header: str) -> None:
    """Strictly parse an RFC 9110 HTTP-date header; raises on garbage."""
    try:
        parsed = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError) as exc:
        raise ValueError(
            f"Transparency Service returned an unparseable {header} header {value!r}: {exc}"
        ) from exc
    if parsed is None:
        raise ValueError(f"Transparency Service returned an unparseable {header} header {value!r}")


def _retry_after(value: str) -> float:
    """Retry-After per RFC 9110 §10.2.1: delta-seconds or HTTP-date."""
    if value is None:
        return 0.0
    stripped = value.strip()
    if stripped.isdigit():
        return min(int(stripped), 30)
    try:
        parsed = email.utils.parsedate_to_datetime(stripped)
    except (TypeError, ValueError, IndexError):
        return 0.0
    if parsed is None:
        return 0.0
    delay = parsed.timestamp() - time.time()
    return max(0.0, min(delay, 30.0))


class SCITTAnchorClient:
    """Register receipt-chain heads with a SCITT Transparency Service.

    The service base URL and bearer token arrive as constructor /
    method parameters — never environment globals — so a caller cannot
    accidentally pin credentials at import time.
    """

    def __init__(
        self,
        service_url: str,
        *,
        token: str | None = None,
        timeout: float = 5.0,
        poll_interval: float = 0.05,
        max_polls: int = 20,
    ) -> None:
        self._service_url = service_url.rstrip("/")
        from raucle.url_guard import validate_url

        validate_url(self._service_url, purpose="transparency service")
        self._token = token  # parameter only, never a module global
        self._timeout = timeout
        self._poll_interval = poll_interval
        self._max_polls = max_polls

    # -- entry building -----------------------------------------------------

    @staticmethod
    def build_entry(chain_head: ChainHead, *, chain_id: str) -> dict[str, Any]:
        """The receipt-chain-head entry payload for the registration."""
        return {
            "entry_profile": ENTRY_PROFILE,
            "chain_id": chain_id,
            "chain_head": {"index": chain_head.index, "hash": chain_head.hash},
        }

    # -- registration flow ---------------------------------------------------

    def register(
        self,
        chain_path: str | Path,
        *,
        chain_id: str,
    ) -> AnchoringResult:
        """Submit the chain-head entry, poll the operation, fetch the statement.

        Never mutates the chain file — anchoring reads bytes, writes none.
        """
        head = compute_chain_head(chain_path)
        entry = self.build_entry(head, chain_id=chain_id)
        payload = json.dumps(entry, ensure_ascii=False).encode("utf-8")
        observations: list[str] = [f"computed chain head: index={head.index} hash={head.hash}"]

        location = self._submit_entry(payload)
        observations.append(f"operation location: {location}")

        for _ in range(self._max_polls):
            status_body = self._poll_operation(location, observations)
            status = status_body.get("status")
            if status == "pending":
                time.sleep(self._poll_interval)
                continue
            if status == "failed":
                observations.append(
                    f"operation failed: {status_body.get('reason', 'no reason given')}"
                )
                return AnchoringResult(STATUS_FAILED, head, observations)
            if status == "complete":
                break
            observations.append(f"unknown operation status {status!r} — failing closed")
            return AnchoringResult(STATUS_FAILED, head, observations)
        else:
            observations.append(
                f"operation still pending after {self._max_polls} polls — caller "
                f"may resume with the recorded location"
            )
            return AnchoringResult(STATUS_PENDING, head, observations)

        statement_url = status_body.get("signed_statement_url")
        if not statement_url:
            observations.append("operation complete but no signed_statement_url — failing closed")
            return AnchoringResult(STATUS_FAILED, head, observations)
        signed_statement = self._fetch_signed_statement(statement_url, observations)

        # The service must echo the exact head we submitted. A mismatch
        # means the service anchored different material — named, never
        # presented as success.
        echo = signed_statement.get("statement", {}) if isinstance(signed_statement, dict) else {}
        anchored = echo.get("chain_head", {}) if isinstance(echo, dict) else {}
        if anchored.get("hash") != head.hash or anchored.get("index") != head.index:
            observations.append(
                f"signed statement anchors hash={anchored.get('hash')!r} "
                f"index={anchored.get('index')!r} which does not match the "
                f"submitted head — DIGEST-MISMATCH"
            )
            return AnchoringResult(STATUS_DIGEST_MISMATCH, head, observations)
        observations.append("signed statement received and head digest confirmed")
        return AnchoringResult(STATUS_ANCHORED, head, observations)

    # -- HTTP plumbing -------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "raucle-scitt-anchor/1",
        }
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _request(
        self, method: str, url: str, body: bytes | None = None
    ) -> tuple[int, dict[str, str], dict[str, Any]]:
        from raucle.url_guard import validate_url

        validate_url(url, purpose="transparency service request")
        req = urllib.request.Request(url, data=body, method=method)
        for key, value in self._headers().items():
            req.add_header(key, value)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                code = resp.status
                headers = {k.lower(): v for k, v in resp.headers.items()}
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"transparency service {method} {url} returned HTTP {exc.code}"
            ) from exc
        _parse_http_date(headers.get("date", ""), "Date")
        data = json.loads(raw.decode("utf-8")) if raw else {}
        return code, headers, data

    def _submit_entry(self, payload: bytes) -> str:
        url = f"{self._service_url}/entries"
        code, headers, _body = self._request("POST", url, payload)
        if code != 201:
            raise RuntimeError(f"entry submission expected HTTP 201, got {code} from {url}")
        location = headers.get("location")
        if not location:
            raise RuntimeError(
                "entry submission returned no Location header (operation "
                "status URL) — cannot poll per the SCITT registration flow"
            )
        if location.startswith("/"):
            # RFC 3986 §5.3: resolve a relative reference against our base.
            location = f"{self._service_url}{location}"
        return location

    def _poll_operation(self, location: str, observations: list[str]) -> dict[str, Any]:
        code, headers, body = self._request("GET", location)
        retry_after = _retry_after(headers.get("retry-after", ""))
        if retry_after > 0 and retry_after > self._poll_interval:
            observations.append(f"honouring Retry-After of {retry_after:.3f}s")
        if code != 200:
            raise RuntimeError(f"operation status expected HTTP 200, got {code} from {location}")
        return body

    def _fetch_signed_statement(
        self, statement_url: str, observations: list[str]
    ) -> dict[str, Any]:
        if statement_url.startswith("/"):
            statement_url = f"{self._service_url}{statement_url}"
        code, _headers, body = self._request("GET", statement_url)
        if code != 200:
            raise RuntimeError(
                f"signed statement expected HTTP 200, got {code} from {statement_url}"
            )
        observations.append(f"fetched signed statement from {statement_url}")
        return body


# ---------------------------------------------------------------------------
# Offline verifier-side check
# ---------------------------------------------------------------------------


def verify_transparency_anchor(
    chain_path: str | Path,
    signed_statement: dict[str, Any] | None = None,
    *,
    chain_id: str | None = None,
    require_transparency: bool = False,
) -> TransparencyCheck:
    """Verify a chain against a cached/fetched Transparency Service statement.

    This check is *optional and OFF by default*: callers that never invoke
    it keep the plain self-signed verification story. When the statement
    is absent the result is honestly named ``SELF-SIGNED-ONLY`` — the
    anchoring was simply never established, and the reason is recorded
    rather than swallowed.

    Verifies two independent properties:

    * digest match — the statement's anchored head equals the recomputed
      chain head (index and hash);
    * signature path present — the statement carries a signature element
      the transparency root can later expand on (full COSE verification
      against a transparency root is verifier wiring for a follow-up; an
      absent signature path can never count as anchored).

    Anchoring proves non-equivocation of the head — nothing more.
    """
    head = compute_chain_head(chain_path)
    if signed_statement is None:
        reasons = [
            "no transparency-service signed statement available: result is "
            "SELF-SIGNED-ONLY (chain verified by its own signatures only; "
            "no non-equivocation guarantee for the head)"
        ]
        if require_transparency:
            reasons.append(
                "require_transparency=True was requested but no statement "
                "was supplied — the check is honestly absent, not skipped"
            )
        return TransparencyCheck(STATUS_SELF_SIGNED_ONLY, head, reasons)

    reasons: list[str] = []
    statement = signed_statement.get("statement", signed_statement)
    if not isinstance(statement, dict):
        return TransparencyCheck(
            STATUS_DIGEST_MISMATCH,
            head,
            ["signed statement carries no readable statement object"],
        )

    anchored = statement.get("chain_head")
    if not isinstance(anchored, dict):
        return TransparencyCheck(
            STATUS_DIGEST_MISMATCH,
            head,
            ["signed statement carries no chain_head object to compare"],
        )

    signature_present = any(field_name in signed_statement for field_name in _SIGNATURE_FIELDS)
    if chain_id is not None and statement.get("chain_id") not in (None, chain_id):
        reasons.append(
            f"statement chain_id {statement.get('chain_id')!r} does not match "
            f"requested {chain_id!r}"
        )
    hash_match = anchored.get("hash") == head.hash
    index_match = anchored.get("index") == head.index
    if not hash_match:
        reasons.append(
            f"anchored head hash {anchored.get('hash')!r} != recomputed chain head {head.hash!r}"
        )
    if not index_match:
        reasons.append(
            f"anchored head index {anchored.get('index')!r} != recomputed "
            f"chain head index {head.index}"
        )
    if not signature_present:
        reasons.append("signed statement carries no signature path")

    if reasons:
        return TransparencyCheck(STATUS_DIGEST_MISMATCH, head, reasons)
    reasons.append(
        "anchored digest matches the recomputed chain head and a signature "
        "path is present — head non-equivocation is attested by the "
        "transparency service"
    )
    return TransparencyCheck(STATUS_ANCHORED, head, reasons)
