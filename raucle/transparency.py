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

X2 slice 2 adds the offline verifier for the HOSTED transparency log
(the log itself is the operator surface, raucle-cloud):
:func:`compute_log_entry_hash`, :func:`verify_log_inclusion` and
:func:`verify_log_consistency` recompute every entry hash from the
proof alone, check the segment linkage, and hold the operator's
Ed25519 epoch checkpoint to the head. The operator's public key is
always a pinned parameter here, never material read off the proof.
"""

from __future__ import annotations

import email.utils
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raucle.audit import _canonical_json, _loads_strict, _sha256_hex
from raucle.provenance import _b64url_decode

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
        email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError) as exc:
        raise ValueError(
            f"Transparency Service returned an unparseable {header} header {value!r}: {exc}"
        ) from exc
    # no None case: parsedate_to_datetime raises rather than returning None (3.10+)


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
    # no None case: parsedate_to_datetime raises rather than returning None (3.10+)
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


# ---------------------------------------------------------------------------
# X2 slice 2: the hosted transparency log, the offline verifier side
# ---------------------------------------------------------------------------
#
# The log itself is an operator surface (raucle-cloud): a per-org,
# append-only, hash-chained log of registered receipt digests whose
# every append closes a signed epoch. Verification is OSS by the 17 Nov
# licence split, so this section defines only the third-party side:
# what a verifier recomputes from a proof, with no trust in the
# operator. The wire contract is docs/spec/x2-transparency-log-v1.md.

#: The link a genesis entry binds. A chain a third party recomputes
#: starts from this named value, so the constant is part of the
#: contract, not an implementation detail.
LOG_GENESIS_PREV_HASH = "sha256:" + "0" * 64

#: The JWS typ of an epoch checkpoint (the signed tree head).
LOG_CHECKPOINT_TYP = "transparency-epoch/v1"

#: The critical JOSE header parameters of every checkpoint.
LOG_CRIT_EXTENSION = "raucle/v1"
LOG_CRIT_VALUE = "transparency"

# Named statuses for the log checks. As with the anchor statuses above,
# these strings are part of the contract, so they are never renamed
# casually. Precedence when several refusal families fire at once:
# MALFORMED, then BAD_SIGNATURE, then CHAIN-BROKEN, then HEAD-MISMATCH,
# with every reason still reported.
STATUS_LOG_INCLUDED = "LOG-INCLUDED"
STATUS_LOG_CONSISTENT = "LOG-CONSISTENT"
STATUS_LOG_MALFORMED = "LOG-MALFORMED"
STATUS_LOG_CHAIN_BROKEN = "LOG-CHAIN-BROKEN"
STATUS_LOG_BAD_SIGNATURE = "LOG-BAD-SIGNATURE"
STATUS_LOG_HEAD_MISMATCH = "LOG-HEAD-MISMATCH"

_LOG_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: The entry profile is closed: seven fields, no others. The entry
#: hash covers six of them; entry_hash is the covering value.
_LOG_ENTRY_FIELDS = frozenset(
    {
        "entry_hash",
        "org",
        "payload_digest",
        "prev_hash",
        "receipt_digest",
        "registered_at",
        "sequence",
    }
)
_LOG_ENTRY_REQUIRED = _LOG_ENTRY_FIELDS - {"payload_digest"}

#: The checkpoint header and payload profiles are closed too: an
#: unknown field is refused, never ignored.
_LOG_CHECKPOINT_HEADER_FIELDS = frozenset({"alg", "crit", "kid", "typ", LOG_CRIT_EXTENSION})
_LOG_CHECKPOINT_PAYLOAD_FIELDS = frozenset(
    {"epoch", "head_hash", "iat", "iss", "nonce", "org", "size"}
)

#: A bounded parse: a checkpoint larger than this is refused, not read.
_LOG_MAX_CHECKPOINT_BYTES = 65536


def compute_log_entry_hash(entry: dict[str, Any]) -> str:
    """The entry hash per the x2 log profile: sha256 over the canonical
    JSON of the entry's six public fields.

    Byte-identical to the hosted log's own computation, so a third
    party recomputes exactly what the operator claims. ``entry_hash``
    is never part of the hashed record. Raises ``KeyError`` when a
    hashed field is absent.
    """
    record = {
        "org": entry["org"],
        "payload_digest": entry.get("payload_digest"),
        "prev_hash": entry["prev_hash"],
        "receipt_digest": entry["receipt_digest"],
        "registered_at": entry["registered_at"],
        "sequence": entry["sequence"],
    }
    return "sha256:" + _sha256_hex(_canonical_json(record))


@dataclass
class LogVerification:
    """The outcome of an offline log check.

    ``status`` is one of the ``STATUS_LOG_*`` named statuses.
    ``reasons`` carries every refusal found, never just the first, so
    a caller that reports only the status still cannot hide which
    bindings failed. ``size`` and ``head_hash`` describe the head the
    proof claims (the signed head on success); they are 0 and ``""``
    when the proof is malformed.
    """

    status: str
    reasons: list[str] = field(default_factory=list)
    size: int = 0
    head_hash: str = ""
    org: str = ""


def _log_digest_ok(value: Any) -> bool:
    return isinstance(value, str) and _LOG_DIGEST_RE.match(value) is not None


def _log_int(value: Any, *, minimum: int) -> bool:
    """An integer of at least *minimum*. Python bools are ints; the
    profile's integers never are."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _log_entry_refusal(entry: Any) -> str | None:
    """A named reason when *entry* is not a log entry, else ``None``."""
    if not isinstance(entry, dict):
        return "an entry is not a JSON object"
    keys = set(entry)
    missing = _LOG_ENTRY_REQUIRED - keys
    if missing:
        return f"an entry lacks the fields {sorted(missing)}"
    unknown = keys - _LOG_ENTRY_FIELDS
    if unknown:
        return f"an entry carries unknown fields {sorted(unknown)}"
    if not isinstance(entry["org"], str) or not entry["org"]:
        return "entry org is not a non-empty string"
    if not _log_int(entry["sequence"], minimum=1):
        return "entry sequence is not a positive integer"
    for name in ("entry_hash", "prev_hash", "receipt_digest"):
        if not _log_digest_ok(entry[name]):
            return f"entry {name} is not a sha256:<64 hex> digest"
    payload_digest = entry.get("payload_digest")
    if payload_digest is not None and not _log_digest_ok(payload_digest):
        return "entry payload_digest is not a sha256:<64 hex> digest"
    if not _log_int(entry["registered_at"], minimum=0):
        return "entry registered_at is not a non-negative integer"
    return None


def _log_inclusion_shape_refusal(proof: Any) -> str | None:
    """A named reason when *proof* is not shaped like an inclusion
    proof, else ``None``. A checkpoint's own artefact failures are not
    shape failures: a checkpoint that cannot be verified is a
    BAD_SIGNATURE matter."""
    if not isinstance(proof, dict):
        return "the proof is not a JSON object"
    for name in ("checkpoint_jws", "entries", "head_hash", "org", "sequence", "size"):
        if name not in proof:
            return f"the proof lacks {name}"
    if not isinstance(proof["org"], str) or not proof["org"]:
        return "proof org is not a non-empty string"
    if not _log_int(proof["sequence"], minimum=1):
        return "proof sequence is not a positive integer"
    if not _log_int(proof["size"], minimum=1):
        return "proof size is not a positive integer"
    if not isinstance(proof["entries"], list) or not proof["entries"]:
        return "proof entries is not a non-empty list"
    if not _log_digest_ok(proof["head_hash"]):
        return "proof head_hash is not a sha256:<64 hex> digest"
    if not isinstance(proof["checkpoint_jws"], str):
        return "proof checkpoint_jws is not a string"
    return None


def _log_consistency_shape_refusal(proof: Any) -> str | None:
    """A named reason when *proof* is not shaped like a consistency
    proof, else ``None``."""
    if not isinstance(proof, dict):
        return "the proof is not a JSON object"
    for name in (
        "entries",
        "from_checkpoint_jws",
        "from_size",
        "org",
        "to_checkpoint_jws",
        "to_size",
    ):
        if name not in proof:
            return f"the proof lacks {name}"
    if not isinstance(proof["org"], str) or not proof["org"]:
        return "proof org is not a non-empty string"
    for name in ("from_size", "to_size"):
        if not _log_int(proof[name], minimum=1):
            return f"proof {name} is not a positive integer"
    if proof["from_size"] >= proof["to_size"]:
        return "sizes must satisfy 1 <= from_size < to_size"
    if not isinstance(proof["entries"], list) or not proof["entries"]:
        return "proof entries is not a non-empty list"
    for name in ("from_checkpoint_jws", "to_checkpoint_jws"):
        if not isinstance(proof[name], str):
            return f"proof {name} is not a string"
    return None


def _verify_log_checkpoint(
    checkpoint_jws: str, *, operator_public_key_pem: str
) -> tuple[dict[str, Any] | None, list[str]]:
    """Verify one epoch checkpoint against the pinned operator key.

    Returns ``(payload, [])`` on success, ``(None, reasons)``
    otherwise. Every failure here is a BAD_SIGNATURE matter: the
    checkpoint is the signed claim, and a claim that cannot be
    verified is worthless as evidence, never merely mis-shaped.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if len(checkpoint_jws) > _LOG_MAX_CHECKPOINT_BYTES:
        return None, [f"the checkpoint exceeds the {_LOG_MAX_CHECKPOINT_BYTES}-byte bound"]
    parts = checkpoint_jws.split(".")
    if len(parts) != 3:
        return None, [f"a checkpoint carries three segments, got {len(parts)}"]
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = _loads_strict(_b64url_decode(header_b64).decode("utf-8"))
        payload = _loads_strict(_b64url_decode(payload_b64).decode("utf-8"))
        signature = _b64url_decode(signature_b64)
    except (ValueError, UnicodeDecodeError) as exc:
        return None, [f"the checkpoint does not parse: {exc}"]
    if not isinstance(header, dict):
        return None, ["the checkpoint header is not a JSON object"]
    unknown = set(header) - _LOG_CHECKPOINT_HEADER_FIELDS
    if unknown:
        return None, [f"the checkpoint header carries unknown fields {sorted(unknown)}"]
    if header.get("alg") != "EdDSA":
        return None, [f"the checkpoint alg is {header.get('alg')!r}, not EdDSA"]
    if header.get("typ") != LOG_CHECKPOINT_TYP:
        return None, [f"the checkpoint typ is {header.get('typ')!r}, not {LOG_CHECKPOINT_TYP}"]
    if header.get("crit") != [LOG_CRIT_EXTENSION]:
        return None, [f"the checkpoint crit is {header.get('crit')!r}, not the documented set"]
    if header.get(LOG_CRIT_EXTENSION) != LOG_CRIT_VALUE:
        return None, [
            f"the checkpoint {LOG_CRIT_EXTENSION} extension is not the transparency value"
        ]
    if not isinstance(header.get("kid"), str) or not header["kid"]:
        return None, ["the checkpoint kid is not a non-empty string"]
    try:
        loaded = serialization.load_pem_public_key(operator_public_key_pem.encode("ascii"))
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        return None, [f"the pinned operator key does not load as a PEM public key: {exc}"]
    if not isinstance(loaded, Ed25519PublicKey):
        return None, ["the pinned operator key is not an Ed25519 public key"]
    try:
        loaded.verify(signature, f"{header_b64}.{payload_b64}".encode("ascii"))
    except InvalidSignature:
        return None, ["the checkpoint signature does not verify against the pinned operator key"]
    if not isinstance(payload, dict):
        return None, ["the checkpoint payload is not a JSON object"]
    missing = _LOG_CHECKPOINT_PAYLOAD_FIELDS - set(payload)
    if missing:
        return None, [f"the checkpoint payload lacks {sorted(missing)}"]
    unknown = set(payload) - _LOG_CHECKPOINT_PAYLOAD_FIELDS
    if unknown:
        return None, [f"the checkpoint payload carries unknown fields {sorted(unknown)}"]
    if not isinstance(payload["org"], str) or not payload["org"]:
        return None, ["the checkpoint org is not a non-empty string"]
    for name in ("epoch", "iat", "size"):
        if not _log_int(payload[name], minimum=0):
            return None, [f"the checkpoint {name} is not a non-negative integer"]
    if payload["epoch"] != payload["size"]:
        return None, [
            f"the checkpoint epoch {payload['epoch']} does not equal its size {payload['size']}"
        ]
    if not _log_digest_ok(payload["head_hash"]):
        return None, ["the checkpoint head_hash is not a sha256:<64 hex> digest"]
    if not isinstance(payload["nonce"], str) or not payload["nonce"]:
        return None, ["the checkpoint nonce is not a non-empty string"]
    if not isinstance(payload["iss"], str) or not payload["iss"]:
        return None, ["the checkpoint iss is not a non-empty string"]
    return payload, []


def _log_segment_reasons(entries: list[dict[str, Any]]) -> list[str]:
    """The chain-level refusals for one contiguous segment: hash
    binding, linkage, contiguity, the genesis link. Every entry has
    passed shape validation before this runs."""
    reasons: list[str] = []
    for entry in entries:
        if compute_log_entry_hash(entry) != entry["entry_hash"]:
            reasons.append(
                f"entry {entry['sequence']} does not bind its stated hash (recomputed != stated)"
            )
    first = entries[0]
    if first["sequence"] == 1 and first["prev_hash"] != LOG_GENESIS_PREV_HASH:
        reasons.append(f"the first entry does not name the genesis link {LOG_GENESIS_PREV_HASH}")
    for index in range(1, len(entries)):
        previous, entry = entries[index - 1], entries[index]
        if entry["sequence"] != previous["sequence"] + 1:
            reasons.append(
                f"the segment is not contiguous: entry {entry['sequence']}"
                f" follows entry {previous['sequence']}"
            )
        if entry["prev_hash"] != previous["entry_hash"]:
            reasons.append(
                f"entry {entry['sequence']} does not link the previous"
                f" entry's hash (entry {previous['sequence']})"
            )
    return reasons


def _log_org_reasons(entries: list[dict[str, Any]], proof_org: str) -> list[str]:
    """Every entry must belong to the proof's org: a mixed-org segment
    cannot come from one org's chain."""
    return [
        f"entry {entry['sequence']} belongs to org {entry['org']!r},"
        f" not the proof org {proof_org!r}"
        for entry in entries
        if entry["org"] != proof_org
    ]


def verify_log_inclusion(
    proof: Any,
    *,
    operator_public_key_pem: str,
    org: str | None = None,
    expect_digest: str | None = None,
) -> LogVerification:
    """Verify an inclusion proof offline, with no trust in the operator.

    A third party recomputes every entry hash from the proof alone,
    checks the segment links the target entry to the head, and holds
    the operator's Ed25519 epoch checkpoint to that head. The operator
    key is always the PINNED parameter: the public key riding the proof
    is convenience material for humans, never verification input, so a
    proof is never verified against its own key.

    An honest limit, named rather than hidden: the proof re-verifies
    the segment it carries in full, and the prefix before the target is
    bound only through the segment's linkage and the signed head. A
    verifier who needs the whole chain asks for the sequence 1 proof,
    which carries every entry from genesis.
    """
    refusal = _log_inclusion_shape_refusal(proof)
    if refusal:
        return LogVerification(STATUS_LOG_MALFORMED, [refusal])
    entries = proof["entries"]
    entry_refusals = [r for r in (_log_entry_refusal(e) for e in entries) if r]
    if entry_refusals:
        return LogVerification(STATUS_LOG_MALFORMED, entry_refusals)

    first, last = entries[0], entries[-1]
    head_reasons: list[str] = []
    chain_reasons: list[str] = []
    if org is not None and proof["org"] != org:
        head_reasons.append(f"the proof is for org {proof['org']!r}, not the expected org {org!r}")
    head_reasons += _log_org_reasons(entries, proof["org"])
    if first["sequence"] != proof["sequence"]:
        chain_reasons.append(
            f"the segment begins at entry {first['sequence']}, not the stated"
            f" target sequence {proof['sequence']}"
        )
    chain_reasons += _log_segment_reasons(entries)
    if proof["head_hash"] != last["entry_hash"]:
        head_reasons.append("the stated head hash is not the segment's head")
    if proof["size"] != last["sequence"]:
        head_reasons.append(
            f"the stated size {proof['size']} is not the segment's head entry {last['sequence']}"
        )
    if expect_digest is not None and first["receipt_digest"] != expect_digest:
        head_reasons.append("the target entry registers a different digest than the expected one")
    stated_digest = proof.get("receipt_digest")
    if stated_digest is not None and stated_digest != first["receipt_digest"]:
        head_reasons.append("the proof names a different digest than its target entry carries")
    payload, checkpoint_reasons = _verify_log_checkpoint(
        proof["checkpoint_jws"], operator_public_key_pem=operator_public_key_pem
    )
    if payload is None:
        return LogVerification(
            STATUS_LOG_BAD_SIGNATURE,
            chain_reasons + head_reasons + checkpoint_reasons,
            size=proof["size"],
            head_hash=proof["head_hash"],
            org=proof["org"],
        )
    if payload["org"] != proof["org"]:
        head_reasons.append(
            f"the signed checkpoint is for org {payload['org']!r}, not {proof['org']!r}"
        )
    if payload["size"] != proof["size"]:
        head_reasons.append(
            f"the signed checkpoint is the head at size {payload['size']}, not {proof['size']}"
        )
    if payload["head_hash"] != last["entry_hash"]:
        head_reasons.append("the segment does not reach the signed head")
    if chain_reasons:
        return LogVerification(
            STATUS_LOG_CHAIN_BROKEN,
            chain_reasons + head_reasons,
            size=proof["size"],
            head_hash=proof["head_hash"],
            org=proof["org"],
        )
    if head_reasons:
        return LogVerification(
            STATUS_LOG_HEAD_MISMATCH,
            head_reasons,
            size=proof["size"],
            head_hash=proof["head_hash"],
            org=proof["org"],
        )
    reasons = [
        "every entry hash recomputes from the proof alone; the segment"
        f" links entry {first['sequence']} to the head {last['sequence']}"
        " and the operator's checkpoint signature verifies against the"
        " pinned key"
    ]
    return LogVerification(
        STATUS_LOG_INCLUDED,
        reasons,
        size=proof["size"],
        head_hash=last["entry_hash"],
        org=proof["org"],
    )


def verify_log_consistency(
    proof: Any,
    *,
    operator_public_key_pem: str,
    org: str | None = None,
) -> LogVerification:
    """Verify a consistency proof offline: the log grew append-only
    between two signed heads.

    The appended segment must link the OLD signed head to the NEW one.
    An operator who rewrites history cannot produce a segment that
    grows from the head it signed before, so the growth binding is the
    check: the first appended entry links the from-checkpoint's signed
    head, the last is the to-checkpoint's signed head, and every entry
    between binds and links. As with inclusion, the operator key is
    the pinned parameter, never the proof's rider.
    """
    refusal = _log_consistency_shape_refusal(proof)
    if refusal:
        return LogVerification(STATUS_LOG_MALFORMED, [refusal])
    entries = proof["entries"]
    entry_refusals = [r for r in (_log_entry_refusal(e) for e in entries) if r]
    if entry_refusals:
        return LogVerification(STATUS_LOG_MALFORMED, entry_refusals)

    first, last = entries[0], entries[-1]
    head_reasons: list[str] = []
    chain_reasons: list[str] = []
    if org is not None and proof["org"] != org:
        head_reasons.append(f"the proof is for org {proof['org']!r}, not the expected org {org!r}")
    head_reasons += _log_org_reasons(entries, proof["org"])
    chain_reasons += _log_segment_reasons(entries)
    if first["sequence"] != proof["from_size"] + 1:
        chain_reasons.append(
            f"the segment begins at entry {first['sequence']}, not the entry"
            f" that follows from_size {proof['from_size']}"
        )
    if last["sequence"] != proof["to_size"]:
        chain_reasons.append(
            f"the segment ends at entry {last['sequence']}, not to_size {proof['to_size']}"
        )
    from_payload, from_reasons = _verify_log_checkpoint(
        proof["from_checkpoint_jws"], operator_public_key_pem=operator_public_key_pem
    )
    to_payload, to_reasons = _verify_log_checkpoint(
        proof["to_checkpoint_jws"], operator_public_key_pem=operator_public_key_pem
    )
    if from_payload is None or to_payload is None:
        return LogVerification(
            STATUS_LOG_BAD_SIGNATURE,
            chain_reasons + head_reasons + from_reasons + to_reasons,
            size=proof["to_size"],
            head_hash=last["entry_hash"],
            org=proof["org"],
        )
    for payload, name in ((from_payload, "from"), (to_payload, "to")):
        if payload["org"] != proof["org"]:
            head_reasons.append(
                f"the signed {name}-checkpoint is for org {payload['org']!r}, not {proof['org']!r}"
            )
    if from_payload["size"] != proof["from_size"]:
        chain_reasons.append(
            f"the from-checkpoint is the head at size {from_payload['size']},"
            f" not {proof['from_size']}"
        )
    if to_payload["size"] != proof["to_size"]:
        chain_reasons.append(
            f"the to-checkpoint is the head at size {to_payload['size']}, not {proof['to_size']}"
        )
    if first["prev_hash"] != from_payload["head_hash"]:
        chain_reasons.append(
            "the segment does not grow from the signed old head: entry"
            f" {first['sequence']} does not link the from-checkpoint's head"
        )
    if to_payload["head_hash"] != last["entry_hash"]:
        head_reasons.append("the to-checkpoint's signed head is not the segment's head")
    if chain_reasons:
        return LogVerification(
            STATUS_LOG_CHAIN_BROKEN,
            chain_reasons + head_reasons,
            size=proof["to_size"],
            head_hash=last["entry_hash"],
            org=proof["org"],
        )
    if head_reasons:
        return LogVerification(
            STATUS_LOG_HEAD_MISMATCH,
            head_reasons,
            size=proof["to_size"],
            head_hash=last["entry_hash"],
            org=proof["org"],
        )
    reasons = [
        "the appended segment binds and links from the signed old head"
        f" (size {proof['from_size']}) to the signed new head (size"
        f" {proof['to_size']}), every entry hash recomputing from the"
        " proof alone"
    ]
    return LogVerification(
        STATUS_LOG_CONSISTENT,
        reasons,
        size=proof["to_size"],
        head_hash=last["entry_hash"],
        org=proof["org"],
    )
