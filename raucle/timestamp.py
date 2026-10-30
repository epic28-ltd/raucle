"""G1: the three-mode time-source model (RFC 3161 timestamping).

Most vendors hide the time-source trust question. Raucle states it: the
docs/spec/time-source-v1.md spec documents three modes and what each one
can honestly claim.

Mode 1, internal (default): the host clock under documented NTP
discipline. Receipts carry iat from the disciplined clock; the evidence
claim is "recorded at host time T", bounded by the stated drift bound.
No extension on the receipt; the chain and the clock discipline are the
evidence.

Mode 2, TSA-attested: an RFC 3161 timestamp authority stamps a digest the
operator supplies. The TSA is customer-chosen; raucle is TSA-agnostic by
design (the wire format is the standard, so any conformant TSA works:
a self-hosted Sigstore timestamp-authority, an EU QTSP with eIDAS Art 41
presumption, an internal TSA). The TimeStampReq is hash-only, always -
no payload material ever reaches the TSA. The anchor receipt (x_timestamp)
embeds the TimeStampToken; the offline verifier re-checks it: CMS parse,
message imprint, nonce, genTime against the TSA certificate's validity
window, and the TSA signature itself.

Mode 3, OpenTimestamps: vendor-neutral blockchain anchoring for
long-horizon archives. Recorded as an anchoring event with a bounded
claim; the .ots proof verifies against the Bitcoin chain externally.
OpenTimestamps anchors carry NO eIDAS Art 41 presumption of correctness -
documented, never claimed.

Dependency policy (deliberate, recorded in the spec):
- The TimeStampReq encoder is hand-rolled stdlib DER: the request is a
  fixed shape we fully control, so no ASN.1 library is needed to build
  it, and the zero-mandatory-dependency rule is preserved for anyone who
  only builds requests.
- The response is EXTERNAL network input: parsing arbitrary CMS
  SignedData by hand is how verification bugs are born, so the parse
  uses asn1crypto (pure Python, no compiled deps, MIT, the standard
  CMS parser for Python tooling). It only PARSES; the actual signature
  verification stays in the already-required `cryptography` package, so
  no new crypto primitive enters the trust path.
- Install with the `timestamp` extra: pip install "raucle[timestamp]".

Verification is fail-closed: a receipt claiming a TSA token that cannot
be re-checked (missing parser, bad signature, mismatched imprint) never
verifies as if attested.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_HASH_PREFIX = "sha256:"
_TS_QUERY_CONTENT_TYPE = "application/timestamp-query"
_TS_REPLY_CONTENT_TYPE = "application/timestamp-reply"
_RESTAMP_SAFETY_DAYS = 30

# RFC 3161 nonces are positive integers of at most 160 bits; raucle
# generates 52-bit nonces so the receipt payload stays inside the
# portable safe-integer range the canonical JSON contract enforces
# (2^53 - 1). ~4.5 quadrillion values is ample replay protection.
_NONCE_BITS = 52


class TimestampError(ValueError):
    """A named failure in the timestamp path (never a bare exception)."""


def _require_asn1crypto() -> None:
    try:
        import asn1crypto  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on install
        raise TimestampError(
            "the timestamp extension requires the raucle[timestamp] extra "
            "(asn1crypto is not installed)"
        ) from exc


# ---------------------------------------------------------------------------
# Mode 2 core: the RFC 3161 client (stdlib only, request side)
# ---------------------------------------------------------------------------

# SHA-256 OID 2.16.840.1.101.3.4.2.1 - DER content bytes, RFC 4055
# canonical form carries no NULL parameters for digest algorithms.
_SHA256_OID_CONTENT = bytes.fromhex("608648016503040201")


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(v: int) -> bytes:
    body = v.to_bytes((v.bit_length() + 7) // 8, "big")
    if body and body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(0x02, body)


def build_timestamp_request(digest: bytes, nonce: int) -> bytes:
    """Build a hash-only RFC 3161 TimeStampReq (DER).

    The request carries the digest and nothing else: version 1, a SHA-256
    messageImprint, the caller's nonce (replay protection; RFC 3161
    permits up to 160 bits, this implementation requires the portable
    safe-integer range), and certReq TRUE so the token carries the TSA
    certificate chain for offline verification.
    """
    if len(digest) != 32:
        raise TimestampError(f"sha256 messageImprint must be 32 bytes, got {len(digest)}")
    if nonce <= 0 or nonce.bit_length() > 53:
        raise TimestampError(
            "nonce must be a positive integer of at most 53 bits (the portable safe-integer range)"
        )
    alg_id = _tlv(0x30, _tlv(0x06, _SHA256_OID_CONTENT))
    imprint = _tlv(0x30, alg_id + _tlv(0x04, digest))
    body = (
        _der_int(1) + imprint + _der_int(nonce) + _tlv(0x01, b"\xff")  # certReq TRUE
    )
    return _tlv(0x30, body)


def new_nonce() -> int:
    return secrets.randbits(_NONCE_BITS) + 1


def submit_timestamp_request(url: str, request_der: bytes, timeout: float = 10.0) -> bytes:
    """POST a TimeStampReq to an RFC 3161 TSA over HTTP."""
    req = urllib.request.Request(  # noqa: S310 - TSAs are caller-chosen
        url,
        data=request_der,
        headers={"Content-Type": _TS_QUERY_CONTENT_TYPE},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        ctype = resp.headers.get("Content-Type", "")
        if _TS_REPLY_CONTENT_TYPE not in ctype:
            raise TimestampError(f"TSA replied with unexpected Content-Type {ctype!r}")
        return resp.read()


def parse_response(der: bytes) -> dict[str, Any]:
    """Parse a TimeStampResp into status fields plus the raw token DER.

    The token is OPTIONAL in the RFC 3161 response (a rejection carries
    only the status); asn1crypto types it as required, so a lenient
    subclass is used on the parse side."""
    _require_asn1crypto()
    from asn1crypto import cms, tsp

    class _Resp(tsp.TimeStampResp):
        _fields = [
            ("status", tsp.PKIStatusInfo),
            ("time_stamp_token", cms.ContentInfo, {"optional": True}),
        ]

    try:
        resp = _Resp.load(der)
    except ValueError as exc:
        raise TimestampError(f"malformed TimeStampResp: {exc}") from exc
    status_info = resp["status"]
    status = status_info["status"].native
    status_strings = [str(s.native) for s in (status_info["status_string"] or [])]
    fail_info = status_info["fail_info"].native
    token = resp["time_stamp_token"]
    token_der = None
    if token is not None and status == "granted":
        token_der = token.dump()
    return {
        "status": str(status),
        "status_string": "; ".join(status_strings),
        "fail_info": str(fail_info) if fail_info else "",
        "token": token_der,
    }


# ---------------------------------------------------------------------------
# Mode 2 core: the offline TimeStampToken re-check
# ---------------------------------------------------------------------------

_DIGEST_BY_NAME = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def _unwrap(content_bytes: bytes) -> bytes:
    """Strip one TLV header, returning the content bytes."""
    if not content_bytes:
        raise TimestampError("empty DER chunk")
    n = content_bytes[1]
    header = 2
    if n & 0x80:
        n_bytes = n & 0x7F
        n = int.from_bytes(content_bytes[2 : 2 + n_bytes], "big")
        header = 2 + n_bytes
    return content_bytes[header : header + n]


def _extract_tst_info(signed_data: Any) -> tuple[Any, bytes]:
    """Extract TSTInfo from a CMS SignedData, handling both the definite
    CMS shape (eContent is an OCTET STRING, what real TSAs emit) and the
    PKCS#7 shape asn1crypto admits at version v1 (content carried bare)."""
    from asn1crypto import tsp

    ec = signed_data["encap_content_info"]
    if ec["content_type"].native != "tst_info":
        raise TimestampError(
            f"token encap content is not TSTInfo (got {ec['content_type'].native!r})"
        )
    if signed_data["version"].native != "v1":
        # Definite CMS: .dump() returns the [0]-tagged chunk; unwrap it,
        # then unwrap the OCTET STRING TLV to recover the exact embedded
        # value bytes (needed for the messageDigest attribute check).
        tst_der = _unwrap(_unwrap(ec["content"].dump()))
    else:
        # v1 may be PKCS#7-shaped (content carried bare after [0]) or
        # CMS-shaped (an OCTET STRING after [0]); the bytes decide.
        chunk = ec["content"].dump()  # [0]-tagged
        inner = _unwrap(chunk)
        tst_der = _unwrap(inner) if inner and inner[0] == 0x04 else inner
    try:
        return tsp.TSTInfo.load(tst_der), tst_der
    except ValueError as exc:
        raise TimestampError(f"malformed TSTInfo: {exc}") from exc


def _find_signer_cert(signed_data: Any, signer_info: Any) -> Any:

    sid = signer_info["sid"]
    chosen = sid.chosen
    if sid.name == "issuer_and_serial_number":
        issuer_der = chosen["issuer"].dump()
        serial = chosen["serial_number"].native
        for c in signed_data["certificates"] or []:
            cert = c.chosen["tbs_certificate"]
            if cert["issuer"].dump() == issuer_der and cert["serial_number"].native == serial:
                return c.chosen
        raise TimestampError("signer certificate not carried in the token")
    ski = chosen.native
    for c in signed_data["certificates"] or []:
        cert = c.chosen
        for ext in cert["tbs_certificate"]["extensions"] or []:
            if ext["extn_id"].native == "key_identifier" and (
                ext["extn_value"].parsed.native == ski
            ):
                return cert
    raise TimestampError("signer certificate (by key id) not carried in the token")


def _verify_signature_with_key(
    pub_key: Any, signature: bytes, signed_attrs_der: bytes, digest_alg: Any
) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    try:
        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key.verify(signature, signed_attrs_der, padding.PKCS1v15(), digest_alg)
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key.verify(signature, signed_attrs_der, digest_alg)
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_key.verify(signature, signed_attrs_der)
        else:
            raise TimestampError(f"unsupported TSA key type {type(pub_key).__name__}")
    except InvalidSignature as exc:
        raise TimestampError("TSA signature verification failed") from exc


def verify_token(
    token_der: bytes,
    *,
    expected_digest: bytes,
    expected_nonce: int,
    pinned_key_pem: bytes | None = None,
) -> dict[str, Any]:
    """Offline re-check of an RFC 3161 TimeStampToken (CMS SignedData).

    Checks, each named on failure: CMS structure, message imprint (the
    token must attest exactly the expected digest), nonce, the mandatory
    signed attributes, the signer certificate's presence, genTime against
    the TSA certificate's validity window, and the TSA signature. With
    *pinned_key_pem* the token's signing key must match the pinned key
    (the operator's TSA, not whichever key the token carries).

    Returns a report dict; never raises for verification failures.
    """
    report: dict[str, Any] = {
        "valid": False,
        "errors": [],
        "gen_time": None,
        "serial": None,
        "policy": "",
        "tsa_cert_subject": "",
        "tsa_cert_not_after": None,
        "hash_algorithm": "sha256",
    }

    def fail(msg: str) -> dict[str, Any]:
        report["errors"].append(msg)
        return report

    try:
        _require_asn1crypto()
        from asn1crypto import cms

        token = cms.ContentInfo.load(token_der)
        if token["content_type"].native != "signed_data":
            return fail(f"token is not CMS SignedData ({token['content_type'].native!r})")
        signed_data = token["content"]

        tst, tst_der = _extract_tst_info(signed_data)

        # 1. message imprint: the token attests the digest we expect
        imprint = tst["message_imprint"]
        hash_name = imprint["hash_algorithm"]["algorithm"].native
        if hash_name not in _DIGEST_BY_NAME:
            return fail(f"unsupported imprint hash {hash_name!r}")
        report["hash_algorithm"] = hash_name
        if imprint["hashed_message"].native != expected_digest:
            return fail("message imprint mismatch (token does not attest this digest)")

        # 2. nonce: the reply binds our request (replay protection)
        nonce = tst["nonce"].native if tst["nonce"] is not None else None
        if nonce != expected_nonce:
            return fail(f"nonce mismatch (expected {expected_nonce}, token has {nonce})")

        gen_time: datetime = tst["gen_time"].native
        report["gen_time"] = gen_time.astimezone(timezone.utc).isoformat()
        report["serial"] = tst["serial_number"].native
        report["policy"] = str(tst["policy"].native)

        # 3. the signer and its certificate
        if not signed_data["signer_infos"]:
            return fail("token carries no SignerInfo")
        signer_info = signed_data["signer_infos"][0]
        signed_attrs = signer_info["signed_attrs"]
        if signed_attrs is None:
            return fail("SignerInfo lacks signed attributes (RFC 3161 requires them)")
        attrs = {a["type"].native: a for a in signed_attrs}

        # 4. mandatory signed attributes: contentType + messageDigest
        if "content_type" not in attrs:
            return fail("signed attributes missing contentType")
        if attrs["content_type"]["values"][0].native != "tst_info":
            return fail(
                "signed attribute contentType is not TSTInfo "
                f"({attrs['content_type']['values'][0].native!r})"
            )
        if "message_digest" not in attrs:
            return fail("signed attributes missing messageDigest")
        digest_alg_name = signer_info["digest_algorithm"]["algorithm"].native
        if digest_alg_name not in _DIGEST_BY_NAME:
            return fail(f"unsupported digest algorithm {digest_alg_name!r}")
        md_expected = _DIGEST_BY_NAME[digest_alg_name](tst_der).digest()
        md_recorded = attrs["message_digest"]["values"][0].native
        if md_recorded != md_expected:
            return fail("messageDigest attribute does not match the TSTInfo content")

        cert = _find_signer_cert(signed_data, signer_info)
        subject = cert.subject.native
        report["tsa_cert_subject"] = (
            ", ".join(f"{k}={v}" for k, v in subject.items())
            if isinstance(subject, dict)
            else str(subject)
        )
        validity = cert["tbs_certificate"]["validity"]
        not_after = validity["not_after"].native
        report["tsa_cert_not_after"] = not_after.astimezone(timezone.utc).isoformat()

        # 5. genTime inside the TSA certificate's validity window (LTV hook)
        not_before = validity["not_before"].native
        if not (not_before <= gen_time <= not_after):
            return fail("genTime falls outside the TSA certificate validity window")

        # 6. the signature itself, over the DER-encoded signed attributes.
        # The field is IMPLICIT [0]-tagged; the signature is over the SET OF
        # encoding (RFC 5652 5.3), so re-tag: 0x31 + the tagged chunk body.
        attrs_chunk = signed_attrs.dump()
        if attrs_chunk[0] != 0xA0:
            return fail("signed attributes are not tagged as expected")
        signed_attrs_der = b"\x31" + attrs_chunk[1:]
        signature = signer_info["signature"].native

        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives import serialization

        verify_key = serialization.load_der_public_key(cert.public_key.dump())
        if pinned_key_pem is not None:
            pinned = serialization.load_pem_public_key(pinned_key_pem)

            def _key_bytes(key: Any) -> bytes:
                return key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )

            if _key_bytes(pinned) != _key_bytes(verify_key):
                return fail("pinned TSA key does not match the token's signer key")
        alg = {
            "sha256": _hashes.SHA256,
            "sha384": _hashes.SHA384,
            "sha512": _hashes.SHA512,
        }[digest_alg_name]()
        _verify_signature_with_key(verify_key, signature, signed_attrs_der, alg)

        report["valid"] = True
        return report
    except TimestampError as exc:
        return fail(str(exc))
    except Exception as exc:  # noqa: BLE001 - verification must not leak crashes
        return fail(f"token re-check failed: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# The anchor receipt (x_timestamp extension)
# ---------------------------------------------------------------------------


def chain_head_digest(chain_path: str | Path) -> tuple[str, str]:
    """(receipt_hash, digest) of a chain's head line.

    The digest is sha256 over the exact head line bytes as they live in
    the ledger - the same bytes the TSA attests and the verifier
    re-derives. Chain exports must preserve lines verbatim or re-anchor.
    """
    lines = [
        ln.strip() for ln in Path(chain_path).read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    if not lines:
        raise TimestampError("cannot anchor an empty chain")
    import json as _json

    head = _json.loads(lines[-1])
    receipt_hash = str(head.get("receipt_hash", ""))
    if not receipt_hash.startswith(_HASH_PREFIX):
        raise TimestampError("chain head lacks a receipt_hash; not a receipt ledger")
    digest = _HASH_PREFIX + hashlib.sha256(lines[-1].encode("utf-8")).hexdigest()
    return receipt_hash, digest


def anchor_payload(
    *,
    digest: str,
    parent_receipt: str,
    tsa_url: str,
    nonce: int,
    token_der: bytes,
    gen_time: str,
    serial: int,
    policy: str,
    mode: str = "tsa",
) -> dict[str, Any]:
    """The x_timestamp anchor payload (GUARDRAIL_SCAN shape, like the
    destruction receipt). Hash-only: the token carries the digest, never
    the payload material."""
    return {
        "iss": "raucle-timestamp",
        "typ": "provenance-receipt/v1",
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "operation": "guardrail_scan",
        "parents": [],
        "taint": ["gate:observed"],
        "input_hash": digest.removeprefix(_HASH_PREFIX),
        "ruleset_hash": hashlib.sha256(f"{mode}|{tsa_url}".encode()).hexdigest(),
        "guardrail_verdict": "chain_anchored",
        "x_timestamp": {
            "mode": mode,
            "digest": digest,
            "parent_receipt": parent_receipt,
            "tsa": tsa_url,
            "nonce": nonce,
            "token": base64.b64encode(token_der).decode("ascii"),
            "gen_time": gen_time,
            "serial": serial,
            "policy": policy,
        },
    }


def build_anchor(
    chain_path: str | Path,
    *,
    url: str,
    operator_key_pem: bytes,
    out_dir: str | Path,
    timeout: float = 10.0,
    nonce: int | None = None,
) -> dict[str, Any]:
    """Anchor the chain head through a customer-chosen RFC 3161 TSA.

    Fail-closed at mint: the returned token is verified BEFORE the anchor
    receipt is minted. An unverifiable token never becomes evidence.
    """
    import json as _json

    parent_receipt, digest = chain_head_digest(chain_path)
    nonce = nonce if nonce is not None else new_nonce()
    digest_bytes = bytes.fromhex(digest.removeprefix(_HASH_PREFIX))

    request_der = build_timestamp_request(digest_bytes, nonce)
    reply = submit_timestamp_request(url, request_der, timeout=timeout)
    parsed = parse_response(reply)
    if parsed["status"] != "granted" or parsed["token"] is None:
        why = parsed["status_string"] or parsed["fail_info"] or parsed["status"]
        raise TimestampError(f"TSA refused the request: {why}")
    token_der = parsed["token"]

    token_report = verify_token(token_der, expected_digest=digest_bytes, expected_nonce=nonce)
    if not token_report["valid"]:
        raise TimestampError(
            "TSA token failed its own re-check at mint: " + "; ".join(token_report["errors"])
        )

    from raucle.compliance_pack import _sign_certificate

    payload = anchor_payload(
        digest=digest,
        parent_receipt=parent_receipt,
        tsa_url=url,
        nonce=nonce,
        token_der=token_der,
        gen_time=str(token_report["gen_time"]),
        serial=int(token_report["serial"]),
        policy=str(token_report["policy"]),
    )
    jws, receipt_hash, operator_pub_pem = _sign_certificate(payload, operator_key_pem)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    anchor_path = out_dir / "anchor.json"
    anchor_doc = {
        "receipt_hash": receipt_hash,
        "jws": jws,
        "operator_public_key_pem": operator_pub_pem.decode("ascii"),
        "parent_receipt": parent_receipt,
        "digest": digest,
        "tsa": url,
        "token_der": base64.b64encode(token_der).decode("ascii"),
        "x_timestamp": payload["x_timestamp"],
    }
    anchor_path.write_text(_json.dumps(anchor_doc, indent=2) + "\n", encoding="utf-8")

    return {
        "anchor": str(anchor_path),
        "receipt_hash": receipt_hash,
        "parent_receipt": parent_receipt,
        "digest": digest,
        "tsa": url,
        "gen_time": token_report["gen_time"],
        "serial": token_report["serial"],
        "policy": token_report["policy"],
        "token_valid": True,
        "x_timestamp": payload["x_timestamp"],
    }


def verify_anchor(
    anchor_path: str | Path,
    *,
    operator_public_pem: bytes | None = None,
    chain_path: str | Path | None = None,
) -> dict[str, Any]:
    """Verify an anchor receipt offline.

    Standalone mode (no chain): the operator signature, the embedded
    TimeStampToken re-check (imprint, nonce, genTime, TSA signature) and
    the token copy consistency. The parent cite is recorded as not
    re-checked - the chain was not supplied.

    Chain mode (chain_path): everything above, plus the parent cite
    resolved against the chain and the head-line digest re-derived from
    the cited ledger line. This is the full check; run it that way
    whenever the chain is available.
    """
    import json as _json

    from raucle.provenance import ProvenanceVerifier

    doc = _json.loads(Path(anchor_path).read_text(encoding="utf-8"))
    jws = doc["jws"]
    seg = jws.split(".")
    payload = _json.loads(base64.urlsafe_b64decode(seg[1] + "=" * (-len(seg[1]) % 4)))
    x_ts = payload.get("x_timestamp", {})

    pub: bytes = operator_public_pem or doc.get("operator_public_key_pem", "").encode("ascii")
    kid = hashlib.sha256(pub).hexdigest()[:16]

    report: dict[str, Any] = {
        "valid": False,
        "errors": [],
        "token_valid": False,
        "gen_time": x_ts.get("gen_time"),
        "serial": x_ts.get("serial"),
        "policy": x_ts.get("policy"),
        "tsa": x_ts.get("tsa"),
        "parent_receipt": x_ts.get("parent_receipt"),
        "digest": x_ts.get("digest"),
        "mode": x_ts.get("mode", "tsa"),
        "cite_check": "not re-checked (standalone; supply the chain for the full check)",
    }

    # the operator signature via the public verifier (single-line chain)
    cert_file = Path(anchor_path).with_suffix(".cert-line.jsonl")
    cert_file.write_text(
        _json.dumps({"receipt_hash": doc["receipt_hash"], "jws": jws}) + "\n",
        encoding="utf-8",
    )
    try:
        if chain_path is not None:
            # full mode: append the anchor to a copy of the cited chain
            import tempfile

            with tempfile.NamedTemporaryFile(
                "w", suffix=".jsonl", delete=False, encoding="utf-8"
            ) as tf:
                tf.write(Path(chain_path).read_text(encoding="utf-8"))
                if not Path(chain_path).read_text(encoding="utf-8").endswith("\n"):
                    tf.write("\n")
                tf.write(_json.dumps({"receipt_hash": doc["receipt_hash"], "jws": jws}) + "\n")
                combined = tf.name
            vreport = ProvenanceVerifier(public_keys={kid: pub}).verify_chain(combined)
            report["cite_check"] = "re-checked against the chain"
        else:
            vreport = _verify_standalone(jws, pub, report)
    finally:
        cert_file.unlink(missing_ok=True)

    report["errors"].extend(vreport.errors)
    report["valid"] = bool(vreport.valid)

    # the convenience token copy must agree with the signed payload
    if "token_der" in doc and x_ts.get("token") and doc["token_der"] != x_ts["token"]:
        report["errors"].append("the anchor file's token copy disagrees with the signed token")
        report["valid"] = False
    return report


def _verify_standalone(jws: str, pub: bytes, report: dict[str, Any]) -> Any:
    """Standalone signature + token re-check, tolerating the (correctly
    failing) chain-context cite rule by doing the checks directly."""
    import base64 as _b64
    import json as _json

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    class _R:
        def __init__(self) -> None:
            self.valid = True
            self.errors: list[str] = []

    r = _R()
    seg = jws.split(".")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        key = serialization.load_pem_public_key(pub)
        assert isinstance(key, Ed25519PublicKey)  # anchor receipts are Ed25519
        sig_bytes = _b64.urlsafe_b64decode(seg[2] + "=" * (-len(seg[2]) % 4))
        signing_input = f"{seg[0]}.{seg[1]}".encode("ascii")
        key.verify(sig_bytes, signing_input)  # verify(signature, data)
    except Exception as exc:  # noqa: BLE001
        r.valid = False
        r.errors.append(f"anchor signature verification failed: {exc}")
        return r

    payload = _json.loads(_b64.urlsafe_b64decode(seg[1] + "=" * (-len(seg[1]) % 4)))
    x_ts = payload.get("x_timestamp", {})
    digest = str(x_ts.get("digest", ""))
    if digest != _HASH_PREFIX + payload.get("input_hash", ""):
        r.valid = False
        r.errors.append("x_timestamp digest does not bind the receipt input_hash")
        return r

    mode = x_ts.get("mode")
    if mode == "opentimestamps":
        report["token_valid"] = None  # the .ots proof verifies externally
        return r
    if mode != "tsa":
        r.valid = False
        r.errors.append(f"unsupported x_timestamp mode {mode!r}")
        return r

    token_der = base64.b64decode(x_ts.get("token", ""))
    token_report = verify_token(
        token_der,
        expected_digest=bytes.fromhex(digest.removeprefix(_HASH_PREFIX)),
        expected_nonce=int(x_ts.get("nonce", 0)),
    )
    report["token_valid"] = token_report["valid"]
    if not token_report["valid"]:
        r.valid = False
        r.errors.extend(f"Time Stamp Token: {e}" for e in token_report["errors"])
    elif str(x_ts.get("gen_time")) != str(token_report["gen_time"]):
        r.valid = False
        r.errors.append("recorded gen_time disagrees with the token's genTime")
    return r


# ---------------------------------------------------------------------------
# G3 pairing: the retimestamp plan for long-lived archives
# ---------------------------------------------------------------------------


def retimestamp_plan(chain_path: str | Path) -> dict[str, Any]:
    """Pair G1 anchors with G3 retention stamps.

    Walks the ledger: the archive horizon is the latest retention_until
    (G3) any receipt claims; every TSA-attested anchor is re-checked
    offline and its TSA certificate's expiry compared against the
    horizon. A certificate that expires first means the anchor must be
    re-stamped (same digest, fresh token) before it lapses. The unanchored
    retained tail - records with a retention schedule but no anchor
    covering them - is counted. Bounded disclosure: hashes and dates
    only, never receipt contents.
    """
    import json as _json

    lines = [
        ln.strip() for ln in Path(chain_path).read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    horizon = 0
    anchors: list[dict[str, Any]] = []
    last_anchor_index = -1
    retained_receipts = 0

    for idx, line in enumerate(lines):
        try:
            rec = _json.loads(line)
        except _json.JSONDecodeError:
            continue
        jws = rec.get("jws", "")
        if not isinstance(jws, str) or jws.count(".") < 2:
            continue
        seg = jws.split(".")[1]
        payload = _json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))

        gate = payload.get("x_gate") or {}
        retention_until = int(gate.get("retention_until", 0) or 0)
        if retention_until > 0:
            horizon = max(horizon, retention_until)
            retained_receipts += 1

        x_ts = payload.get("x_timestamp")
        if isinstance(x_ts, dict):
            last_anchor_index = idx
            mode = x_ts.get("mode", "tsa")
            entry: dict[str, Any] = {
                "anchor_receipt": rec.get("receipt_hash", ""),
                "parent_receipt": x_ts.get("parent_receipt", ""),
                "mode": mode,
                "gen_time": x_ts.get("gen_time"),
                "tsa_cert_not_after": None,
                "needs_restamp": False,
                "restamp_by": None,
                "token_valid": None,
            }
            if mode == "tsa":
                token_der = base64.b64decode(x_ts.get("token", ""))
                token_report = verify_token(
                    token_der,
                    expected_digest=bytes.fromhex(
                        str(x_ts.get("digest", "")).removeprefix(_HASH_PREFIX)
                    ),
                    expected_nonce=int(x_ts.get("nonce", 0)),
                )
                entry["token_valid"] = token_report["valid"]
                if not token_report["valid"]:
                    entry["needs_restamp"] = True
                    entry["restamp_by"] = "now (token fails re-check)"
                elif token_report["tsa_cert_not_after"]:
                    not_after = datetime.fromisoformat(token_report["tsa_cert_not_after"])
                    entry["tsa_cert_not_after"] = token_report["tsa_cert_not_after"]
                    not_after_epoch = int(not_after.timestamp())
                    if horizon and not_after_epoch <= horizon:
                        entry["needs_restamp"] = True
                        entry["restamp_by"] = not_after_epoch - _RESTAMP_SAFETY_DAYS * 86400
            anchors.append(entry)

    unanchored = 0
    if last_anchor_index >= 0:
        for idx, line in enumerate(lines):
            if idx <= last_anchor_index:
                continue
            try:
                rec = _json.loads(line)
            except _json.JSONDecodeError:
                continue
            jws = rec.get("jws", "")
            if not isinstance(jws, str) or jws.count(".") < 2:
                continue
            seg = jws.split(".")[1]
            payload = _json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
            gate = payload.get("x_gate") or {}
            if int(gate.get("retention_until", 0) or 0) > 0:
                unanchored += 1
    else:
        unanchored = retained_receipts

    return {
        "archive_horizon": horizon,
        "anchors": anchors,
        "unanchored_receipts": unanchored,
        "restamp_safety_days": _RESTAMP_SAFETY_DAYS,
    }
