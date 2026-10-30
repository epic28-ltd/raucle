"""G1: the three-mode time-source model (RFC 3161 timestamping).

Contract under test (docs/spec/time-source-v1.md):
- Mode 1 (internal, default): local clock, NTP discipline documented, drift
  bounds stated; no extension on the receipt.
- Mode 2 (TSA-attested): a customer-chosen RFC 3161 TSA stamps a digest the
  operator supplies. Hash-only TimeStampReq, always. The anchor receipt
  (x_timestamp) embeds the TimeStampToken; the offline verifier re-checks
  it: CMS parse, message imprint, nonce, genTime, the TSA signature.
- Mode 3 (OpenTimestamps): recorded as an anchoring event with a bounded
  claim; no eIDAS Art 41 presumption (documented, never claimed).

The mock TSA below is a self-hosted Sigstore-TSA-style service: a real
HTTP server on a live socket issuing real RFC 3161 CMS tokens.
"""

import base64
import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from raucle.timestamp import (
    build_anchor,
    build_timestamp_request,
    chain_head_digest,
    new_nonce,
    parse_response,
    retimestamp_plan,
    submit_timestamp_request,
    verify_anchor,
    verify_token,
)

# --------------------------------------------------------------------------
# A self-hosted Sigstore-TSA-style mock: real HTTP, real RFC 3161 tokens
# --------------------------------------------------------------------------

MOCK_POLICY_OID = "1.3.6.1.4.1.53713.0.1.2.1"  # arbitrary, like Sigstore's


class MockTSA:
    """An in-process RFC 3161 timestamp authority over a live socket.

    Issues real CMS SignedData tokens (RSA over signedAttrs, RFC 3161
    mandatory attributes present) so the client and the offline verifier
    exercise the same bytes they would see from a production TSA.
    """

    def __init__(self, *, cert_days: int = 730, gen_time: datetime | None = None):
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.gen_time = gen_time or datetime.now(timezone.utc)
        not_before = self.gen_time - timedelta(days=1)
        not_after = self.gen_time + timedelta(days=cert_days)
        name = cx509.Name(
            [
                cx509.NameAttribute(NameOID.COMMON_NAME, "raucle test TSA"),
                cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "raucle tests"),
            ]
        )
        self.cert = (
            cx509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.rsa_key.public_key())
            .serial_number(cx509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                cx509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
                critical=True,  # RFC 3161: the TSTInfo EKU must be critical
            )
            .sign(self.rsa_key, hashes.SHA256())
        )
        self.cert_der = self.cert.public_bytes(serialization.Encoding.DER)
        self.reject_next = False
        self.corrupt_signature = False
        self._serial = 41
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        assert self._server is not None
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "MockTSA":
        tsa = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server naming
                body = self.rfile.read(int(self.headers["Content-Length"]))
                try:
                    reply = tsa._handle(body)
                    status = 200
                except ValueError as exc:
                    reply = tsa._rejection(str(exc))
                    status = 200  # RFC 3161 rejections ride the 200 body
                self.send_response(status)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *args) -> None:  # keep test output clean
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # -- token construction (real CMS, same shape as a production TSA) ----

    def _handle(self, request_der: bytes) -> bytes:
        from asn1crypto import cms, tsp, x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        if self.reject_next:
            self.reject_next = False
            raise ValueError("mock rejection")
        req = tsp.TimeStampReq.load(request_der)
        if req["message_imprint"]["hash_algorithm"]["algorithm"].native != "sha256":
            raise ValueError("mock supports sha256 only")
        digest = req["message_imprint"]["hashed_message"].native
        nonce = req["nonce"].native
        assert digest  # the imprint is the mock's only payload binding
        gen_time = self.gen_time.replace(tzinfo=timezone.utc)
        self._serial += 1

        tst_info = tsp.TSTInfo(
            {
                "version": 1,
                "policy": MOCK_POLICY_OID,
                "message_imprint": req["message_imprint"],
                "serial_number": self._serial,
                "gen_time": gen_time,
                "accuracy": None,
                "ordering": False,
                "nonce": nonce,
                "tsa": None,
                "extensions": None,
            }
        )
        tst_der = tst_info.dump()

        signing_time = cms.Time({"utc_time": gen_time.replace(microsecond=0)})
        signed_attrs = cms.CMSAttributes(
            [
                {"type": "content_type", "values": ["tst_info"]},
                {
                    "type": "message_digest",
                    "values": [hashlib.sha256(tst_der).digest()],
                },
                {"type": "signing_time", "values": [signing_time]},
            ]
        )
        signed_attrs_der = signed_attrs.dump()
        signature = self.rsa_key.sign(signed_attrs_der, padding.PKCS1v15(), hashes.SHA256())
        if self.corrupt_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])

        # the sid must byte-match the certificate's own issuer/serial
        # (both sides derive from the same DER, the way a real TSA does)
        asn1_cert = x509.Certificate.load(self.cert_der)
        tbs = asn1_cert["tbs_certificate"]
        signer_info = cms.SignerInfo(
            {
                "version": "v1",
                "sid": cms.IssuerAndSerialNumber(
                    {
                        "issuer": tbs["issuer"],
                        "serial_number": tbs["serial_number"].native,
                    }
                ),
                "digest_algorithm": {"algorithm": "sha256", "parameters": None},
                "signed_attrs": signed_attrs,
                "signature_algorithm": {"algorithm": "rsassa_pkcs1v15", "parameters": None},
                "signature": signature,
                "unsigned_attrs": None,
            }
        )
        signed_data = cms.SignedData(
            {
                "version": "v3",
                "digest_algorithms": [{"algorithm": "sha256", "parameters": None}],
                "encap_content_info": {
                    "content_type": "tst_info",
                    "content": tst_info,
                },
                "certificates": [x509.Certificate.load(self.cert_der)],
                "crls": [],
                "signer_infos": [signer_info],
            }
        )
        token = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
        resp = tsp.TimeStampResp(
            {
                "status": {"status": "granted", "status_string": None, "fail_info": None},
                "time_stamp_token": token,
            }
        )
        return resp.dump()

    def _rejection(self, why: str) -> bytes:
        from asn1crypto import tsp
        from asn1crypto.core import Sequence

        # RFC 3161 rejections omit the token; asn1crypto types it as
        # required, so emit the token-less shape with a generic Sequence
        class _Resp(Sequence):
            _fields = [
                ("status", tsp.PKIStatusInfo),
            ]

        resp = _Resp(
            {
                "status": {
                    "status": "rejection",
                    "status_string": [why],
                    "fail_info": {"unaccepted_extensions"},
                },
            }
        )
        return resp.dump()


@pytest.fixture
def mock_tsa():
    tsa = MockTSA().start()
    yield tsa
    tsa.stop()


# --------------------------------------------------------------------------
# Fixtures: a small receipt chain + an operator key
# --------------------------------------------------------------------------


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _mint_receipt_chain(tmp_path, rows: int = 3, retention_days: int = 0, name: str = "chain"):
    """A receipt ledger in the gate's envelope shape: one Ed25519-signed
    {receipt_hash, jws} line per row (guardrail_scan payload; x_gate
    retention_until stamped when retention_days > 0). The minter's public
    PEM lands in <name>-minter-pub.pem for full-chain verification."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from raucle.provenance import _canonical_json, _sha256_hex

    path = tmp_path / f"{name}.jsonl"
    ed = Ed25519PrivateKey.generate()
    pub = ed.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (tmp_path / f"{name}-minter-pub.pem").write_bytes(pub)
    kid = _sha256_hex(pub)[:16]

    iat = 1782998400
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(rows):
            payload = {
                "iss": "raucle-gateway",
                "typ": "provenance-receipt/v1",
                "iat": iat + i,
                "agent_id": "raucle:gateway",
                "agent_key_id": kid,
                "operation": "guardrail_scan",
                "parents": [],
                "taint": ["gate:observed"],
                "input_hash": _sha256_hex(f"args{i}".encode()),
                "ruleset_hash": _sha256_hex(b"policy"),
                "guardrail_verdict": "ALLOW",
                "x_gate": {
                    "decision": "ALLOW",
                    "reason": "policy allow",
                    "tool": "export_records",
                    "agent_id": "agent:svc",
                    "source": "",
                    "destination": "",
                    "policy": "",
                    "rule_id": "r1",
                    "acting_for": "",
                    "latency_us": 100,
                    "trace_id": "",
                    "approval_id": "",
                    "retention_until": (iat + retention_days * 86400 if retention_days else 0),
                },
            }
            header = {
                "alg": "EdDSA",
                "typ": "provenance-receipt/v1",
                "kid": kid,
                "crit": ["raucle/v1"],
                "raucle/v1": "provenance",
            }
            signing_input = (
                f"{_b64u(_canonical_json(header))}.{_b64u(_canonical_json(payload))}"
            ).encode()
            sig = ed.sign(signing_input)
            jws = f"{signing_input.decode('ascii')}.{_b64u(sig)}"
            receipt_hash = "sha256:" + _sha256_hex(jws.encode("ascii"))
            fh.write(json.dumps({"receipt_hash": receipt_hash, "jws": jws}) + "\n")
    return path


def _make_chain(tmp_path, rows: int = 3):
    return _mint_receipt_chain(tmp_path, rows=rows, name="chain")


def _operator_key(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (tmp_path / "operator-private.pem").write_bytes(pem)
    return pem, pub


# --------------------------------------------------------------------------
# Mode 2 core: the RFC 3161 client
# --------------------------------------------------------------------------


def test_request_is_hash_only_canonical_der():
    """The TimeStampReq carries a digest and nothing else (privacy by
    default), and the hand-rolled DER is byte-identical to the asn1crypto
    reference encoding."""
    import hashlib

    from asn1crypto import tsp

    digest = hashlib.sha256(b"receipt head material").digest()
    nonce = new_nonce()
    der = build_timestamp_request(digest, nonce)

    req = tsp.TimeStampReq.load(der)
    assert req["version"].native == "v1"
    assert req["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"
    assert req["message_imprint"]["hashed_message"].native == digest
    assert req["nonce"].native == nonce
    assert req["cert_req"].native is True

    reference = tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": tsp.MessageImprint(
                {
                    "hash_algorithm": {"algorithm": "sha256", "parameters": None},
                    "hashed_message": digest,
                }
            ),
            "req_policy": None,
            "nonce": nonce,
            "cert_req": True,
            "extensions": None,
        }
    )
    assert reference.dump() == der, "hand-rolled DER diverges from reference"
    # hash-only: nothing but the 32-byte digest reached the wire
    assert b"receipt head material" not in der


def test_submit_and_parse_granted(mock_tsa):
    import hashlib

    digest = hashlib.sha256(b"the chain head").digest()
    nonce = new_nonce()
    req = build_timestamp_request(digest, nonce)
    reply = submit_timestamp_request(mock_tsa.url, req, timeout=5.0)
    parsed = parse_response(reply)
    assert parsed["status"] == "granted"
    assert parsed["token"] is not None

    report = verify_token(parsed["token"], expected_digest=digest, expected_nonce=nonce)
    assert report["valid"], report["errors"]
    assert report["serial"] == 42  # the mock's first stamp
    assert report["policy"] == MOCK_POLICY_OID
    assert report["gen_time"] is not None
    assert "raucle test TSA" in report["tsa_cert_subject"]


def test_rejected_status_is_a_named_error(mock_tsa):
    import hashlib

    mock_tsa.reject_next = True
    req = build_timestamp_request(hashlib.sha256(b"x").digest(), new_nonce())
    reply = submit_timestamp_request(mock_tsa.url, req, timeout=5.0)
    parsed = parse_response(reply)
    assert parsed["status"] != "granted"
    assert parsed["token"] is None
    assert parsed["fail_info"], "rejection must name the failure"


def test_verify_imprint_mismatch_is_named():
    import hashlib

    tsa = MockTSA().start()
    try:
        digest = hashlib.sha256(b"real head").digest()
        nonce = new_nonce()
        reply = submit_timestamp_request(
            tsa.url, build_timestamp_request(digest, nonce), timeout=5.0
        )
        token = parse_response(reply)["token"]
    finally:
        tsa.stop()

    report = verify_token(
        token, expected_digest=hashlib.sha256(b"tampered head").digest(), expected_nonce=nonce
    )
    assert not report["valid"]
    assert any("message imprint" in e for e in report["errors"])


def test_verify_nonce_mismatch_is_named(mock_tsa):
    import hashlib

    digest = hashlib.sha256(b"head").digest()
    reply = submit_timestamp_request(
        mock_tsa.url, build_timestamp_request(digest, new_nonce()), timeout=5.0
    )
    token = parse_response(reply)["token"]
    report = verify_token(token, expected_digest=digest, expected_nonce=999)
    assert not report["valid"]
    assert any("nonce" in e for e in report["errors"])


def test_verify_tampered_signature_is_named(mock_tsa):
    import hashlib

    mock_tsa.corrupt_signature = True
    digest = hashlib.sha256(b"head").digest()
    nonce = new_nonce()
    reply = submit_timestamp_request(
        mock_tsa.url, build_timestamp_request(digest, nonce), timeout=5.0
    )
    token = parse_response(reply)["token"]
    report = verify_token(token, expected_digest=digest, expected_nonce=nonce)
    assert not report["valid"]
    assert any("signature" in e for e in report["errors"])


def test_verify_pinned_key(mock_tsa):
    import hashlib

    from cryptography.hazmat.primitives import serialization

    digest = hashlib.sha256(b"head").digest()
    nonce = new_nonce()
    reply = submit_timestamp_request(
        mock_tsa.url, build_timestamp_request(digest, nonce), timeout=5.0
    )
    token = parse_response(reply)["token"]

    good_pem = mock_tsa.cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    report = verify_token(
        token, expected_digest=digest, expected_nonce=nonce, pinned_key_pem=good_pem
    )
    assert report["valid"], report["errors"]

    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    wrong_pem = (
        _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    report = verify_token(
        token, expected_digest=digest, expected_nonce=nonce, pinned_key_pem=wrong_pem
    )
    assert not report["valid"]
    assert any("pinned" in e for e in report["errors"])


def test_gen_time_outside_cert_validity_is_named():
    """The LTV hook: a token whose genTime falls outside the TSA cert's
    validity window fails verification with a named error. This is the
    check that makes the retimestamp plan meaningful."""
    import hashlib

    # cert valid for 730 days from 2024; gen_time stamped 2030 (outside)
    tsa = MockTSA(
        cert_days=730,
        gen_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
    ).start()
    try:
        # gen_time used for TSTInfo is the mock's configured clock (2024),
        # inside the window; instead force an outside window by clock
        tsa.gen_time = datetime(2030, 6, 1, tzinfo=timezone.utc)
        digest = hashlib.sha256(b"head").digest()
        nonce = new_nonce()
        reply = submit_timestamp_request(
            tsa.url, build_timestamp_request(digest, nonce), timeout=5.0
        )
        token = parse_response(reply)["token"]
    finally:
        tsa.stop()
    report = verify_token(token, expected_digest=digest, expected_nonce=nonce)
    assert not report["valid"]
    assert any("validity" in e for e in report["errors"])


# --------------------------------------------------------------------------
# The anchor receipt (x_timestamp) and the offline verifier re-check
# --------------------------------------------------------------------------


def _mint_anchor(tmp_path, mock_tsa, chain=None):
    operator_priv, operator_pub = _operator_key(tmp_path)
    chain = chain or _make_chain(tmp_path)
    manifest = build_anchor(
        chain,
        url=mock_tsa.url,
        operator_key_pem=operator_priv,
        out_dir=tmp_path / "anchor-out",
    )
    return manifest, operator_priv, operator_pub, chain


def test_build_anchor_writes_receipt_and_token(tmp_path, mock_tsa):
    manifest, _priv, _pub, chain = _mint_anchor(tmp_path, mock_tsa)
    anchor = json.loads((tmp_path / "anchor-out" / "anchor.json").read_text())
    assert anchor["jws"]
    assert anchor["token_der"]
    assert manifest["parent_receipt"].startswith("sha256:")
    # the anchor binds the chain head: digest = sha256 over the head line
    head_receipt, head_digest = chain_head_digest(chain)
    assert manifest["parent_receipt"] == head_receipt
    import hashlib

    lines = [ln for ln in chain.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert manifest["digest"] == "sha256:" + hashlib.sha256(lines[-1].encode()).hexdigest()
    assert manifest["x_timestamp"]["mode"] == "tsa"
    assert manifest["x_timestamp"]["tsa"] == mock_tsa.url


def test_anchor_verifies_offline_through_the_standard_verifier(tmp_path, mock_tsa):
    """The anchor receipt verifies with the public verifier, no network,
    and the embedded TimeStampToken re-checks against the chain head."""
    manifest, _priv, pub, _chain = _mint_anchor(tmp_path, mock_tsa)
    report = verify_anchor(manifest["anchor"], operator_public_pem=pub)
    assert report["valid"], report["errors"]
    assert report["token_valid"] is True


def test_anchor_token_tamper_fails_the_chain_verification(tmp_path, mock_tsa):
    """A byte-edited TimeStampToken embedded in a receipt makes the whole
    chain verification INVALID, with the failure named. The tampered
    payload is RE-SIGNED by the operator key so the operator signature is
    legitimate and the token re-check is the only thing that fails."""
    from raucle.provenance import ProvenanceVerifier

    manifest, priv, pub, chain = _mint_anchor(tmp_path, mock_tsa)
    anchor_path = tmp_path / "anchor-out" / "anchor.json"

    # 1. append the good anchor to the chain it cites; the verifier needs
    #    BOTH keys: the chain minter's and the operator's
    anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    with open(chain, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"receipt_hash": anchor["receipt_hash"], "jws": anchor["jws"]}) + "\n")
    keys = {**_minter_keys(tmp_path), _kid_of(anchor["jws"]): pub}
    assert ProvenanceVerifier(public_keys=keys).verify_chain(chain).valid

    # 2. re-sign a payload whose embedded token has one flipped byte
    seg = anchor["jws"].split(".")
    header = json.loads(base64.urlsafe_b64decode(seg[0] + "=" * (-len(seg[0]) % 4)))
    payload = json.loads(base64.urlsafe_b64decode(seg[1] + "=" * (-len(seg[1]) % 4)))
    tok = bytearray(base64.b64decode(payload["x_timestamp"]["token"]))
    tok[-1] ^= 0xFF
    payload["x_timestamp"]["token"] = base64.b64encode(bytes(tok)).decode()
    jws2 = recompute_jws(header, payload, _ed25519_from_pem(priv))
    receipt_hash2 = "sha256:" + hashlib.sha256(jws2.encode("ascii")).hexdigest()
    with open(chain, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"receipt_hash": receipt_hash2, "jws": jws2}) + "\n")

    vreport = ProvenanceVerifier(public_keys=keys).verify_chain(chain)
    assert not vreport.valid
    assert any("Time Stamp Token" in e for e in vreport.errors)


def test_anchor_citing_missing_receipt_is_named(tmp_path, mock_tsa):
    """The anchor must cite a receipt present in the chain it is verified
    with - ghost-citing fails like x_finding."""
    from raucle.provenance import ProvenanceVerifier

    manifest, priv, pub, _chain = _mint_anchor(tmp_path, mock_tsa)
    anchor_path = tmp_path / "anchor-out" / "anchor.json"
    anchor = json.loads(anchor_path.read_text(encoding="utf-8"))

    seg = anchor["jws"].split(".")
    header = json.loads(base64.urlsafe_b64decode(seg[0] + "=" * (-len(seg[0]) % 4)))
    payload = json.loads(base64.urlsafe_b64decode(seg[1] + "=" * (-len(seg[1]) % 4)))
    payload["x_timestamp"]["parent_receipt"] = "sha256:" + "0" * 64
    anchor["jws"] = recompute_jws(header, payload, _ed25519_from_pem(priv))
    anchor["receipt_hash"] = "sha256:" + hashlib.sha256(anchor["jws"].encode("ascii")).hexdigest()
    anchor_line = tmp_path / "ghost.jsonl"
    anchor_line.write_text(
        json.dumps({"receipt_hash": anchor["receipt_hash"], "jws": anchor["jws"]}) + "\n",
        encoding="utf-8",
    )
    vreport = ProvenanceVerifier(public_keys={payload["agent_key_id"]: pub}).verify_chain(
        anchor_line
    )
    assert not vreport.valid
    assert any("not in the chain" in e for e in vreport.errors)


def recompute_jws(header: dict, payload: dict, priv) -> str:
    """Re-sign a (possibly edited) payload with the same canonical JWS
    shape the gate uses; header/payload must be the DECODED objects."""

    def _b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _canon(obj) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

    sig = priv.sign(f"{_b64u(_canon(header))}.{_b64u(_canon(payload))}".encode("ascii"))
    return f"{_b64u(_canon(header))}.{_b64u(_canon(payload))}.{_b64u(sig)}"


def test_recorded_gen_time_tamper_is_named(tmp_path, mock_tsa):
    """A genTime field edited after the fact (record != token) fails."""
    from raucle.provenance import ProvenanceVerifier

    manifest, priv, pub, _chain = _mint_anchor(tmp_path, mock_tsa)
    anchor_path = tmp_path / "anchor-out" / "anchor.json"
    anchor = json.loads(anchor_path.read_text(encoding="utf-8"))

    seg = anchor["jws"].split(".")
    header = json.loads(base64.urlsafe_b64decode(seg[0] + "=" * (-len(seg[0]) % 4)))
    payload = json.loads(base64.urlsafe_b64decode(seg[1] + "=" * (-len(seg[1]) % 4)))
    payload["x_timestamp"]["gen_time"] = "2031-01-01T00:00:00+00:00"
    anchor["jws"] = recompute_jws(header, payload, _ed25519_from_pem(priv))
    anchor["receipt_hash"] = "sha256:" + hashlib.sha256(anchor["jws"].encode("ascii")).hexdigest()
    line_file = tmp_path / "gentime-tamper.jsonl"
    line_file.write_text(
        json.dumps({"receipt_hash": anchor["receipt_hash"], "jws": anchor["jws"]}) + "\n",
        encoding="utf-8",
    )
    vreport = ProvenanceVerifier(public_keys={payload["agent_key_id"]: pub}).verify_chain(line_file)
    assert not vreport.valid
    assert any("gen_time" in e for e in vreport.errors)


def _ed25519_from_pem(pem: bytes):
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_private_key(pem, password=None)


def test_opentimestamps_mode_records_bounded_claim(tmp_path):
    """Mode 3: an OpenTimestamps anchor records the anchoring event with a
    bounded claim. Appended to the chain it cites, the full-chain verifier
    re-checks digest consistency, the re-derivation from the cited ledger
    line and the cite itself; it never claims the OTS proof verifies and
    never claims an eIDAS Art 41 presumption. A tampered digest fails."""
    from raucle.provenance import ProvenanceVerifier, _sha256_hex

    chain = _make_chain(tmp_path)
    lines = [ln for ln in chain.read_text(encoding="utf-8").splitlines() if ln.strip()]
    head = json.loads(lines[-1])
    digest = "sha256:" + _sha256_hex(lines[-1].encode())
    minter_pub = (tmp_path / "chain-minter-pub.pem").read_bytes()
    minter_kid = json.loads(
        base64.urlsafe_b64decode(
            head["jws"].split(".")[1] + "=" * (-len(head["jws"].split(".")[1]) % 4)
        )
    )["agent_key_id"]

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = _sha256_hex(pub)[:16]
    keys = {minter_kid: minter_pub, kid: pub}

    def _ots_jws(digest_value: str) -> str:
        payload = {
            "iss": "raucle-timestamp",
            "typ": "provenance-receipt/v1",
            "iat": 1782998400,
            "agent_id": "raucle:timestamp",
            "agent_key_id": kid,
            "operation": "guardrail_scan",
            "parents": [],
            "taint": ["gate:observed"],
            "input_hash": digest_value.removeprefix("sha256:"),
            "ruleset_hash": _sha256_hex(b"opentimestamps"),
            "guardrail_verdict": "chain_anchored",
            "x_timestamp": {
                "mode": "opentimestamps",
                "digest": digest_value,
                "parent_receipt": head["receipt_hash"],
                "ots": "RlVFREFQzogbW9jayBvdHMK",  # placeholder proof bytes
            },
        }
        header = {
            "alg": "EdDSA",
            "typ": "provenance-receipt/v1",
            "kid": kid,
            "crit": ["raucle/v1"],
            "raucle/v1": "provenance",
        }
        return recompute_jws(header, payload, priv)

    # the OTS anchor appended to the chain it cites verifies in full
    full_chain = tmp_path / "chain-with-ots.jsonl"
    jws = _ots_jws(digest)
    rh = "sha256:" + _sha256_hex(jws.encode("ascii"))
    with open(full_chain, "w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(ln + "\n")
        fh.write(json.dumps({"receipt_hash": rh, "jws": jws}) + "\n")
    vreport = ProvenanceVerifier(public_keys=keys).verify_chain(full_chain)
    assert vreport.valid, vreport.errors

    # a tampered digest does not re-derive -> INVALID with the digest named
    jws2 = _ots_jws("sha256:" + "0" * 64)
    rh2 = "sha256:" + _sha256_hex(jws2.encode("ascii"))
    with open(full_chain, "w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(ln + "\n")
        fh.write(json.dumps({"receipt_hash": rh2, "jws": jws2}) + "\n")
    vreport2 = ProvenanceVerifier(public_keys=keys).verify_chain(full_chain)
    assert not vreport2.valid
    assert any("digest" in e for e in vreport2.errors)


def test_missing_timestamp_extra_fails_closed(tmp_path, mock_tsa, monkeypatch):
    """A receipt claiming a TSA token cannot silently verify in an install
    without the asn1crypto parser: fail closed, named error."""
    import builtins

    from raucle.provenance import ProvenanceVerifier

    manifest, _priv, pub, _chain = _mint_anchor(tmp_path, mock_tsa)
    anchor = json.loads((tmp_path / "anchor-out" / "anchor.json").read_text(encoding="utf-8"))
    line_file = tmp_path / "anchor-line.jsonl"
    line_file.write_text(
        json.dumps({"receipt_hash": anchor["receipt_hash"], "jws": anchor["jws"]}) + "\n",
        encoding="utf-8",
    )

    real_import = builtins.__import__

    def _no_asn1(name, *args, **kwargs):
        if name == "asn1crypto" or name.startswith("asn1crypto."):
            raise ImportError("asn1crypto not installed (raucle[timestamp] extra required)")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_asn1)
    import sys

    monkeypatch.delitem(sys.modules, "asn1crypto", raising=False)
    vreport = ProvenanceVerifier(public_keys={_kid_of(anchor["jws"]): pub}).verify_chain(line_file)
    assert not vreport.valid
    assert any("timestamp" in e and "extra" in e for e in vreport.errors)


def _kid_of(jws: str) -> str:
    seg = jws.split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    return payload["agent_key_id"]


def _minter_keys(tmp_path, name: str = "chain") -> dict:
    """The fixture chain minter's key map for full-chain verification."""
    from raucle.provenance import _sha256_hex

    pub = (tmp_path / f"{name}-minter-pub.pem").read_bytes()
    return {_sha256_hex(pub)[:16]: pub}


# --------------------------------------------------------------------------
# G3 pairing: the retimestamp plan
# --------------------------------------------------------------------------


def _make_chain_with_retention(tmp_path, retention_days: int = 2555):
    """A chain whose gate receipts carry x_gate.retention_until (G3)."""
    return _mint_receipt_chain(tmp_path, rows=3, retention_days=retention_days, name="ret-chain")


def test_retimestamp_plan_flags_expiring_anchor(tmp_path, mock_tsa):
    """The plan pairs G1 anchors with G3 retention: a TSA cert that expires
    before the archive's retention horizon must be restamped, with a
    restamp-by date; the unanchored tail is listed."""
    chain = _make_chain_with_retention(tmp_path, retention_days=3650)  # 10 years
    # anchor the head with a TSA whose cert lasts 730 days
    operator_priv, operator_pub = _operator_key(tmp_path)
    manifest = build_anchor(
        chain, url=mock_tsa.url, operator_key_pem=operator_priv, out_dir=tmp_path / "a2"
    )
    # append the anchor so the plan sees it in the chain
    anchor = json.loads((tmp_path / "a2" / "anchor.json").read_text(encoding="utf-8"))
    with open(chain, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"receipt_hash": anchor["receipt_hash"], "jws": anchor["jws"]}) + "\n")

    plan = retimestamp_plan(chain)
    assert plan["archive_horizon"] == 1782998400 + 3650 * 86400
    assert len(plan["anchors"]) == 1
    a = plan["anchors"][0]
    assert a["anchor_receipt"] == manifest["receipt_hash"]
    assert a["needs_restamp"] is True  # 730-day cert < 10-year horizon
    assert a["restamp_by"] is not None
    assert plan["unanchored_receipts"] == 0  # anchor is the last line


def test_retimestamp_plan_clean_when_cert_outlasts_horizon(tmp_path, mock_tsa):
    chain = _make_chain_with_retention(tmp_path, retention_days=365)
    operator_priv, _pub = _operator_key(tmp_path)
    build_anchor(chain, url=mock_tsa.url, operator_key_pem=operator_priv, out_dir=tmp_path / "a3")
    anchor = json.loads((tmp_path / "a3" / "anchor.json").read_text(encoding="utf-8"))
    with open(chain, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"receipt_hash": anchor["receipt_hash"], "jws": anchor["jws"]}) + "\n")
    plan = retimestamp_plan(chain)
    assert plan["anchors"][0]["needs_restamp"] is False  # 730-day cert > 1-year horizon
    assert plan["anchors"][0]["restamp_by"] is None


def test_plan_lists_unanchored_retained_tail(tmp_path):
    chain = _make_chain_with_retention(tmp_path, retention_days=365)
    plan = retimestamp_plan(chain)
    assert plan["anchors"] == []
    assert plan["unanchored_receipts"] == 3


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def test_cli_stamp_verify_plan(tmp_path, mock_tsa, capsys):
    from raucle.cli import main

    chain = _make_chain_with_retention(tmp_path, retention_days=2555)
    operator_priv, _pub = _operator_key(tmp_path)
    out = tmp_path / "cli-anchor-dir"

    rc = main(
        [
            "timestamp",
            "stamp",
            "--chain",
            str(chain),
            "--url",
            mock_tsa.url,
            "--operator-key",
            str(tmp_path / "operator-private.pem"),
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    out_text = capsys.readouterr().out
    assert "anchor receipt" in out_text
    assert (out / "anchor.json").exists()

    rc = main(["timestamp", "verify", "--anchor", str(out / "anchor.json")])
    capsys.readouterr()
    assert rc == 0

    rc = main(["timestamp", "plan", "--chain", str(chain)])
    out_text = capsys.readouterr().out
    assert rc == 0
    assert "retention horizon" in out_text or "archive horizon" in out_text


def test_cli_verify_bad_token_exits_nonzero(tmp_path, mock_tsa):
    from raucle.cli import main

    chain = _make_chain(tmp_path)
    operator_priv, _pub = _operator_key(tmp_path)
    out = tmp_path / "cli-anchor-dir"
    rc = main(
        [
            "timestamp",
            "stamp",
            "--chain",
            str(chain),
            "--url",
            mock_tsa.url,
            "--operator-key",
            str(tmp_path / "operator-private.pem"),
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    anchor_path = out / "anchor.json"
    # flip a byte in the embedded token
    data = json.loads(anchor_path.read_text(encoding="utf-8"))
    tok = bytearray(base64.b64decode(data["token_der"]))
    tok[-1] ^= 0xFF
    data["token_der"] = base64.b64encode(bytes(tok)).decode()
    anchor_path.write_text(json.dumps(data), encoding="utf-8")
    rc_verify = main(["timestamp", "verify", "--anchor", str(anchor_path)])
    assert rc_verify != 0
