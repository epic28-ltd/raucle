"""Timestamp family edge tests: request validation, DER edge cases,
token re-check failure paths (each named on failure), anchor mint
fail-closed paths, standalone vs chain verification, and the retimestamp
plan's ledger-walk edges.

Complements tests/test_timestamping.py (happy paths + main invariants).
"""

import base64
import hashlib
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from raucle import timestamp as ts
from raucle.timestamp import (
    TimestampError,
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
from tests.test_timestamping import MOCK_POLICY_OID, MockTSA, _mint_receipt_chain, _operator_key
from tests.test_timestamping import _b64u as _b64u  # re-export for local minting


@pytest.fixture
def mock_tsa():
    tsa = MockTSA().start()
    yield tsa
    tsa.stop()


# --------------------------------------------------------------------------
# TimeStampReq validation + DER edge cases
# --------------------------------------------------------------------------


def test_request_rejects_non_sha256_length_digest():
    with pytest.raises(TimestampError, match="must be 32 bytes"):
        build_timestamp_request(b"short", 1)


def test_request_rejects_non_positive_nonce():
    with pytest.raises(TimestampError, match="safe-integer"):
        build_timestamp_request(hashlib.sha256(b"x").digest(), 0)


def test_request_rejects_oversized_nonce():
    with pytest.raises(TimestampError, match="safe-integer"):
        build_timestamp_request(hashlib.sha256(b"x").digest(), 2**53 + 1)


def test_request_nonce_with_sign_bit_round_trips():
    """A nonce whose first DER body byte has its high bit set must gain the
    minimal leading zero byte (BER integer rule) and still round-trip."""
    nonce = (2**52) | (2**51) | 3  # 53 bits, high bit of the body set
    der = build_timestamp_request(hashlib.sha256(b"x").digest(), nonce)
    from asn1crypto import tsp

    req = tsp.TimeStampReq.load(der)
    assert req["nonce"].native == nonce


def test_der_len_long_form():
    body = b"a" * 300
    tlv = ts._tlv(0x04, body)
    assert tlv[:2] == b"\x04\x82" and tlv[2:4] == len(body).to_bytes(2, "big")
    assert ts._unwrap(tlv) == body


def test_unwrap_empty_chunk_is_named():
    with pytest.raises(TimestampError, match="empty DER chunk"):
        ts._unwrap(b"")


# --------------------------------------------------------------------------
# Transport: the TSA must answer with the RFC 3161 content type
# --------------------------------------------------------------------------


def test_submit_rejects_wrong_content_type():
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    try:
        thread.start()
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        req = build_timestamp_request(hashlib.sha256(b"x").digest(), new_nonce())
        with pytest.raises(TimestampError, match="unexpected Content-Type"):
            submit_timestamp_request(url, req, timeout=5.0)
    finally:
        srv.shutdown()
        srv.server_close()


# --------------------------------------------------------------------------
# verify_token: failure paths, each named
# --------------------------------------------------------------------------


def _get_token(tsa, *, corrupt=False):
    if corrupt:
        tsa.corrupt_signature = True
    digest = hashlib.sha256(b"chain head edge").digest()
    nonce = new_nonce()
    reply = submit_timestamp_request(tsa.url, build_timestamp_request(digest, nonce), timeout=5.0)
    token = parse_response(reply)["token"]
    if corrupt:
        tsa.corrupt_signature = False
    return token, digest, nonce


def test_verify_non_der_input_is_caught_not_raised():
    report = verify_token(b"definitely not DER", expected_digest=b"\x00" * 32, expected_nonce=1)
    assert not report["valid"]
    assert any("token re-check failed" in e for e in report["errors"])


def test_verify_rejects_non_signed_data_token():
    from asn1crypto import cms

    token = cms.ContentInfo({"content_type": "data", "content": b"\x04\x03abc"}).dump()
    report = verify_token(token, expected_digest=b"\x00" * 32, expected_nonce=1)
    assert not report["valid"]
    assert any("not CMS SignedData" in e for e in report["errors"])


def test_verify_rejects_wrong_encap_content_type():
    from asn1crypto import cms, tsp

    tsa = MockTSA().start()
    try:
        token, _dg, _nc = _get_token(tsa)
        ci = cms.ContentInfo.load(token)
        sd = ci["content"]
        sd["encap_content_info"]["content_type"] = "data"
        report = verify_token(ci.dump(), expected_digest=b"\x00" * 32, expected_nonce=1)
        assert not report["valid"]
        assert any("not TSTInfo" in e for e in report["errors"])
    finally:
        tsa.stop()
    del tsp


def test_verify_pkcs7_shaped_v1_with_malformed_tst():
    """The v1 branch that unwraps a bare-content (PKCS#7 shape) token, fed
    a TSTInfo body that will not parse, fails with a named error."""
    from asn1crypto import cms

    sd = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [],
            "encap_content_info": {
                "content_type": "tst_info",
                "content": cms.OctetString(b"not a TSTInfo at all"),  # bare PKCS#7 shape
            },
            "certificates": [],
            "crls": [],
            "signer_infos": [],
        }
    )
    token = cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()
    report = verify_token(token, expected_digest=b"\x00" * 32, expected_nonce=1)
    assert not report["valid"]
    assert any("malformed TSTInfo" in e or "re-check failed" in e for e in report["errors"])


def _unsigned_token(tst_fields, version="v3"):
    """A structurally minimal CMS token (no signer_infos): enough for the
    checks that run before signer inspection, e.g. the imprint hash test."""
    from asn1crypto import cms, tsp

    sd = cms.SignedData(
        {
            "version": version,
            "digest_algorithms": [],
            "encap_content_info": {
                "content_type": "tst_info",
                "content": tsp.TSTInfo(tst_fields),
            },
            "certificates": [],
            "crls": [],
            "signer_infos": [],
        }
    )
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()


def test_verify_rejects_unsupported_imprint_hash():

    tst = {
        "version": 1,
        "policy": MOCK_POLICY_OID,
        "message_imprint": {
            "hash_algorithm": {"algorithm": "sha1", "parameters": None},
            "hashed_message": b"\x00" * 32,
        },
        "serial_number": 7,
        "gen_time": datetime.now(timezone.utc),
        "ordering": False,
        "nonce": 1,
        "extensions": None,
    }
    report = verify_token(_unsigned_token(tst), expected_digest=b"\x00" * 32, expected_nonce=1)
    assert not report["valid"]
    assert any("unsupported imprint hash" in e for e in report["errors"])


def _load_token(token):
    from asn1crypto import cms

    return cms.ContentInfo.load(token)


def test_verify_no_signer_infos_is_named():
    from asn1crypto import tsp

    tsa = MockTSA().start()
    try:
        token, dg, nc = _get_token(tsa)
        ci = _load_token(token)
        ci["content"]["signer_infos"] = []
        report = verify_token(ci.dump(), expected_digest=dg, expected_nonce=nc)
        assert not report["valid"]
        assert any("no SignerInfo" in e for e in report["errors"])
    finally:
        tsa.stop()
    del tsp


def test_verify_missing_signed_attrs_is_named():
    tsa = MockTSA().start()
    try:
        token, dg, nc = _get_token(tsa)
        ci = _load_token(token)
        ci["content"]["signer_infos"][0]["signed_attrs"] = None
        report = verify_token(ci.dump(), expected_digest=dg, expected_nonce=nc)
        assert not report["valid"]
        assert any("signed attributes" in e for e in report["errors"])
    finally:
        tsa.stop()


def test_verify_unresolvable_signer_cert_is_named(mock_tsa):
    from asn1crypto import cms
    from asn1crypto import x509 as ax509

    token, dg, nc = _get_token(mock_tsa)
    ci = _load_token(token)
    asn1_cert = ax509.Certificate.load(ci["content"]["certificates"][0].dump())
    si = ci["content"]["signer_infos"][0]
    assert si["sid"].name == "issuer_and_serial_number"
    si["sid"] = cms.IssuerAndSerialNumber(
        {
            "issuer": asn1_cert["tbs_certificate"]["issuer"],
            "serial_number": asn1_cert["tbs_certificate"]["serial_number"].native + 1,
        }
    )
    report = verify_token(ci.dump(), expected_digest=dg, expected_nonce=nc)
    assert not report["valid"]
    assert any("signer certificate not carried" in e for e in report["errors"])


def test_verify_signed_attr_failures_are_named(mock_tsa):
    token, dg, nc = _get_token(mock_tsa)

    def verify_mutated(mutate):
        ci = _load_token(token)
        mutate(ci)
        return verify_token(ci.dump(), expected_digest=dg, expected_nonce=nc)

    def drop_content_type(ci):
        attrs = ci["content"]["signer_infos"][0]["signed_attrs"]
        ci["content"]["signer_infos"][0]["signed_attrs"] = [
            a for a in attrs if a["type"].native != "content_type"
        ]

    def wrong_content_type(ci):
        attrs = ci["content"]["signer_infos"][0]["signed_attrs"]
        for a in attrs:
            if a["type"].native == "content_type":
                a["values"][0] = "data"

    def drop_message_digest(ci):
        attrs = ci["content"]["signer_infos"][0]["signed_attrs"]
        ci["content"]["signer_infos"][0]["signed_attrs"] = [
            a for a in attrs if a["type"].native != "message_digest"
        ]

    def bad_digest_alg(ci):
        ci["content"]["signer_infos"][0]["digest_algorithm"]["algorithm"] = "sha1"

    def tamper_message_digest(ci):
        attrs = ci["content"]["signer_infos"][0]["signed_attrs"]
        for a in attrs:
            if a["type"].native == "message_digest":
                a["values"][0] = b"\x00" * 32

    r = verify_mutated(drop_content_type)
    assert any("missing contentType" in e for e in r["errors"])
    r = verify_mutated(wrong_content_type)
    assert any("contentType is not TSTInfo" in e for e in r["errors"])
    r = verify_mutated(drop_message_digest)
    assert any("missing messageDigest" in e for e in r["errors"])
    r = verify_mutated(bad_digest_alg)
    assert any("unsupported digest algorithm" in e for e in r["errors"])
    r = verify_mutated(tamper_message_digest)
    assert any("messageDigest attribute does not match" in e for e in r["errors"])


def test_verify_unsupported_signer_key_type_is_named(mock_tsa):
    """A signer certificate whose key type the re-check does not support
    fails with a named error (never a crash, never a silent pass)."""
    from asn1crypto import x509 as ax509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import dsa

    token, dg, nc = _get_token(mock_tsa)
    ci = _load_token(token)
    params = dsa.generate_parameters(key_size=1024)
    dkey = params.generate_private_key()
    spki = dkey.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert = ax509.Certificate.load(ci["content"]["certificates"][0].dump())
    from asn1crypto import keys as akeys

    cert["tbs_certificate"]["subject_public_key_info"] = akeys.PublicKeyInfo.load(spki)
    ci["content"]["certificates"] = [cert]
    report = verify_token(ci.dump(), expected_digest=dg, expected_nonce=nc)
    assert not report["valid"]
    assert any("unsupported TSA key type" in e for e in report["errors"])


# --------------------------------------------------------------------------
# Chain head digest edges + anchor mint fail-closed
# --------------------------------------------------------------------------


def test_chain_head_empty_file_is_named(tmp_path):
    p = tmp_path / "empty.jsonl"
    p.write_text("\n\n", encoding="utf-8")
    with pytest.raises(TimestampError, match="empty chain"):
        chain_head_digest(p)


def test_chain_head_without_receipt_hash_is_named(tmp_path):
    p = tmp_path / "notchain.jsonl"
    p.write_text('{"jws": "x"}\n', encoding="utf-8")
    with pytest.raises(TimestampError, match="receipt_hash"):
        chain_head_digest(p)


def test_build_anchor_tsa_refusal_is_named(tmp_path, mock_tsa):
    chain = _mint_receipt_chain(tmp_path, rows=2, name="c1")
    _op_pem, _ = _operator_key(tmp_path)
    mock_tsa.reject_next = True
    with pytest.raises(TimestampError, match="TSA refused"):
        build_anchor(chain, url=mock_tsa.url, operator_key_pem=_op_pem, out_dir=tmp_path / "out")


def test_build_anchor_unverifiable_token_never_anchors(tmp_path, mock_tsa):
    chain = _mint_receipt_chain(tmp_path, rows=2, name="c2")
    _op_pem, _ = _operator_key(tmp_path)
    mock_tsa.corrupt_signature = True
    with pytest.raises(TimestampError, match="failed its own re-check"):
        build_anchor(chain, url=mock_tsa.url, operator_key_pem=_op_pem, out_dir=tmp_path / "out")
    assert not (tmp_path / "out" / "anchor.json").exists()


# --------------------------------------------------------------------------
# verify_anchor: chain mode and the standalone failure paths
# --------------------------------------------------------------------------


def _mint_chain_with_key(tmp_path, ed, pub, rows, name, retention_days=0):
    """Receipt ledger in the gate's envelope shape, signed with a supplied
    Ed25519 key — so the same key verifies both chain lines and the anchor
    receipt (verify_anchor passes exactly one public key)."""

    from raucle.provenance import _canonical_json, _sha256_hex

    path = tmp_path / f"{name}.jsonl"
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
                "x_gate": {"decision": "ALLOW", "retention_until": 0},
            }
            header = {
                "alg": "EdDSA",
                "typ": "provenance-receipt/v1",
                "kid": kid,
                "crit": ["raucle/v1"],
                "raucle/v1": "provenance",
            }
            si = f"{_b64u(_canonical_json(header))}.{_b64u(_canonical_json(payload))}".encode()
            jws = f"{si.decode('ascii')}.{_b64u(ed.sign(si))}"
            receipt_hash = "sha256:" + _sha256_hex(jws.encode("ascii"))
            fh.write(json.dumps({"receipt_hash": receipt_hash, "jws": jws}) + "\n")
    return path


def _mint_anchor(tmp_path, mock_tsa, name="chain"):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    ed = Ed25519PrivateKey.generate()
    pub = ed.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (tmp_path / f"{name}-minter-pub.pem").write_bytes(pub)
    op_pem = ed.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    chain = _mint_chain_with_key(tmp_path, ed, pub, rows=3, name=name)
    res = build_anchor(
        chain, url=mock_tsa.url, operator_key_pem=op_pem, out_dir=tmp_path / f"{name}-out"
    )
    return chain, res


def test_verify_anchor_chain_mode_full_check(tmp_path, mock_tsa):
    chain, res = _mint_anchor(tmp_path, mock_tsa)
    report = verify_anchor(res["anchor"], chain_path=chain)
    assert report["valid"], report["errors"]
    assert report["cite_check"] == "re-checked against the chain"


def test_verify_anchor_standalone_ok(tmp_path, mock_tsa):
    _, res = _mint_anchor(tmp_path, mock_tsa, name="c3")
    report = verify_anchor(res["anchor"])
    assert report["valid"], report["errors"]
    assert report["token_valid"] is True


def test_verify_anchor_bad_operator_signature(tmp_path, mock_tsa):
    _, res = _mint_anchor(tmp_path, mock_tsa, name="c4")
    with open(res["anchor"], encoding="utf-8") as fh:
        doc = json.load(fh)
    doc["jws"] = doc["jws"][:-2] + ("AA" if doc["jws"][-2:] != "AA" else "BB")
    p = tmp_path / "tampered.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    report = verify_anchor(p)
    assert not report["valid"]
    assert any("signature verification failed" in e for e in report["errors"])


def test_verify_anchor_non_ed25519_operator_key(tmp_path, mock_tsa):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    _, res = _mint_anchor(tmp_path, mock_tsa, name="c5")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    report = verify_anchor(res["anchor"], operator_public_pem=pub)
    assert not report["valid"]
    assert any("not Ed25519" in e for e in report["errors"])


def _sign_with(priv, payload):
    """Canonical {header, payload, sig} Ed25519 JWS in the provenance shape."""
    from cryptography.hazmat.primitives import serialization

    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = hashlib.sha256(pub_pem).hexdigest()[:16]
    header = {
        "alg": "EdDSA",
        "typ": "provenance-receipt/v1",
        "kid": kid,
        "crit": ["raucle/v1"],
        "raucle/v1": "provenance",
    }
    canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":")).encode()  # noqa: E731
    si = f"{_b64u(canon(header))}.{_b64u(canon(payload))}".encode()
    return f"{si.decode('ascii')}.{_b64u(priv.sign(si))}"


def _forge_anchor_doc(tmp_path, x_ts, input_hash):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":")).encode()  # noqa: E731
    header = {"alg": "EdDSA", "typ": "provenance-receipt/v1"}
    payload = {
        "iss": "raucle-timestamp",
        "typ": "provenance-receipt/v1",
        "iat": 1782998400,
        "operation": "guardrail_scan",
        "parents": [],
        "taint": ["gate:observed"],
        "input_hash": input_hash,
        "ruleset_hash": "sha256:0" * 1,
        "guardrail_verdict": "chain_anchored",
        "x_timestamp": x_ts,
    }
    si = f"{b64u(canon(header))}.{b64u(canon(payload))}".encode()
    jws = f"{si.decode('ascii')}.{b64u(priv.sign(si))}"
    doc = {
        "receipt_hash": "sha256:" + hashlib.sha256(jws.encode()).hexdigest(),
        "jws": jws,
        "operator_public_key_pem": pub.decode(),
    }
    p = tmp_path / "forged.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_verify_anchor_digest_binding_mismatch(tmp_path):
    x_ts = {
        "mode": "tsa",
        "digest": "sha256:" + "ab" * 32,
        "token": "",
        "nonce": 1,
        "gen_time": "2026-01-01T00:00:00+00:00",
    }
    p = _forge_anchor_doc(tmp_path, x_ts, "aa" * 32)
    report = verify_anchor(p)
    assert not report["valid"]
    assert any("does not bind the receipt input_hash" in e for e in report["errors"])


def test_verify_anchor_opentimestamps_mode_defers(tmp_path):
    x_ts = {"mode": "opentimestamps", "digest": "sha256:" + "ab" * 32}
    p = _forge_anchor_doc(tmp_path, x_ts, "ab" * 32)
    report = verify_anchor(p)
    assert report["valid"], report["errors"]
    assert report["token_valid"] is None  # .ots proof verifies externally


def test_verify_anchor_unsupported_mode_named(tmp_path):
    x_ts = {"mode": "carrier-pigeon", "digest": "sha256:" + "ab" * 32}
    p = _forge_anchor_doc(tmp_path, x_ts, "ab" * 32)
    report = verify_anchor(p)
    assert not report["valid"]
    assert any("unsupported x_timestamp mode" in e for e in report["errors"])


def test_verify_anchor_standalone_token_invalid(tmp_path, mock_tsa):
    _, res = _mint_anchor(tmp_path, mock_tsa, name="c6")
    with open(res["anchor"], encoding="utf-8") as fh:
        doc = json.load(fh)
    payload = json.loads(base64.urlsafe_b64decode(doc["jws"].split(".")[1] + "=="))
    token_b64 = payload["x_timestamp"]["token"]
    tok = bytearray(base64.b64decode(token_b64))
    tok[-3] ^= 0xFF
    payload["x_timestamp"]["token"] = base64.b64encode(bytes(tok)).decode()
    hdr, pl, sig = doc["jws"].split(".")
    p = tmp_path / "badtoken.json"
    p.write_text(
        json.dumps(
            {
                **doc,
                "jws": (
                    f"{hdr}.{base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()}.{sig}"
                ),
            }
        ),
        encoding="utf-8",
    )
    report = verify_anchor(p)
    assert not report["valid"]


def test_verify_anchor_gen_time_disagreement(tmp_path, mock_tsa):
    from cryptography.hazmat.primitives import serialization

    _, res = _mint_anchor(tmp_path, mock_tsa, name="c7")
    with open(res["anchor"], encoding="utf-8") as fh:
        doc = json.load(fh)
    payload = json.loads(base64.urlsafe_b64decode(doc["jws"].split(".")[1] + "=="))
    x_ts = dict(payload["x_timestamp"])
    x_ts["gen_time"] = "1999-12-31T23:59:59+00:00"
    pl = dict(payload)
    pl["x_timestamp"] = x_ts
    # re-sign the altered payload with a fresh operator key that the doc
    # itself publishes (standalone mode trusts the doc's key)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    ed = Ed25519PrivateKey.generate()

    pub_pem = ed.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jws = _sign_with(ed, pl)
    p = tmp_path / "badgen.json"
    p.write_text(
        json.dumps(
            {
                "receipt_hash": "sha256:" + "0" * 64,
                "jws": jws,
                "operator_public_key_pem": pub_pem.decode(),
            }
        ),
        encoding="utf-8",
    )
    report = verify_anchor(p)
    assert not report["valid"]
    assert report["errors"], report
    assert any("gen_time" in e or "Time Stamp Token" in e for e in report["errors"]), report[
        "errors"
    ]


def test_verify_anchor_token_copy_disagreement(tmp_path, mock_tsa):
    from raucle.compliance_pack import _sign_certificate
    from raucle.timestamp import anchor_payload

    chain, res = _mint_anchor(tmp_path, mock_tsa, name="c8")
    with open(res["anchor"], encoding="utf-8") as fh:
        doc = json.load(fh)
    parent, digest = chain_head_digest(chain)
    payload = anchor_payload(
        digest=digest,
        parent_receipt=parent,
        tsa_url=mock_tsa.url,
        nonce=1,
        token_der=b"other token",
        gen_time=str(res["gen_time"]),
        serial=1,
        policy=MOCK_POLICY_OID,
    )
    jws, receipt_hash, _ = _sign_certificate(payload, _operator_key(tmp_path)[0])
    bad_doc = {
        "receipt_hash": receipt_hash,
        "jws": jws,
        "operator_public_key_pem": doc["operator_public_key_pem"],
        "token_der": doc["token_der"],
        "x_timestamp": payload["x_timestamp"],
    }
    p = tmp_path / "c8-out-copy.json"
    p.write_text(json.dumps(bad_doc), encoding="utf-8")
    report = verify_anchor(p)
    assert not report["valid"]
    assert any("token copy disagrees" in e for e in report["errors"])


# --------------------------------------------------------------------------
# retimestamp_plan: ledger-walk edges
# --------------------------------------------------------------------------


def _append_anchor_line(tmp_path, chain, mock_tsa, out_name):
    op_pem, _ = _operator_key(tmp_path)
    return build_anchor(
        chain, url=mock_tsa.url, operator_key_pem=op_pem, out_dir=tmp_path / out_name
    )


def test_retimestamp_plan_ledger_edges(tmp_path, mock_tsa):
    chain = _mint_receipt_chain(tmp_path, rows=3, retention_days=3650, name="r1")
    # junk lines are skipped; a malformed envelope is skipped; retained
    # receipts before the last anchor are covered
    with open(chain, "a", encoding="utf-8") as fh:
        fh.write("not json at all\n")
        fh.write('{"receipt_hash": "x", "jws": "no-dots"}\n')
    plan = retimestamp_plan(chain)
    assert plan["archive_horizon"] > 0
    assert plan["unanchored_receipts"] == 3  # no anchor anywhere yet
    assert plan["restamp_safety_days"] > 0


def test_retimestamp_plan_unanchored_tail(tmp_path, mock_tsa):
    chain = _mint_receipt_chain(tmp_path, rows=2, retention_days=3650, name="r2")
    res = _append_anchor_line(tmp_path, chain, mock_tsa, "r2-out")
    with open(res["anchor"], encoding="utf-8") as fh:
        anchor_doc = json.load(fh)
    extra = _mint_receipt_chain(tmp_path, rows=2, retention_days=3650, name="r3")
    with open(chain, "a", encoding="utf-8") as fh:
        fh.write(
            json.dumps({"receipt_hash": anchor_doc["receipt_hash"], "jws": anchor_doc["jws"]})
            + "\n"
        )
        with open(extra, encoding="utf-8") as efh:
            fh.writelines(efh.readlines())
    plan = retimestamp_plan(chain)
    assert plan["anchors"], "the appended anchor must register"
    assert plan["anchors"][-1]["token_valid"] is True
    # receipts appended after the anchor with a retention schedule count
    assert plan["unanchored_receipts"] == 2


def test_retimestamp_plan_invalid_token_needs_restamp(tmp_path, mock_tsa):
    chain = _mint_receipt_chain(tmp_path, rows=2, retention_days=3650, name="r4")
    res = _append_anchor_line(tmp_path, chain, mock_tsa, "r4-out")
    with open(res["anchor"], encoding="utf-8") as fh:
        tamper = json.load(fh)
    tok = bytearray(base64.b64decode(tamper["token_der"]))
    tok[-3] ^= 0xFF
    with open(chain, encoding="utf-8") as cfh:
        lines = cfh.readlines()
    # rebuild the anchor line with a corrupted token signed by a throwaway key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    payload = json.loads(base64.urlsafe_b64decode(tamper["jws"].split(".")[1] + "=="))
    payload["x_timestamp"]["token"] = base64.b64encode(bytes(tok)).decode()
    header = {"alg": "EdDSA", "typ": "provenance-receipt/v1"}
    si = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    inner = f"{b64u(json.dumps(header, sort_keys=True).encode())}.{b64u(si)}".encode()
    jws = f"{inner.decode('ascii')}.{b64u(priv.sign(inner))}"
    anchor_line = json.dumps({"receipt_hash": "sha256:tampered", "jws": jws})
    with open(chain, "w", encoding="utf-8") as fh:
        fh.writelines(lines[:-1])
        fh.write(anchor_line + "\n")
    plan = retimestamp_plan(chain)
    assert plan["anchors"], "tampered anchor must still register as an anchor entry"
    entry = plan["anchors"][-1]
    assert entry["needs_restamp"] is True
    assert entry["restamp_by"] == "now (token fails re-check)"
    assert entry["token_valid"] is False
