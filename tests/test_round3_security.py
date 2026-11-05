"""Regression tests for the round-3 adversarial security audit (2026-06-01).

Each test pins a confirmed finding from docs/oss-security-audit-round3.md so a
future change that reintroduces the bug fails loudly. Dependency-light: tests
that would need optional extras (fastapi/langchain/autogen/pillow) are guarded.

Report: ../raucle/docs/oss-security-audit-round3.md
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from raucle.audit import _canonical_json as audit_canon
from raucle.audit import _merkle_root
from raucle.feed import _assert_safe_url
from raucle.feed import _canonical_json as feed_canon
from raucle.prove import SQLClauseProver, URLPolicyProver
from raucle.provenance import (
    AgentIdentity,
    CapabilityStatement,
    ProvenanceLogger,
    ProvenanceReceipt,
    ProvenanceVerifier,
)


# --- #1 SQL prover: set-operation table extraction bypass --------------------
@pytest.mark.parametrize("op", ["EXCEPT", "INTERSECT", "MINUS"])
def test_sql_setop_does_not_prove_forbidden_table(op):
    # Reading a forbidden table via a set operation must NOT be PROVEN.
    r = SQLClauseProver().prove(
        {"templates": [f"SELECT a FROM customers {op} SELECT a FROM admin_secrets"]},
        {"allowed_tables": ["customers"]},
    )
    assert r.status != "PROVEN"


def test_sql_legit_query_still_proven():
    r = SQLClauseProver().prove(
        {"templates": ["SELECT a FROM customers"]}, {"allowed_tables": ["customers"]}
    )
    assert r.status == "PROVEN"


# --- #7 SELECT ... INTO under read-only default ------------------------------
@pytest.mark.parametrize("tok", ["INTO", "MERGE", "CREATE"])
def test_sql_default_forbids_write_tokens(tok):
    sql = {
        "INTO": "SELECT * INTO admin_copy FROM customers",
        "MERGE": "MERGE INTO t USING s ON t.id=s.id",
        "CREATE": "CREATE TABLE x AS SELECT 1",
    }[tok]
    assert SQLClauseProver().prove({"templates": [sql]}, {}).status != "PROVEN"


# --- #8 forbid_query_keys over an open grammar -------------------------------
def test_forbid_query_keys_open_grammar_is_undecided():
    r = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["api.example.com"]},
        {"forbid_query_keys": ["token"]},
    )
    assert r.status == "UNDECIDED"


def test_forbid_query_keys_closed_grammar_proves_or_refutes():
    safe = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["h"], "query_keys": ["q"], "query_keys_closed": True},
        {"forbid_query_keys": ["token"]},
    )
    assert safe.status == "PROVEN"
    bad = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["h"], "query_keys": ["token"], "query_keys_closed": True},
        {"forbid_query_keys": ["token"]},
    )
    assert bad.status == "REFUTED"


# --- provenance verifier hardening (#4 expiry, #5 agent_id, #6 kid) ----------
def _stmt(idn, **ov):
    import base64

    from raucle.provenance import _canonical_json

    s = idn.statement
    stmt = CapabilityStatement(
        agent_id=ov.get("agent_id", s.agent_id),
        key_id=s.key_id,
        public_key_pem=s.public_key_pem,
        allowed_models=list(s.allowed_models),
        allowed_tools=list(s.allowed_tools),
        expires_at=ov.get("expires_at"),
    )
    # Self-sign so the verifier (which now authenticates statements) trusts it.
    stmt.signature = base64.b64encode(idn.sign(_canonical_json(stmt.body()))).decode("ascii")
    return stmt


def _chain(tmp_path):
    idn = AgentIdentity.generate(agent_id="agent:good")
    c = tmp_path / "c.jsonl"
    with ProvenanceLogger(agent=idn, sink_path=c) as log:
        log.record_user_input(text="hi")
    return idn, c


def test_provenance_baseline_valid(tmp_path):
    idn, c = _chain(tmp_path)
    v = ProvenanceVerifier(
        public_keys={idn.key_id: idn.public_key_pem()}, capabilities={idn.key_id: _stmt(idn)}
    )
    assert v.verify_chain(c).valid is True


def test_provenance_rejects_expired_statement(tmp_path):
    idn, c = _chain(tmp_path)
    v = ProvenanceVerifier(
        public_keys={idn.key_id: idn.public_key_pem()},
        capabilities={idn.key_id: _stmt(idn, expires_at=1)},
    )
    rep = v.verify_chain(c)
    assert rep.valid is False
    assert any("expired" in e for e in rep.errors)


def test_provenance_rejects_agent_id_spoof(tmp_path):
    idn, c = _chain(tmp_path)
    v = ProvenanceVerifier(
        public_keys={idn.key_id: idn.public_key_pem()},
        capabilities={idn.key_id: _stmt(idn, agent_id="agent:someone-else")},
    )
    rep = v.verify_chain(c)
    assert rep.valid is False
    assert any("agent_id" in e for e in rep.errors)


def test_strict_from_jws_rejects_kid_mismatch(tmp_path):
    import base64

    idn, c = _chain(tmp_path)
    rec = json.loads(c.read_text().strip().splitlines()[0])
    h, p, s = rec["jws"].split(".")
    hdr = json.loads(base64.urlsafe_b64decode(h + "==" * (-len(h) % 4)))
    hdr["kid"] = "not-the-agent-key-id"
    newh = (
        base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(ValueError, match="kid"):
        ProvenanceReceipt.from_jws(f"{newh}.{p}.{s}", strict=True)


# --- audit (#9 keyless signed, #13 NaN, #22 non-hex leaf) --------------------
def test_audit_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        audit_canon({"x": float("nan")})


def test_feed_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        feed_canon({"x": float("inf")})


def test_merkle_root_raises_on_non_hex_leaf():
    with pytest.raises(ValueError, match="non-hex"):
        _merkle_root(["nothex!!"])


def test_merkle_root_valid_hex_ok():
    assert len(_merkle_root(["00" * 32])) == 64


# --- feed SSRF pin (#21 dead-code crash) -------------------------------------
def test_feed_assert_safe_url_returns_pinned_ip():
    infos = [(2, 1, 6, "", ("93.184.216.34", 443))] * 2
    with mock.patch("socket.getaddrinfo", return_value=infos):
        host, ip = _assert_safe_url("https://example.com/feed.json")
    assert host == "example.com"
    assert ip == "93.184.216.34"


def test_feed_assert_safe_url_blocks_metadata_ip():
    with (
        mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("169.254.169.254", 443))]),
        pytest.raises(ValueError),
    ):
        _assert_safe_url("https://evil.example/x")


# --- #21 live DNS-rebind pin: connection dials the validated IP, resolves once ---
class _StopDial(Exception):
    """Sentinel raised from the mocked dial so we don't need a full TLS/HTTP fake."""


def test_feed_fetch_pins_validated_ip_and_resolves_once():
    """fetch_feed must dial the IP that _assert_safe_url validated, and must NOT
    perform a second DNS lookup at connect time (the DNS-rebind defense). Before
    the #21 fix this path was dead code (TypeError) and never exercised at all.
    """
    import socket as _socket

    from raucle.feed import fetch_feed

    safe_ip = "93.184.216.34"
    getaddr = mock.Mock(return_value=[(2, 1, 6, "", (safe_ip, 443))])
    dialed: list = []

    def _fake_create_connection(addr, *a, **k):
        dialed.append(addr)
        raise _StopDial  # stop before TLS/HTTP — we only assert the dial target

    with (
        mock.patch.object(_socket, "getaddrinfo", getaddr),
        mock.patch.object(_socket, "create_connection", _fake_create_connection),
        pytest.raises(_StopDial),
    ):
        fetch_feed("https://example.com/feed.json")

    # Dialed exactly the pinned, pre-validated IP — not a re-resolved address.
    assert dialed == [(safe_ip, 443)]
    # Resolved exactly once: the pin means no second lookup a rebind could poison.
    assert getaddr.call_count == 1


def test_feed_fetch_rejects_url_whose_host_resolves_to_blocked_ip():
    import socket as _socket

    from raucle.feed import fetch_feed

    with (
        mock.patch.object(_socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 443))]),
        pytest.raises(ValueError),
    ):
        fetch_feed("https://internal.example/feed.json")


# --- Codex F1: JSONSchemaProver + additionalProperties soundness -------------
def test_jsonschema_forbidden_value_on_undeclared_field_not_proven():
    pytest.importorskip("z3")  # JSONSchemaProver needs the [proof] extra
    from raucle.prove import JSONSchemaProver

    # additionalProperties default-true: an attacker can supply 'role', so a
    # blacklist on it cannot be PROVEN — {"x":"ok","role":"admin"} is valid.
    schema = {
        "type": "object",
        "properties": {"x": {"type": "string"}},
        "additionalProperties": True,
    }
    r = JSONSchemaProver().prove(schema, {"forbidden_values": {"role": ["admin"]}})
    assert r.status == "REFUTED"


def test_jsonschema_closed_schema_makes_undeclared_blacklist_vacuous():
    pytest.importorskip("z3")  # JSONSchemaProver needs the [proof] extra
    from raucle.prove import JSONSchemaProver

    schema = {
        "type": "object",
        "properties": {"x": {"type": "string"}},
        "additionalProperties": False,
    }
    r = JSONSchemaProver().prove(schema, {"forbidden_values": {"role": ["admin"]}})
    assert r.status == "PROVEN"


# --- Codex F4: strict verify enforces JOSE typ + raucle/v1 marker ------------
def _tamper_header(jws, **overrides):
    import base64

    h, p, s = jws.split(".")
    hdr = json.loads(base64.urlsafe_b64decode(h + "==" * (-len(h) % 4)))
    hdr.update(overrides)
    nh = (
        base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    return f"{nh}.{p}.{s}"


def test_strict_from_jws_rejects_bad_typ(tmp_path):
    idn, c = _chain(tmp_path)
    jws = json.loads(c.read_text().strip().splitlines()[0])["jws"]
    tampered = _tamper_header(jws, typ="not-provenance")
    with pytest.raises(ValueError, match="typ"):
        ProvenanceReceipt.from_jws(tampered, strict=True)


def test_strict_from_jws_rejects_bad_marker(tmp_path):
    idn, c = _chain(tmp_path)
    jws = json.loads(c.read_text().strip().splitlines()[0])["jws"]
    tampered = _tamper_header(jws, **{"raucle/v1": "nope"})
    with pytest.raises(ValueError, match="raucle/v1"):
        ProvenanceReceipt.from_jws(tampered, strict=True)


# --- LangChain blacklist-on-opaque-string guard (#3b/#5) ---------------------
def test_langchain_blacklist_helper():
    lc = pytest.importorskip("raucle.integrations.langchain")

    class T:
        def __init__(self, c):
            self.constraints = c

    assert lc._blacklist_on_named_field(T({"forbidden_values": {"to": ["x"]}})) is True
    assert lc._blacklist_on_named_field(T({"forbidden_values": {"input": ["x"]}})) is False
    assert lc._blacklist_on_named_field(T({"forbidden_field_combinations": [["a", "b"]]})) is True
    assert lc._blacklist_on_named_field(T({"allowed_values": {"to": ["ok"]}})) is False
    assert lc._blacklist_on_named_field(T({})) is False


# === Codex run-2 (current-main cross-model) regressions ======================


# --- F1: malformed caller agent_id must not pass the descendant prefix check --
def test_gate_rejects_malformed_caller_agent_id():
    pytest.importorskip("cryptography")
    from raucle.capability import CapabilityGate, CapabilityIssuer

    iss = CapabilityIssuer.generate("issuer")
    tok = iss.mint(agent_id="agent:a", tool="t")
    g = CapabilityGate(trusted_issuers={iss.key_id: iss.public_key_pem})
    assert g.check(tok, tool="t", agent_id="agent:a..evil").allowed is False
    assert g.check(tok, tool="t", agent_id="agent:a.").allowed is False
    assert g.check(tok, tool="t", agent_id="agent:a.good").allowed is True  # real descendant
    assert g.check(tok, tool="t", agent_id="agent:a").allowed is True  # self


# --- F2: SQL prover must check the FULL qualified table name -----------------
def test_sql_schema_qualified_table_not_proven_when_only_schema_allowed():
    from raucle.prove import SQLClauseProver

    p = SQLClauseProver()
    assert (
        p.prove(
            {"templates": ["SELECT * FROM public.secret"]}, {"allowed_tables": ["public"]}
        ).status
        == "REFUTED"
    )
    assert (
        p.prove(
            {"templates": ["SELECT * FROM public.secret"]}, {"allowed_tables": ["public.secret"]}
        ).status
        == "PROVEN"
    )


# --- F3: verifier rejects structurally invalid receipts ----------------------
def test_verifier_rejects_tool_call_without_parents_or_output_hash(tmp_path):
    from raucle.provenance import (
        AgentIdentity,
        Operation,
        ProvenanceReceipt,
        ProvenanceVerifier,
    )

    idn = AgentIdentity.generate(agent_id="agent:x")
    r = ProvenanceReceipt(
        agent_id="agent:x",
        agent_key_id=idn.key_id,
        operation=Operation.TOOL_CALL,
        parents=[],
        tool="send_email",
    )
    r.sign(idn)
    c = tmp_path / "c.jsonl"
    c.write_text(json.dumps({"receipt_hash": r.receipt_hash, "jws": r.jws}) + "\n")
    rep = ProvenanceVerifier(public_keys={idn.key_id: idn.public_key_pem()}).verify_chain(c)
    assert rep.valid is False


# --- F4: canonical JSON rejects floats (cross-impl parity with TS/Go/Rust/C#) -
def test_provenance_canonical_json_rejects_floats():
    from raucle.provenance import _canonical_json

    with pytest.raises(ValueError, match="float"):
        _canonical_json({"x": 1.0})
    # integers / bools / strings still serialise
    assert _canonical_json({"a": 1, "b": True}) == b'{"a":1,"b":true}'


# --- F6: wildcard host pattern does not match the apex -----------------------
def test_url_wildcard_does_not_match_apex():
    from raucle.prove import URLPolicyProver

    u = URLPolicyProver()
    g = {"schemes": ["https"], "path_prefixes": ["/"], "query_keys_closed": True}
    assert (
        u.prove({**g, "hosts": ["example.com"]}, {"host_allowlist": ["*.example.com"]}).status
        == "REFUTED"
    )
    assert (
        u.prove({**g, "hosts": ["api.example.com"]}, {"host_allowlist": ["*.example.com"]}).status
        == "PROVEN"
    )


# === Codex run-3 (current-main) regressions =================================


def test_jsonschema_patternproperties_not_proven():
    """patternProperties can admit a field additionalProperties:false appears to
    forbid, so the prover must NOT certify PROVEN (round-3 run-3 F1)."""
    pytest.importorskip("z3")
    from raucle.prove import JSONSchemaProver

    s = {
        "type": "object",
        "properties": {},
        "patternProperties": {"^role$": {"type": "string"}},
        "additionalProperties": False,
    }
    assert (
        JSONSchemaProver().prove(s, {"forbidden_values": {"role": ["admin"]}}).status == "UNDECIDED"
    )


def test_capability_token_rejects_float_bounds():
    """cap:v1 numeric constraints are integer-only (run-3 F5)."""
    pytest.importorskip("cryptography")
    from raucle.capability import CapabilityIssuer

    iss = CapabilityIssuer.generate("issuer")
    with pytest.raises(ValueError, match="float"):
        iss.mint(agent_id="agent:a", tool="pay", constraints={"max_value": {"amount": 1.5}})
    # integer bound still mints
    iss.mint(agent_id="agent:a", tool="pay", constraints={"max_value": {"amount": 100}})


def test_verifier_rejects_unsorted_taint_and_bad_payload_typ(tmp_path):
    """Manually-crafted JWS with unsorted taint (bypassing sign()'s sort) and a
    tampered payload typ must be rejected (run-3 F3)."""
    pytest.importorskip("cryptography")
    import hashlib

    from raucle.provenance import (
        _EXPECTED_TYP,
        AgentIdentity,
        ProvenanceVerifier,
        _b64url_encode,
        _canonical_json,
    )

    idn = AgentIdentity.generate(agent_id="agent:x")
    header = {
        "alg": "EdDSA",
        "typ": _EXPECTED_TYP,
        "kid": idn.key_id,
        "crit": ["raucle/v1"],
        "raucle/v1": "provenance",
    }

    def _make(payload):
        hb = _b64url_encode(_canonical_json(header))
        pb = _b64url_encode(_canonical_json(payload))
        sig = idn.sign((hb + "." + pb).encode("ascii"))
        jws = hb + "." + pb + "." + _b64url_encode(sig)
        rh = "sha256:" + hashlib.sha256(jws.encode()).hexdigest()
        p = tmp_path / "c.jsonl"
        p.write_text(json.dumps({"receipt_hash": rh, "jws": jws}) + "\n")
        return p

    base = {
        "iss": "raucle-detect/provenance",
        "typ": _EXPECTED_TYP,
        "iat": 1,
        "agent_id": "agent:x",
        "agent_key_id": idn.key_id,
        "operation": "user_input",
        "parents": [],
        "input_hash": "sha256:" + "0" * 64,
    }
    v = ProvenanceVerifier(public_keys={idn.key_id: idn.public_key_pem()})
    # unsorted taint
    assert v.verify_chain(_make({**base, "taint": ["z", "a"]})).valid is False
    # bad payload typ (strict from_jws rejects → malformed record)
    assert v.verify_chain(_make({**base, "taint": [], "typ": "evil"})).valid is False


def test_forbidden_values_catches_value_in_collection_arg():
    """A forbidden value hidden in a list/dict argument must still be denied
    (capability-constraint bypass: forbidden_values only checked scalar ==)."""
    pytest.importorskip("cryptography")
    from raucle.capability import CapabilityGate, CapabilityIssuer

    iss = CapabilityIssuer.generate("issuer")
    g = CapabilityGate(trusted_issuers={iss.key_id: iss.public_key_pem})
    tok = iss.mint(
        agent_id="agent:a",
        tool="send_email",
        constraints={"forbidden_values": {"to": ["attacker@evil"]}},
    )
    assert g.check(tok, tool="send_email", args={"to": "attacker@evil"}).allowed is False
    assert g.check(tok, tool="send_email", args={"to": ["attacker@evil"]}).allowed is False
    assert (
        g.check(tok, tool="send_email", args={"to": ["ok@good", "attacker@evil"]}).allowed is False
    )
    assert (
        g.check(tok, tool="send_email", args={"to": {"primary": "attacker@evil"}}).allowed is False
    )
    # legit calls (scalar or collection without the forbidden value) still allowed
    assert g.check(tok, tool="send_email", args={"to": "ok@good"}).allowed is True
    assert g.check(tok, tool="send_email", args={"to": ["a@good", "b@good"]}).allowed is True


def test_verifier_rejects_forged_capability_statement(tmp_path):
    """A capability statement with a bogus/invalid signature (or one not signed
    by the trusted key) must be rejected, not trusted to widen allowed_tools
    (round-4 F2)."""
    pytest.importorskip("cryptography")
    from raucle.provenance import (
        AgentIdentity,
        CapabilityStatement,
        Operation,
        ProvenanceReceipt,
        ProvenanceVerifier,
    )

    idn = AgentIdentity.generate(agent_id="agent:a", allowed_tools=["safe"])
    ui = ProvenanceReceipt(
        agent_id="agent:a",
        agent_key_id=idn.key_id,
        operation=Operation.USER_INPUT,
        parents=[],
        input_hash="sha256:" + "2" * 64,
    )
    ui.sign(idn)
    tc = ProvenanceReceipt(
        agent_id="agent:a",
        agent_key_id=idn.key_id,
        operation=Operation.TOOL_CALL,
        parents=[ui.receipt_hash],
        input_hash="sha256:" + "0" * 64,
        output_hash="sha256:" + "1" * 64,
        tool="evil",
    )
    tc.sign(idn)
    c = tmp_path / "c.jsonl"
    c.write_text(
        json.dumps({"receipt_hash": ui.receipt_hash, "jws": ui.jws})
        + "\n"
        + json.dumps({"receipt_hash": tc.receipt_hash, "jws": tc.jws})
        + "\n"
    )
    forged = CapabilityStatement(
        agent_id="agent:a",
        key_id=idn.key_id,
        public_key_pem=idn.public_key_pem(),
        allowed_tools=["evil", "safe"],
        signature="bogus",
    )
    rep = ProvenanceVerifier(
        public_keys={idn.key_id: idn.public_key_pem()}, capabilities={idn.key_id: forged}
    ).verify_chain(c)
    assert rep.valid is False
    assert any("signature/key-binding" in e for e in rep.errors)


# === Codex run-5 (current-main) regressions =================================


def test_scalar_forbidden_values_rejected_at_mint():
    """A scalar (string) forbidden_values value must be rejected, not sorted
    into characters (which silently disables the blacklist) — round-5 F1."""
    pytest.importorskip("cryptography")
    from raucle.capability import CapabilityIssuer

    iss = CapabilityIssuer.generate("issuer")
    with pytest.raises(ValueError, match="must be a list"):
        iss.mint(
            agent_id="agent:a", tool="send", constraints={"forbidden_values": {"role": "admin"}}
        )
    with pytest.raises(ValueError, match="must be a list"):
        iss.mint(agent_id="agent:a", tool="send", constraints={"allowed_values": {"role": "admin"}})


def test_audit_loads_strict_rejects_duplicate_keys():
    """Audit chain records with duplicate keys are a JSON ambiguity (last-key
    wins here, first-key elsewhere) and must be rejected — round-5 F2."""
    from raucle.audit import _loads_strict

    with pytest.raises(ValueError, match="duplicate key"):
        _loads_strict('{"event":{"a":1},"index":0,"event":{"b":2}}')
    # well-formed record still parses
    assert _loads_strict('{"index":0,"event":{"a":1}}')["index"] == 0


def test_strict_verify_rejects_non_canonical_jws(tmp_path):
    """A JWS whose payload bytes are valid-but-non-canonical (whitespace /
    unsorted keys) must not verify — the receipt contract is JCS-canonical
    (round-5 F3)."""
    pytest.importorskip("cryptography")
    import hashlib

    from raucle.provenance import (
        _EXPECTED_TYP,
        AgentIdentity,
        ProvenanceVerifier,
        _b64url_encode,
        _canonical_json,
    )

    idn = AgentIdentity.generate(agent_id="agent:x")
    hdr = {
        "alg": "EdDSA",
        "typ": _EXPECTED_TYP,
        "kid": idn.key_id,
        "crit": ["raucle/v1"],
        "raucle/v1": "provenance",
    }
    payload = {
        "iss": "raucle-detect/provenance",
        "typ": _EXPECTED_TYP,
        "iat": 1,
        "agent_id": "agent:x",
        "agent_key_id": idn.key_id,
        "operation": "user_input",
        "parents": [],
        "taint": [],
        "input_hash": "sha256:" + "0" * 64,
    }
    hb = _b64url_encode(_canonical_json(hdr))
    pb = _b64url_encode(
        json.dumps(payload, separators=(", ", ": ")).encode()
    )  # non-canonical spaces
    sig = idn.sign((hb + "." + pb).encode("ascii"))
    jws = hb + "." + pb + "." + _b64url_encode(sig)
    rh = "sha256:" + hashlib.sha256(jws.encode()).hexdigest()
    c = tmp_path / "c.jsonl"
    c.write_text(json.dumps({"receipt_hash": rh, "jws": jws}) + "\n")
    rep = ProvenanceVerifier(public_keys={idn.key_id: idn.public_key_pem()}).verify_chain(c)
    assert rep.valid is False


# === Codex run-6 (current-main) regressions =================================


def test_sql_grammar_allowed_tables_cannot_broaden_policy():
    """grammar.allowed_tables must not broaden the policy allowlist (round-6 F1)."""
    from raucle.prove import SQLClauseProver, UnsupportedGrammar

    p = SQLClauseProver()
    # both present: policy dominates, grammar's broader entry ignored
    assert (
        p.prove(
            {"templates": ["SELECT * FROM secret"], "allowed_tables": ["secret"]},
            {"allowed_tables": ["public"], "forbidden_tokens": []},
        ).status
        == "REFUTED"
    )
    # grammar-only is a misplaced-key footgun → raises (no silent unrestricted PROVEN)
    with pytest.raises(UnsupportedGrammar):
        p.prove(
            {"templates": ["SELECT * FROM secret"], "allowed_tables": ["secret"]},
            {"forbidden_tokens": []},
        )


def test_sql_non_select_table_access_undecided():
    """Table-bearing forms the FROM/JOIN extractor can't cover → UNDECIDED, not
    a false PROVEN (round-6 F2)."""
    from raucle.prove import SQLClauseProver

    p = SQLClauseProver()
    assert (
        p.prove({"templates": ["COPY secret TO STDOUT"]}, {"allowed_tables": ["public"]}).status
        == "UNDECIDED"
    )
    assert (
        p.prove(
            {"templates": ["SELECT * INTO evil FROM public"]},
            {"allowed_tables": ["public"], "forbidden_tokens": []},
        ).status
        == "UNDECIDED"
    )


def test_gate_rejects_broadened_attenuation_chain():
    """A child citing a parent but carrying BROADER constraints is rejected by
    the chain walk (round-6 F3)."""
    pytest.importorskip("cryptography")
    import raucle.capability as cap
    from raucle.capability import CapabilityGate, CapabilityIssuer

    iss = CapabilityIssuer.generate("issuer")
    parent = iss.mint(
        agent_id="agent:a", tool="t", constraints={"allowed_values": {"role": ["user"]}}
    )
    forged = iss.mint(
        agent_id="agent:a", tool="t", constraints={"allowed_values": {"role": ["user", "admin"]}}
    )
    forged.parent_id = parent.token_id
    forged.token_id = "cap:" + cap._sha256_hex(cap._canonical_json(forged.body()))[:24]
    forged.signature = cap._b64(iss._priv.sign(cap._canonical_json(forged.body())))
    by_id = {parent.token_id: parent, forged.token_id: forged}
    g = CapabilityGate(trusted_issuers={iss.key_id: iss.public_key_pem}, parent_resolver=by_id.get)
    dec = g.check(forged, tool="t", args={"role": "admin"})
    assert dec.allowed is False
    assert "attenuation" in dec.reason


def test_strict_verify_rejects_extra_jose_header(tmp_path):
    """Header with a key outside the fixed set is rejected (round-6 F6)."""
    pytest.importorskip("cryptography")
    from raucle.provenance import (
        _EXPECTED_TYP,
        AgentIdentity,
        ProvenanceReceipt,
        _b64url_encode,
        _canonical_json,
    )

    idn = AgentIdentity.generate(agent_id="agent:x")
    hdr = {
        "alg": "EdDSA",
        "typ": _EXPECTED_TYP,
        "kid": idn.key_id,
        "crit": ["raucle/v1"],
        "raucle/v1": "provenance",
        "extra": "x",
    }
    pl = {
        "iss": "raucle-detect/provenance",
        "typ": _EXPECTED_TYP,
        "iat": 1,
        "agent_id": "agent:x",
        "agent_key_id": idn.key_id,
        "operation": "user_input",
        "parents": [],
        "taint": [],
        "input_hash": "sha256:" + "0" * 64,
    }
    hb = _b64url_encode(_canonical_json(hdr))
    pb = _b64url_encode(_canonical_json(pl))
    jws = hb + "." + pb + "." + _b64url_encode(idn.sign((hb + "." + pb).encode("ascii")))
    with pytest.raises(ValueError, match="header key"):
        ProvenanceReceipt.from_jws(jws, strict=True)
