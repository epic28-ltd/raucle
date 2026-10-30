"""Tests for the formal-verification provers (v0.9.0)."""

from __future__ import annotations

import pytest

z3 = pytest.importorskip("z3")

from raucle.prove import (
    JSONSchemaProver,
    ProofResult,
    SQLClauseProver,
    UnsupportedGrammar,
    URLPolicyProver,
)

# ---------------------------------------------------------------------------
# JSON Schema prover
# ---------------------------------------------------------------------------


def _txfer_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "amount": {"type": "number", "minimum": 0, "maximum": 1_000_000},
            "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]},
        },
        "required": ["to", "amount", "currency"],
    }


def test_jsonschema_proven_when_policy_holds():
    p = JSONSchemaProver().prove(
        _txfer_schema(),
        {"max_value": {"amount": 1_000_000}},
    )
    assert p.status == "PROVEN"
    assert p.counterexample is None
    assert p.prover == "JSONSchemaProver"


def test_jsonschema_refuted_with_concrete_counterexample():
    p = JSONSchemaProver().prove(
        _txfer_schema(),
        {"max_value": {"amount": 100}},
    )
    assert p.status == "REFUTED"
    assert p.counterexample is not None
    assert p.counterexample["amount"] > 100
    assert p.counterexample["currency"] in {"USD", "EUR", "GBP"}


def test_jsonschema_forbidden_recipient_refuted():
    p = JSONSchemaProver().prove(
        _txfer_schema(),
        {"forbidden_values": {"to": ["attacker@evil.example"]}},
    )
    assert p.status == "REFUTED"
    assert p.counterexample["to"] == "attacker@evil.example"


def test_jsonschema_forbidden_recipient_proven_when_enum_excludes_it():
    schema = {
        "type": "object",
        "properties": {
            "to": {"type": "string", "enum": ["alice@example.com", "bob@example.com"]},
        },
        "required": ["to"],
    }
    p = JSONSchemaProver().prove(schema, {"forbidden_values": {"to": ["attacker@evil.example"]}})
    assert p.status == "PROVEN"


def test_jsonschema_field_combination_refuted():
    schema = {
        "type": "object",
        "properties": {
            "delete_all": {"type": "boolean"},
            "tenant_id": {"type": "string"},
        },
    }
    p = JSONSchemaProver().prove(
        schema,
        {"forbidden_field_combinations": [["delete_all", "tenant_id"]]},
    )
    assert p.status == "REFUTED"


def test_jsonschema_trivial_policy_proven_with_note():
    p = JSONSchemaProver().prove(_txfer_schema(), {})
    assert p.status == "PROVEN"
    assert any("trivially proven" in n for n in p.notes)


def test_jsonschema_unsupported_grammar_raises():
    with pytest.raises(UnsupportedGrammar):
        JSONSchemaProver().prove({"type": "array"}, {})


def test_jsonschema_hash_is_deterministic():
    p1 = JSONSchemaProver().prove(_txfer_schema(), {"max_value": {"amount": 100}})
    p2 = JSONSchemaProver().prove(_txfer_schema(), {"max_value": {"amount": 100}})
    # Counterexample content may vary (Z3 model choice) but grammar/policy hashes are stable.
    assert p1.grammar_hash == p2.grammar_hash
    assert p1.policy_hash == p2.policy_hash


# ---------------------------------------------------------------------------
# JSON Schema prover - exclusion query (the I1 counterfactual z3 leg)
# ---------------------------------------------------------------------------


def _class_schema(fields: dict[str, str]) -> dict:
    """A shape-derived class schema: same field names, same primitive types,
    every recorded field required, nothing else admitted."""
    return {
        "type": "object",
        "properties": {k: {"type": v} for k, v in fields.items()},
        "required": sorted(fields),
        "additionalProperties": False,
    }


def test_prove_exclusion_proven_when_constraints_exclude_the_whole_class():
    """A required-pair combination ban excludes every member of a class that
    carries both fields: the deny is structural, not value-specific."""
    schema = _class_schema({"account": "string", "reason": "string"})
    policy = {"forbidden_field_combinations": [["account", "reason"]]}
    r = JSONSchemaProver().prove_exclusion(schema, policy)
    assert r.status == "PROVEN"
    assert r.counterexample is None
    assert r.grammar_hash.startswith("sha256:")
    assert any("exclusion" in n for n in r.notes)


def test_prove_exclusion_refuted_with_counterexample_when_value_specific():
    """A single-value blacklist never excludes a whole string class: some
    class member escapes the denylist and would still be allowed."""
    schema = _class_schema({"account": "string"})
    policy = {"forbidden_values": {"account": ["ACC-999"]}}
    r = JSONSchemaProver().prove_exclusion(schema, policy)
    assert r.status == "REFUTED"
    # the counterexample is a whole class member that satisfies the policy
    assert set(r.counterexample) == {"account"}
    assert r.counterexample["account"] != "ACC-999"


def test_prove_exclusion_undecided_on_unmodelled_policy_key():
    """allowed_values is gate-enforced but not prover-modelled: the exclusion
    can be certified in NEITHER direction (a would-be witness might still be
    denied by the unassessed constraint). Fail closed, never upgrade."""
    schema = _class_schema({"account": "string"})
    r = JSONSchemaProver().prove_exclusion(schema, {"allowed_values": {"account": ["ACC-001"]}})
    assert r.status == "UNDECIDED"
    assert any("allowed_values" in n for n in r.notes)


def test_prove_exclusion_uninhabited_grammar_is_undecided_not_vacuously_proven():
    """An empty grammar makes 'every member violates' vacuously true; a
    vacuous truth is not a certified exclusion."""
    schema = {
        "type": "object",
        "properties": {"n": {"type": "number", "minimum": 10, "maximum": 5}},
        "required": ["n"],
    }
    r = JSONSchemaProver().prove_exclusion(schema, {"max_value": {"n": 100}})
    assert r.status == "UNDECIDED"
    assert any("vacuous" in n for n in r.notes)


def test_prove_exclusion_empty_policy_refuted_when_grammar_inhabited():
    """Zero constraints exclude nothing: an inhabited class keeps a member
    that satisfies them all."""
    r = JSONSchemaProver().prove_exclusion(_class_schema({"account": "string"}), {})
    assert r.status == "REFUTED"
    assert set(r.counterexample) == {"account"}


def test_prove_and_prove_exclusion_are_dual_queries():
    """Same inputs, opposite questions: a policy some members violate and
    others satisfy is REFUTED in both directions; a policy every member
    violates is REFUTED for prove() and PROVEN for prove_exclusion()."""
    schema = _class_schema({"a": "string"})
    some_violate = {"forbidden_values": {"a": ["x"]}}
    p = JSONSchemaProver().prove(schema, some_violate)
    e = JSONSchemaProver().prove_exclusion(schema, some_violate)
    assert p.status == "REFUTED" and e.status == "REFUTED"

    # A ban no class member escapes: REFUTED for prove() (a violator exists)
    # and PROVEN for prove_exclusion() (no satisfier exists).
    two = _class_schema({"a": "string", "b": "string"})
    everything = {"forbidden_field_combinations": [["a", "b"]]}
    assert JSONSchemaProver().prove(two, everything).status == "REFUTED"
    assert JSONSchemaProver().prove_exclusion(two, everything).status == "PROVEN"


# ---------------------------------------------------------------------------
# URL prover
# ---------------------------------------------------------------------------


def test_url_https_only_proven_when_grammar_is_https():
    p = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["api.example.com"]},
        {"require_https": True},
    )
    assert p.status == "PROVEN"


def test_url_https_only_refuted_when_grammar_allows_http():
    p = URLPolicyProver().prove(
        {"schemes": ["https", "http"], "hosts": ["api.example.com"]},
        {"require_https": True},
    )
    assert p.status == "REFUTED"
    assert p.counterexample["scheme"] == "http"


def test_url_forbidden_query_key_refuted():
    p = URLPolicyProver().prove(
        {
            "schemes": ["https"],
            "hosts": ["api.example.com"],
            "query_keys": ["q", "api_key"],
        },
        {"forbid_query_keys": ["api_key", "token"]},
    )
    assert p.status == "REFUTED"
    assert p.counterexample["query_key"] == "api_key"


def test_url_host_allowlist_wildcard_matches():
    p = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["api.example.com", "v2.example.com"]},
        {"host_allowlist": ["*.example.com"]},
    )
    assert p.status == "PROVEN"


def test_url_host_allowlist_refuted_when_unauth_host_in_grammar():
    p = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["api.example.com", "evil.attacker.com"]},
        {"host_allowlist": ["*.example.com"]},
    )
    assert p.status == "REFUTED"
    assert p.counterexample["host"] == "evil.attacker.com"


# ---------------------------------------------------------------------------
# SQL prover
# ---------------------------------------------------------------------------


def test_sql_readonly_query_proven():
    p = SQLClauseProver().prove(
        {
            "templates": [
                "SELECT id, name FROM customers WHERE tenant_id = ?",
                "SELECT total FROM invoices WHERE id = ?",
            ],
            "allowed_tables": ["customers", "invoices"],
        },
        {"allowed_tables": ["customers", "invoices"]},
    )
    assert p.status == "PROVEN"


def test_sql_forbidden_drop_refuted():
    p = SQLClauseProver().prove(
        {"templates": ["DROP TABLE customers"]},
        {},
    )
    assert p.status == "REFUTED"
    assert "DROP" in p.counterexample["violation"]


def test_sql_unknown_table_refuted():
    p = SQLClauseProver().prove(
        {"templates": ["SELECT * FROM secrets"]},
        {"allowed_tables": ["customers"]},
    )
    assert p.status == "REFUTED"
    assert "secrets" in p.counterexample["violation"].lower()


def test_sql_statement_chaining_refuted():
    p = SQLClauseProver().prove(
        {"templates": ["SELECT 1; DROP TABLE customers"]},
        {"allow_statement_chaining": False},
    )
    assert p.status == "REFUTED"


def test_sql_chaining_allowed_when_flag_set():
    p = SQLClauseProver().prove(
        {"templates": ["SELECT 1; SELECT 2"]},
        {"allow_statement_chaining": True, "forbidden_tokens": []},
    )
    assert p.status == "PROVEN"


# ---------------------------------------------------------------------------
# ProofResult shape
# ---------------------------------------------------------------------------


def test_proof_result_hash_is_canonical():
    r1 = ProofResult(
        status="PROVEN",
        prover="JSONSchemaProver",
        prover_version="jsonschema-prover/v1",
        grammar_hash="sha256:aaa",
        policy_hash="sha256:bbb",
    )
    r2 = ProofResult(
        status="PROVEN",
        prover="JSONSchemaProver",
        prover_version="jsonschema-prover/v1",
        grammar_hash="sha256:aaa",
        policy_hash="sha256:bbb",
    )
    assert r1.hash == r2.hash
    assert r1.hash.startswith("sha256:")


def test_url_max_path_depth_is_undecidable_not_proven():
    """max_path_depth over a prefix grammar cannot be PROVEN (segments appendable)."""
    from raucle.prove import URLPolicyProver

    grammar = {
        "schemes": ["https"],
        "hosts": ["api.example.com"],
        "path_prefixes": ["/v1"],
        "query_keys": [],
    }
    r = URLPolicyProver().prove(grammar, {"max_path_depth": 3})
    assert r.status == "UNDECIDED"
    # but a declared prefix already too deep is a concrete REFUTED counterexample
    r2 = URLPolicyProver().prove(
        {"schemes": ["https"], "hosts": ["h"], "path_prefixes": ["/a/b/c"], "query_keys": []},
        {"max_path_depth": 1},
    )
    assert r2.status == "REFUTED"


def test_sql_comma_join_not_falsely_proven():
    """A forbidden table reached via a comma-join must not yield PROVEN (soundness)."""
    from raucle.prove import SQLClauseProver

    p = SQLClauseProver()
    r = p.prove(
        {"templates": ["SELECT * FROM customers, secrets"]}, {"allowed_tables": ["customers"]}
    )
    assert r.status == "REFUTED"  # secrets is read but not allowed
    ok = p.prove(
        {"templates": ["SELECT * FROM customers WHERE id = 1"]}, {"allowed_tables": ["customers"]}
    )
    assert ok.status == "PROVEN"
    # a subquery the crude extractor can't decompose must be UNDECIDED, never PROVEN
    sub = p.prove(
        {"templates": ["SELECT * FROM (SELECT * FROM secrets) x"]},
        {"allowed_tables": ["customers"]},
    )
    assert sub.status in ("UNDECIDED", "REFUTED")


def test_sql_unmodelled_constructs_undecided():
    """§8.4: SQL constructs the regex extractor cannot model soundly must yield
    UNDECIDED on the allowed_tables (PROVEN-eligible) path, never a false PROVEN.
    """
    from raucle.prove import SQLClauseProver

    p = SQLClauseProver()
    pol = {"allowed_tables": ["customers"]}
    # quoted identifier could hide a disallowed table name
    quoted = p.prove({"templates": ['SELECT * FROM "customers"']}, pol)
    assert quoted.status == "UNDECIDED", quoted.status
    # table function — func(...) is not a base table the extractor can resolve
    tfunc = p.prove({"templates": ["SELECT * FROM generate_series(1, 10)"]}, pol)
    assert tfunc.status == "UNDECIDED", tfunc.status
    # LATERAL join
    lat = p.prove({"templates": ["SELECT * FROM customers, LATERAL (SELECT 1) z"]}, pol)
    assert lat.status == "UNDECIDED", lat.status
    # recursive CTE
    rec = p.prove({"templates": ["WITH RECURSIVE t AS (SELECT 1) SELECT * FROM customers"]}, pol)
    assert rec.status == "UNDECIDED", rec.status
    # VALUES table source
    vals = p.prove({"templates": ["SELECT * FROM (VALUES (1),(2)) v"]}, pol)
    assert vals.status == "UNDECIDED", vals.status
    # sanity: plain modelled SELECT still PROVEN
    ok = p.prove({"templates": ["SELECT id FROM customers WHERE id = 1"]}, pol)
    assert ok.status == "PROVEN", ok.status


def test_url_prover_unknown_keys_undecided():
    """B1/§8.1: URLPolicyProver must NOT certify a grammar/policy carrying a key
    it does not model — unknown key → UNDECIDED (never a false PROVEN)."""
    from raucle.prove import URLPolicyProver

    p = URLPolicyProver()
    base_grammar = {"schemes": ["https"], "hosts": ["api.example.com"]}
    # sanity: clean grammar/policy → PROVEN
    assert p.prove(base_grammar, {"require_https": True}).status == "PROVEN"
    # unknown grammar key
    g = dict(base_grammar, unmodelled_url_dimension=["x"])
    assert p.prove(g, {"require_https": True}).status == "UNDECIDED"
    # unknown policy key
    assert p.prove(base_grammar, {"unmodelled_policy_obligation": True}).status == "UNDECIDED"


def test_sql_unmodelled_construct_undecided_without_allowed_tables():
    """B2/§8.4: the unmodelled-SQL net must run even when no allowed_tables is
    set — otherwise UNNEST / quoted idents / recursive CTEs return false PROVEN."""
    from raucle.prove import SQLClauseProver

    p = SQLClauseProver()
    # No allowed_tables in policy at all.
    assert p.prove({"templates": ["SELECT * FROM UNNEST(xs)"]}, {}).status == "UNDECIDED"
    assert p.prove({"templates": ['SELECT * FROM "tbl"']}, {}).status == "UNDECIDED"
    rec = "WITH RECURSIVE t AS (SELECT 1) SELECT * FROM t"
    assert p.prove({"templates": [rec]}, {}).status == "UNDECIDED"
    # plain modelled SELECT still PROVEN with no allowed_tables
    assert p.prove({"templates": ["SELECT id FROM customers"]}, {}).status == "PROVEN"


def test_sql_unknown_policy_key_undecided():
    """B2/§8.1: an unknown SQL policy key → UNDECIDED."""
    from raucle.prove import SQLClauseProver

    p = SQLClauseProver()
    r = p.prove({"templates": ["SELECT id FROM customers"]}, {"unmodelled_sql_obligation": 1})
    assert r.status == "UNDECIDED", r.status
