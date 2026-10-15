"""Formal verification of bounded guardrails — SMT-backed completeness proofs.

The 2026 AI-security industry runs on the phrase *"we tested it against
10,000 attacks."*  That is not a guarantee, that is statistics over a
sample.  For bounded input sub-languages -- tool-call JSON, URL strings --
we can do dramatically better: produce an actual proof that **no string in
the grammar** bypasses a given policy. For SQL the scope is narrower: a
finite-template checker over a modelled subset (see ``SQLClauseProver``),
which returns ``UNDECIDED`` for any construct it does not model rather than
claiming a proof it cannot make.

This module ships three first-cut provers, each producing a signed
``ProofResult`` artifact whose hash can be embedded in a v0.5.0
verdict receipt or chained into the v0.4.0 audit log:

- ``JSONSchemaProver`` -- given a JSON Schema for a tool call and a
  policy (allowed enums, numeric bounds, forbidden field combinations),
  emit ``PROVEN`` or a concrete counterexample tool-call.
- ``URLPolicyProver`` -- given a URL allowlist (scheme + host glob +
  path prefix) and an extra rule (e.g. "no secrets in query"), emit
  ``PROVEN`` or a counterexample URL.
- ``SQLClauseProver`` -- a **finite SQL-template checker over a modelled
  subset** (NOT a general SQL prover): given a bounded policy (forbidden
  tokens, declared tables, no statement chaining) over an enumerated set of
  statement templates, emit ``PROVEN`` / ``REFUTED`` (counterexample) /
  ``UNDECIDED`` (template uses a construct outside the modelled subset).

The proof artifacts are not "the policy is safe in general" -- they
are "the policy is safe **over the declared grammar**".  That is the
honest scope.  When the grammar is the agent's tool-call interface,
the proof is exactly the property a buyer wants: *the agent literally
cannot emit a tool call that violates this policy*.

Usage::

    from raucle.prove import JSONSchemaProver

    schema = {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "amount": {"type": "number"},
            "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]},
        },
        "required": ["to", "amount", "currency"],
    }
    policy = {
        "max_amount": 100.0,
        "forbidden_recipients": ["attacker@evil.example"],
    }
    result = JSONSchemaProver().prove(schema, policy)
    if result.status == "PROVEN":
        print(result.hash)
    else:
        print("counterexample:", result.counterexample)

Design
------
- Z3 is the underlying SMT engine, used as an optional extra.  The
  prover is one ``pip install 'raucle[proof]'`` away.
- Every prove() returns a ``ProofResult`` whose canonical-JSON body
  is hashed identically to a receipt, so it can be Ed25519-signed
  and chained into existing trust primitives.
- We deliberately reject grammars we cannot model.  Unbounded regex
  fields, recursive schemas, and arbitrary string functions raise
  ``UnsupportedGrammar``.  Honest scope beats lying coverage.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from . import registry as _registry
from ._canon import utf16_key as _canon_utf16_key

_SHA256_PREFIX = "sha256:"  # named once (Sonar S1192)


def _canonical_json(obj: Any) -> bytes:
    # UTF-16 code-unit key ordering (shared _canon helper) so a strict-mode
    # policy_hash binds byte-identically to the capability token even for non-BMP
    # policy keys. allow_nan=False: NaN/Infinity are not valid JSON.
    from ._canon import reorder_keys_utf16

    return json.dumps(
        reorder_keys_utf16(obj),
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class UnsupportedGrammar(ValueError):
    """Raised when a schema or policy cannot be modelled honestly in SMT."""


def _require_z3() -> Any:
    try:
        import z3  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "raucle.prove requires the [proof] extra: pip install 'raucle[proof]'"
        ) from exc
    return z3


@dataclass
class ProofResult:
    """Outcome of a prover run.

    ``status`` is one of:

    - ``PROVEN``       -- the policy holds over every string in the grammar
    - ``REFUTED``      -- a counterexample exists; see ``counterexample``
    - ``UNDECIDED``    -- the solver timed out or returned ``unknown``
    """

    status: str
    prover: str
    prover_version: str
    grammar_hash: str
    policy_hash: str
    counterexample: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)
    timeout_ms: int = 0

    def body(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "prover": self.prover,
            "prover_version": self.prover_version,
            "grammar_hash": self.grammar_hash,
            "policy_hash": self.policy_hash,
            "counterexample": self.counterexample,
            "notes": sorted(self.notes, key=_canon_utf16_key),
            "timeout_ms": self.timeout_ms,
        }

    @property
    def hash(self) -> str:
        return _SHA256_PREFIX + _sha256_hex(_canonical_json(self.body()))

    def to_dict(self) -> dict[str, Any]:
        d = self.body()
        d["hash"] = self.hash
        return d


# ---------------------------------------------------------------------------
# JSON Schema prover
# ---------------------------------------------------------------------------


_JSON_PROVER_VERSION = "jsonschema-prover/v1"


@dataclass
class JSONSchemaProver:
    """Prove that no JSON object matching ``schema`` violates ``policy``.

    Supported schema fragments:

    - ``type``: ``object``, ``string``, ``number``, ``integer``, ``boolean``
    - ``properties`` with primitive types
    - ``required``
    - ``enum`` on strings
    - ``minimum`` / ``maximum`` on numbers

    Supported policy keys:

    - ``forbidden_values`` -- ``{field: [bad, ...]}`` for string fields
    - ``max_value`` / ``min_value`` -- ``{field: bound}`` for numeric fields
    - ``required_present`` -- ``[field, ...]`` (redundant with schema, but
      useful when the schema is permissive and the policy is strict)
    - ``forbidden_field_combinations`` -- ``[[a, b], ...]`` (a present AND
      b present is a violation)

    .. note::
       ``allowed_values`` (whitelists) and ``starts_with`` (string-prefix) are
       **gate-time** capability constraints (see
       :func:`raucle.capability._check_constraints`) that this prover
       does **not** model. They are NOT silently ignored: a policy carrying any
       key outside the registry's ``PROVER_ENCODABLE_KEYS`` downgrades a
       would-be PROVEN to **UNDECIDED** (§8.2 — never a proof that omitted part
       of the policy). Express positive whitelists/prefixes as capability
       constraints enforced at the gate.
    """

    timeout_ms: int = 5000

    @staticmethod
    def _build_z3_var(z3: Any, name: str, spec: dict, presence: dict, constraints: list) -> Any:
        """Build a single Z3 variable from a property spec. Returns the z3 var."""
        t = spec.get("type")
        if t == "string":
            var = z3.String(name)
            if "enum" in spec:
                enum = spec["enum"]
                if not all(isinstance(e, str) for e in enum):
                    raise UnsupportedGrammar(f"enum on {name} must be all strings")
                constraints.append(
                    z3.Implies(
                        presence[name],
                        z3.Or(*[var == v for v in enum]),
                    )
                )
            return var
        if t in ("number", "integer"):
            var = z3.Real(name) if t == "number" else z3.Int(name)
            if "minimum" in spec:
                constraints.append(z3.Implies(presence[name], var >= spec["minimum"]))
            if "maximum" in spec:
                constraints.append(z3.Implies(presence[name], var <= spec["maximum"]))
            return var
        if t == "boolean":
            return z3.Bool(name)
        raise UnsupportedGrammar(f"unsupported property type {t!r} on {name}")

    @staticmethod
    def _build_z3_vars(
        z3: Any,
        schema: dict[str, Any],
        constraints: list[Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        """Build Z3 variables for each declared property.

        Returns ``(z3_vars, presence, prop_types)``.
        """
        z3_vars: dict[str, Any] = {}
        presence: dict[str, Any] = {}
        prop_types: dict[str, str] = {}
        required = set(schema.get("required", []))

        for name, spec in schema["properties"].items():
            prop_types[name] = spec.get("type")
            presence[name] = z3.Bool(f"__present__{name}")
            if name in required:
                constraints.append(presence[name])
            z3_vars[name] = JSONSchemaProver._build_z3_var(z3, name, spec, presence, constraints)
        return z3_vars, presence, prop_types

    @staticmethod
    def _encode_forbidden_values(
        z3: Any,
        fld: str,
        bads: list,
        z3_vars: dict[str, Any],
        presence: dict[str, Any],
        prop_types: dict[str, str],
        additional_allowed: bool,
        notes: list[str],
    ) -> list[Any]:
        """Encode forbidden_values for a single field as Z3 violations."""
        if fld not in z3_vars:
            if not additional_allowed:
                notes.append(
                    f"forbidden_values field {fld!r} not in schema; "
                    f"additionalProperties:false makes it unreachable"
                )
                return []
            z3_vars[fld] = z3.String(fld)
            presence[fld] = z3.Bool(f"__present__{fld}")
            prop_types[fld] = "string"
            notes.append(
                f"forbidden_values field {fld!r} not declared but "
                f"additionalProperties allows it; modelled as a free field"
            )
        elif prop_types.get(fld) != "string":
            raise UnsupportedGrammar(f"forbidden_values on non-string field {fld!r} not supported")
        return [z3.And(presence[fld], z3_vars[fld] == bad) for bad in bads]

    @staticmethod
    def _encode_policy_violations(
        z3: Any,
        policy: dict[str, Any],
        z3_vars: dict[str, Any],
        presence: dict[str, Any],
        prop_types: dict[str, str],
        additional_allowed: bool,
        notes: list[str],
    ) -> list[Any]:
        """Encode policy constraints as Z3 violation disjunctions."""
        violations: list[Any] = []

        for fld, bads in policy.get("forbidden_values", {}).items():
            violations.extend(
                JSONSchemaProver._encode_forbidden_values(
                    z3, fld, bads, z3_vars, presence, prop_types, additional_allowed, notes
                )
            )

        for fld, bound in policy.get("max_value", {}).items():
            if fld not in z3_vars or prop_types.get(fld) not in ("number", "integer"):
                raise UnsupportedGrammar(f"max_value on non-numeric field {fld!r}")
            violations.append(z3.And(presence[fld], z3_vars[fld] > bound))

        for fld, bound in policy.get("min_value", {}).items():
            if fld not in z3_vars or prop_types.get(fld) not in ("number", "integer"):
                raise UnsupportedGrammar(f"min_value on non-numeric field {fld!r}")
            violations.append(z3.And(presence[fld], z3_vars[fld] < bound))

        for fld in policy.get("required_present", []):
            if fld not in presence:
                raise UnsupportedGrammar(f"required_present references unknown field {fld!r}")
            violations.append(z3.Not(presence[fld]))

        for combo in policy.get("forbidden_field_combinations", []):
            if not all(c in presence for c in combo):
                raise UnsupportedGrammar(
                    f"forbidden_field_combinations references unknown fields: {combo!r}"
                )
            violations.append(z3.And(*[presence[c] for c in combo]))

        return violations

    def prove(
        self,
        schema: dict[str, Any],
        policy: dict[str, Any],
    ) -> ProofResult:
        z3 = _require_z3()
        if schema.get("type") != "object" or "properties" not in schema:
            raise UnsupportedGrammar(
                "JSONSchemaProver only supports top-level type=object with properties"
            )

        notes: list[str] = []

        # Keywords that change which objects are valid but that this prover does
        # NOT model. If any are present we cannot soundly certify PROVEN —
        # e.g. patternProperties / propertyNames can admit fields that
        # `additionalProperties: false` otherwise appears to forbid, and
        # allOf/anyOf/oneOf/$ref reshape the value space. We still run the solver
        # (a REFUTED counterexample stays valid) but downgrade any would-be
        # PROVEN to UNDECIDED. (Soundness fix: a `{"role":"admin"}` object is
        # schema-valid under patternProperties `^role$` even with
        # additionalProperties:false, so a blacklist on `role` is not provable.)
        # Modelled schema keywords come from the registry (§8.1) so the drift
        # test pins them; an unmodelled keyword downgrades PROVEN → UNDECIDED.
        unmodelled = sorted(set(schema) - _registry.JSON_SCHEMA_OBJECT_KEYS)
        if unmodelled:
            notes.append(
                f"schema uses keyword(s) this prover does not model {unmodelled}; "
                f"PROVEN downgraded to UNDECIDED (cannot certify completeness)"
            )

        # Policy-language whitelist (§8.2 — "decorative proof inputs"). The
        # prover only encodes the constraint kinds flagged ``prover_encodable``
        # in the Modelled Language Registry. A policy carrying any other key
        # (e.g. ``allowed_values`` / ``starts_with``, which the gate DOES
        # enforce but this prover does NOT model) would otherwise be certified
        # PROVEN while silently ignoring that key — a proof that omitted part of
        # the policy, then bound into the token's policy_proof_hash. Fail closed:
        # any unmodelled policy key downgrades a would-be PROVEN to UNDECIDED.
        unmodelled_policy = sorted(_registry.unmodelled_policy_keys(set(policy)))
        if unmodelled_policy:
            unmodelled = sorted(set(unmodelled) | set(unmodelled_policy))
            notes.append(
                f"policy uses constraint key(s) this prover does not model "
                f"{unmodelled_policy}; PROVEN downgraded to UNDECIDED "
                f"(cannot certify a policy whose keys it ignores)"
            )
        # Build Z3 variables per declared property.
        constraints: list[Any] = []
        z3_vars, presence, prop_types = self._build_z3_vars(z3, schema, constraints)

        # Encode the policy as a *violation* disjunction.  We ask the solver:
        # is there any assignment satisfying the schema that ALSO satisfies the
        # violation?  If unsat, the policy is proven complete.
        # JSON Schema permits undeclared fields unless additionalProperties is
        # explicitly false. A blacklist over a field the schema does not declare
        # is therefore NOT vacuous: an attacker can supply that field with the
        # forbidden value and still satisfy the schema. (Soundness fix — a bare
        # `continue` here previously discarded the constraint and returned PROVEN
        # for e.g. {"properties":{"x":...},"additionalProperties":true} +
        # forbidden_values:{"role":["admin"]}, which {"x":"ok","role":"admin"}
        # violates.)
        additional_allowed = schema.get("additionalProperties", True) is not False

        violations = self._encode_policy_violations(
            z3, policy, z3_vars, presence, prop_types, additional_allowed, notes
        )

        if not violations:
            notes.append("no policy constraints; trivially proven")

        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        for c in constraints:
            solver.add(c)
        solver.add(z3.Or(*violations) if violations else z3.BoolVal(False))

        check = solver.check()
        if str(check) == "unsat":
            # Cannot certify completeness when the schema uses keywords we don't
            # model (patternProperties/composition/$ref) — fail safe.
            status = "UNDECIDED" if unmodelled else "PROVEN"
            counter = None
        elif str(check) == "sat":
            status = "REFUTED"
            model = solver.model()
            counter = self._extract_counterexample(model, z3_vars, presence)
        else:
            status = "UNDECIDED"
            counter = None
            notes.append(f"solver returned {check}")

        return ProofResult(
            status=status,
            prover="JSONSchemaProver",
            prover_version=_JSON_PROVER_VERSION,
            grammar_hash=_SHA256_PREFIX + _sha256_hex(_canonical_json(schema)),
            policy_hash=_SHA256_PREFIX + _sha256_hex(_canonical_json(policy)),
            counterexample=counter,
            notes=notes,
            timeout_ms=self.timeout_ms,
        )

    @staticmethod
    def _extract_counterexample(
        model: Any, z3_vars: dict[str, Any], presence: dict[str, Any]
    ) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, var in z3_vars.items():
            pres = model.eval(presence[name], model_completion=True)
            if str(pres) != "True":
                continue
            val = model.eval(var, model_completion=True)
            s = str(val).strip('"')
            if s in ("True", "False"):
                out[name] = s == "True"
            else:
                try:
                    out[name] = int(s) if "." not in s else float(s)
                except ValueError:
                    out[name] = s
        return out


# ---------------------------------------------------------------------------
# URL policy prover
# ---------------------------------------------------------------------------


_URL_PROVER_VERSION = "url-prover/v1"


@dataclass
class URLPolicyProver:
    """Prove that every URL matching ``grammar`` satisfies ``policy``.

    ``grammar`` is a small enumerable shape::

        {
            "schemes": ["https"],
            "hosts": ["api.example.com", "*.example.com"],
            "path_prefixes": ["/v1/", "/v2/"],
            "query_keys": ["q", "page"],
        }

    ``policy``::

        {
            "require_https": true,
            "forbid_query_keys": ["token", "api_key", "password"],
            "host_allowlist": ["api.example.com", "*.example.com"],
            "max_path_depth": 5,
        }

    The completeness claim is: for every URL the agent can construct under
    ``grammar``, the policy holds.  Counterexamples are concrete URLs.
    """

    @staticmethod
    def _check_require_https(
        policy: dict[str, Any], schemes: list[str], hosts: list[str], path_prefixes: list[str]
    ) -> list[dict[str, Any]]:
        """Check require_https: every non-https scheme is a violation."""
        violations: list[dict[str, Any]] = []
        if policy.get("require_https"):
            for s in schemes:
                if s != "https":
                    violations.append({"scheme": s, "host": hosts[0], "path": path_prefixes[0]})
        return violations

    @staticmethod
    def _check_forbid_query_keys(
        policy: dict[str, Any],
        grammar: dict[str, Any],
        query_keys: list[str],
        schemes: list[str],
        hosts: list[str],
        path_prefixes: list[str],
    ) -> tuple[list[dict[str, Any]], bool, list[str]]:
        """Check forbid_query_keys. Returns ``(violations, undecidable, notes)``."""
        violations: list[dict[str, Any]] = []
        notes: list[str] = []
        undecidable = False
        forbidden_q = set(policy.get("forbid_query_keys", []))
        for q in query_keys:
            if q in forbidden_q:
                violations.append(
                    {
                        "scheme": schemes[0],
                        "host": hosts[0],
                        "path": path_prefixes[0],
                        "query_key": q,
                    }
                )
        if forbidden_q and not grammar.get("query_keys_closed"):
            undecidable = True
            notes.append(
                "forbid_query_keys cannot be PROVEN over an open query-key grammar: "
                "an agent may append a forbidden key to any URL. Declare "
                "'query_keys_closed': true to assert the key set is exhaustive (UNDECIDED)"
            )
        return violations, undecidable, notes

    @staticmethod
    def _check_host_allowlist(
        policy: dict[str, Any], hosts: list[str], schemes: list[str], path_prefixes: list[str]
    ) -> list[dict[str, Any]]:
        """Check host_allowlist: every grammar host must be permitted."""
        violations: list[dict[str, Any]] = []
        allowlist = policy.get("host_allowlist")
        if allowlist is not None:
            for h in hosts:
                if not any(_host_matches(h, a) for a in allowlist):
                    violations.append({"scheme": schemes[0], "host": h, "path": path_prefixes[0]})
        return violations

    @staticmethod
    def _check_max_path_depth(
        policy: dict[str, Any], path_prefixes: list[str], schemes: list[str], hosts: list[str]
    ) -> tuple[list[dict[str, Any]], bool, list[str]]:
        """Check max_path_depth. Returns ``(violations, undecidable, notes)``."""
        violations: list[dict[str, Any]] = []
        notes: list[str] = []
        undecidable = False
        max_depth = policy.get("max_path_depth")
        if max_depth is not None:
            depth_violation = False
            for p in path_prefixes:
                depth = len([s for s in p.split("/") if s])
                if depth > max_depth:
                    notes.append(f"path prefix {p!r} already exceeds max_path_depth={max_depth}")
                    violations.append({"scheme": schemes[0], "host": hosts[0], "path": p})
                    depth_violation = True
            if not depth_violation:
                undecidable = True
                notes.append(
                    "max_path_depth cannot be PROVEN over a prefix grammar: an agent may append "
                    "segments to any prefix, so deeper paths remain constructible (UNDECIDED)"
                )
        return violations, undecidable, notes

    def prove(self, grammar: dict[str, Any], policy: dict[str, Any]) -> ProofResult:
        notes: list[str] = []
        violations: list[dict[str, Any]] = []

        schemes = grammar.get("schemes", [])
        hosts = grammar.get("hosts", [])
        path_prefixes = grammar.get("path_prefixes", ["/"])
        query_keys = grammar.get("query_keys", [])

        if not schemes or not hosts:
            raise UnsupportedGrammar("grammar must declare non-empty schemes and hosts")

        # §8.1/§8.2 fail-closed: a grammar or policy key this prover does not
        # model cannot be certified — it may impose an obligation or expand the
        # URL space we never checked. Downgrade any would-be PROVEN to UNDECIDED
        # (a REFUTED counterexample below stays valid). Registry-backed so the
        # drift test pins the modelled surface.
        unmodelled_url = sorted(_registry.unmodelled_url_keys(set(grammar), set(policy)))
        undecidable = bool(unmodelled_url)
        if unmodelled_url:
            notes.append(
                f"URL grammar/policy uses key(s) this prover does not model "
                f"{unmodelled_url}; PROVEN downgraded to UNDECIDED "
                f"(cannot certify a dimension it does not check)"
            )

        # require_https
        violations.extend(self._check_require_https(policy, schemes, hosts, path_prefixes))

        # forbid_query_keys
        q_violations, q_undecidable, q_notes = self._check_forbid_query_keys(
            policy, grammar, query_keys, schemes, hosts, path_prefixes
        )
        violations.extend(q_violations)
        undecidable = undecidable or q_undecidable
        notes.extend(q_notes)

        # host_allowlist
        violations.extend(self._check_host_allowlist(policy, hosts, schemes, path_prefixes))

        # max_path_depth
        d_violations, d_undecidable, d_notes = self._check_max_path_depth(
            policy, path_prefixes, schemes, hosts
        )
        violations.extend(d_violations)
        undecidable = undecidable or d_undecidable
        notes.extend(d_notes)

        if violations:
            status = "REFUTED"
            counter = violations[0]
        elif undecidable:
            status = "UNDECIDED"
            counter = None
        else:
            status = "PROVEN"
            counter = None

        return ProofResult(
            status=status,
            prover="URLPolicyProver",
            prover_version=_URL_PROVER_VERSION,
            grammar_hash=_SHA256_PREFIX + _sha256_hex(_canonical_json(grammar)),
            policy_hash=_SHA256_PREFIX + _sha256_hex(_canonical_json(policy)),
            counterexample=counter,
            notes=notes,
        )


def _host_matches(host: str, pattern: str) -> bool:
    """Match a host against an optionally wildcarded pattern.

    ``*.example.com`` matches a strict subdomain (``api.example.com``) but NOT
    the apex (``example.com``) — consistent with RFC 6125 / TLS / cookie wildcard
    semantics. Matching the apex would let the prover return PROVEN for apex
    access under a subdomain-only allowlist (overbroad). To permit the apex,
    list it explicitly alongside the wildcard.
    """
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com" — requires at least one label before it
        apex = pattern[2:]  # "example.com" — the bare domain
        return host.endswith(suffix) and host != apex
    return False


# ---------------------------------------------------------------------------
# SQL clause prover (bounded read-only-ish policy)
# ---------------------------------------------------------------------------


_SQL_PROVER_VERSION = "sql-prover/v1"

_DEFAULT_FORBIDDEN_TOKENS = (
    "DROP",
    "DELETE",
    "TRUNCATE",
    "ALTER",
    "UPDATE",
    "INSERT",
    "INTO",  # SELECT ... INTO writes a new table under a read-only default
    "MERGE",
    "CREATE",
    "REPLACE",
    "GRANT",
    "REVOKE",
    "EXEC",
    "EXECUTE",
    "CALL",
    "ATTACH",
    "PRAGMA",
)

_STATEMENT_CHAIN_RE = re.compile(r";\s*\S")

# §8.4 — SQL constructs the regex FROM/JOIN extractor does NOT model soundly.
# Their presence in a template makes static table-isolation unverifiable, so a
# would-be PROVEN is downgraded to UNDECIDED (fail-closed) rather than risk a
# false PROVEN. This enumerates the "reject → UNDECIDED" side of §8.4:
#   - quoted/back-quoted identifiers (a quoted name can contain whitespace,
#     keywords, or dots that defeat the identifier/clause regexes);
#   - LATERAL / table functions / UNNEST / VALUES table sources;
#   - recursive or otherwise non-trivial CTEs (name shadowing);
#   - TABLESAMPLE / PIVOT / UNPIVOT dialect forms.
# A plain SELECT/WITH over FROM/JOIN with bare identifiers stays in the modelled
# (PROVEN-eligible) set. sqlglot is intentionally NOT adopted here: a parser
# whose AST diverges from the target DB's own dialect is itself a soundness
# risk (§8.4); the conservative-UNDECIDED net is sound without it.
# Built from the registry's SQL construct surface (§8.4) so the modelled set is
# registry-owned and the drift test can pin it.
_UNMODELLED_SQL_RE = re.compile("|".join(_registry.SQL_UNMODELLED_CONSTRUCTS), re.IGNORECASE)


@dataclass
class SQLClauseProver:
    """A **finite SQL-template checker over a modelled subset** — not a general
    SQL prover.

    It checks a bounded policy across an enumerated set of statement *templates*
    using a regex extractor; it does **not** parse arbitrary SQL. Templates that
    use constructs outside the modelled subset (quoted identifiers,
    ``LATERAL``/``UNNEST``/``VALUES``, recursive CTEs, table functions, and
    other dialect forms — see ``registry.SQL_UNMODELLED_CONSTRUCTS``) yield
    UNDECIDED, never a false PROVEN. Highest assurance for table isolation comes
    from validating against the target DB's own parser under a no-execute role;
    this checker is a portable, dependency-light approximation that fails closed.

    The honest claim is: given a finite set
    of statement *templates* and the columns/tables they touch, prove the
    policy holds for every template.

    ``grammar``::

        {
            "templates": [
                "SELECT id, name FROM customers WHERE tenant_id = ?",
                "SELECT total FROM invoices WHERE id = ?"
            ],
            "allowed_tables": ["customers", "invoices"],
        }

    ``policy``::

        {
            "forbidden_tokens": ["DROP", "DELETE", ...],   # case-insensitive
            "allow_statement_chaining": false,
            "allowed_tables": ["customers", "invoices"],
        }

    Counterexamples are the offending template plus the rule that broke.
    """

    @staticmethod
    def _extract_table_refs(upper: str, tmpl: str, notes: list[str]) -> tuple[list[str], bool]:
        """Extract table references from FROM/JOIN clauses.

        Returns ``(table_refs, undecidable)``.
        """
        clause_re = re.compile(
            r"(?:FROM|JOIN)\s+(.+?)"
            r"(?=\s+(?:WHERE|GROUP|ORDER|HAVING|LIMIT|UNION|EXCEPT"
            r"|INTERSECT|MINUS|JOIN|ON|USING|FOR)\b|;|$)",
            re.DOTALL,
        )
        table_refs: list[str] = []
        undecidable = False
        for clause in clause_re.findall(upper):
            for piece in clause.split(","):
                piece = piece.strip()
                if not piece:
                    continue
                if "(" in piece:
                    undecidable = True
                    notes.append(f"unparsable table reference in {tmpl!r} (UNDECIDED)")
                    continue
                m = re.match(r"([A-Z_][A-Z0-9_]*(?:\.[A-Z_][A-Z0-9_]*)*)", piece)
                if m:
                    table_refs.append(m.group(1))
                else:
                    undecidable = True
                    notes.append(f"unparsable table reference in {tmpl!r} (UNDECIDED)")
        return table_refs, undecidable

    @staticmethod
    def _check_sql_template(
        tmpl: str,
        forbidden: set[str],
        allow_chain: bool,
        allowed_tables: set[str],
        notes: list[str],
    ) -> tuple[dict[str, Any] | None, bool]:
        """Check one SQL template against the policy.

        Returns ``(counterexample, undecidable)``.
        """
        upper = tmpl.upper()

        # Forbidden tokens
        tokens = re.findall(r"[A-Z_][A-Z_0-9]*", upper)
        for tok in tokens:
            if tok in forbidden:
                return {"template": tmpl, "violation": f"forbidden token {tok}"}, False

        # Statement chaining
        if not allow_chain and _STATEMENT_CHAIN_RE.search(tmpl):
            return {"template": tmpl, "violation": "statement chaining via ';'"}, False

        # §8.4: unmodelled SQL constructs → UNDECIDED
        if _UNMODELLED_SQL_RE.search(tmpl):
            notes.append(
                f"unmodelled SQL construct in {tmpl!r} (quoted identifier / "
                f"LATERAL / UNNEST / VALUES / recursive CTE / dialect form); "
                f"completeness not verifiable (UNDECIDED)"
            )
            return None, True

        if not allowed_tables:
            return None, False

        # The FROM/JOIN extractor is only SOUND for plain SELECT queries.
        if not re.match(r"\s*(WITH\b|SELECT\b)", upper) or re.search(
            r"\b(COPY|INTO|MERGE)\b", upper
        ):
            notes.append(
                f"table-bearing statement form in {tmpl!r} not covered by the "
                f"FROM/JOIN extractor; table isolation not verifiable (UNDECIDED)"
            )
            return None, True

        table_refs, tbl_undecidable = SQLClauseProver._extract_table_refs(upper, tmpl, notes)
        for ref in table_refs:
            if ref.lower() not in allowed_tables:
                return (
                    {"template": tmpl, "violation": f"table {ref!r} not in allowed_tables"},
                    tbl_undecidable,
                )
        return None, tbl_undecidable

    def prove(self, grammar: dict[str, Any], policy: dict[str, Any]) -> ProofResult:
        templates = grammar.get("templates")
        if not templates:
            raise UnsupportedGrammar("grammar.templates must be a non-empty list")

        forbidden = {t.upper() for t in policy.get("forbidden_tokens", _DEFAULT_FORBIDDEN_TOKENS)}
        allow_chain = policy.get("allow_statement_chaining", False)
        # allowed_tables is a POLICY constraint and the policy allowlist must
        # DOMINATE. Earlier this unioned in grammar.allowed_tables, letting
        # attacker-controlled grammar BROADEN the policy allowlist (round-6 F1).
        # Now the grammar's copy is ignored entirely. But if it appears ONLY in
        # the grammar (and not the policy), that is a caller mistake that would
        # otherwise yield an unrestricted PROVEN — reject it loudly (round-4 F3).
        if "allowed_tables" in grammar and "allowed_tables" not in policy:
            raise UnsupportedGrammar(
                "allowed_tables is a policy constraint, not grammar metadata — "
                "pass it in the policy argument, not the grammar"
            )
        allowed_tables = {t.lower() for t in policy.get("allowed_tables", [])}

        notes: list[str] = []
        counter: dict[str, Any] | None = None
        undecidable = False

        # §8.1 fail-closed: unknown SQL grammar/policy keys cannot be certified.
        unmodelled_sql = sorted(_registry.unmodelled_sql_keys(set(grammar), set(policy)))
        if unmodelled_sql:
            undecidable = True
            notes.append(
                f"SQL grammar/policy uses key(s) this prover does not model "
                f"{unmodelled_sql}; PROVEN downgraded to UNDECIDED"
            )

        for tmpl in templates:
            counter, tmpl_undecidable = self._check_sql_template(
                tmpl, forbidden, allow_chain, allowed_tables, notes
            )
            undecidable = undecidable or tmpl_undecidable
            if counter:
                break

        if counter is not None:
            status = "REFUTED"
        elif undecidable:
            status = "UNDECIDED"
        else:
            status = "PROVEN"
        return ProofResult(
            status=status,
            prover="SQLClauseProver",
            prover_version=_SQL_PROVER_VERSION,
            grammar_hash=_SHA256_PREFIX + _sha256_hex(_canonical_json(grammar)),
            policy_hash=_SHA256_PREFIX + _sha256_hex(_canonical_json(policy)),
            counterexample=counter,
            notes=notes,
        )
