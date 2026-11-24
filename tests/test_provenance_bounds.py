"""Q19: provenance verifier resource bounds (red-first).

Per-close coverage for the phase-9 verifier-security review, Finding 67:

(a) a 5000-deep synthetic chain refuses at the depth bound, named;
(b) an oversized parent array refuses at the parent-count bound, named;
(c) a diamond-heavy shared-ancestor graph: the memoised traversal's work
    counter stays at one edge examination per adjacency entry while an
    unmemoised baseline re-walks the shared subgraphs exponentially, with
    identical verdicts to the unbounded baseline on small graphs;
(d) a cycle is refused by name (defensive traversal seam, corrupted-map
    data, the house precedent) and the content-addressing property pin;
(e) bounds-disabled env restores legacy behaviour; default ON (fail-closed);
(f) real receipts from the existing suite corpus verify unchanged.

Every refusal is named ``ProvenanceVerifierBoundsExceeded`` and carries the
limit hit, the observed value and the cap. Bounds are env-overridable per
deployment (``RAUCLE_VERIFY_MAX_*``); ``RAUCLE_VERIFY_BOUNDS=off`` restores
the legacy unbounded verifier for the documented migration window.
"""

import json
from itertools import count
from pathlib import Path

import pytest

import raucle.provenance as provenance_mod
from raucle.provenance import (
    AgentIdentity,
    Operation,
    ProvenanceReceipt,
    ProvenanceVerifier,
    hash_text,
)

REPO = Path(__file__).resolve().parent.parent
DEMO_BUNDLE_CHAIN = REPO / "docs/demo-bundle/chain.jsonl"
DEMO_BUNDLE_PUBKEY = REPO / "docs/demo-bundle/pubkeys/b5fc7cdc4daecad1.pem"

_mint_counter = count()

_identities = []


def _identity() -> AgentIdentity:
    if not _identities:
        ident = AgentIdentity.generate("agent:q19-bounds")
        _identities.append(ident)
    return _identities[0]


def _mint(op, parents, *, taint=("external_user",), corpus="", tool=""):
    """Mint a distinct receipt. Every receipt varies its hashed content so
    no two receipts share payload bytes (identical payloads hash-collapse,
    the suite's known duplicate-hash pitfall)."""
    ident = _identity()
    receipt = ProvenanceReceipt(
        agent_id=ident.agent_id,
        agent_key_id=ident.key_id,
        operation=op,
        parents=sorted(parents),
        input_hash=hash_text(f"q19-distinct-{next(_mint_counter)}"),
        output_hash=hash_text("out"),
        model="m" if op == Operation.MODEL_CALL else "",
        tool=tool,
        taint=sorted(set(taint)),
        tenant="tenant-q19" if op == Operation.RETRIEVAL else None,
        issued_at=1_700_000_000,
        corpus=corpus,
    )
    receipt.sign(ident)
    return receipt


def _write_chain(tmp_path: Path, name: str, receipts) -> Path:
    path = tmp_path / name
    with open(path, "w", encoding="utf-8") as fh:
        for r in receipts:
            fh.write(json.dumps({"receipt_hash": r.receipt_hash, "jws": r.jws}) + "\n")
    return path


def _verify(path, extra_env=None, unset=None):
    """Verify with the Q19 env contract applied (bounds read at
    ProvenanceVerifier construction, mirroring the deployment surface)."""
    import os

    env = os.environ
    saved = {}
    try:
        for name in unset or []:
            saved[name] = env.pop(name, None)
        for key, value in (extra_env or {}).items():
            saved[key] = env.get(key)
            env[key] = value
        verifier = ProvenanceVerifier(public_keys=_public_keys())
        return verifier.verify_chain(path)
    finally:
        for key, value in saved.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value


def _public_keys():
    ident = _identity()
    return {ident.key_id: ident.public_key_pem()}


def _deep_chain(n: int):
    chain = [_mint(Operation.USER_INPUT, [])]
    prev = chain[0].receipt_hash
    for _ in range(n - 1):
        nxt = _mint(Operation.MODEL_CALL, [prev])
        chain.append(nxt)
        prev = nxt.receipt_hash
    return chain


def _refusal_errors(report) -> list[str]:
    return [e for e in report.errors if "ProvenanceVerifierBoundsExceeded" in e]


# ---------------------------------------------------------------------------
# (a) deep chain refuses at the depth bound, named
# ---------------------------------------------------------------------------


def test_deep_chain_refuses_at_depth_bound_named(tmp_path, monkeypatch):
    """A 5000-deep chain refuses with a named depth refusal once the
    bundle-bytes override lifts the byte cap out of the way (the documented
    operator recipe for genuinely deep chains: raise the byte bound, the
    depth bound then binds at its own default)."""
    monkeypatch.setenv("RAUCLE_VERIFY_MAX_BUNDLE_BYTES", "100000000")
    monkeypatch.setenv("RAUCLE_VERIFY_MAX_NODES", "100000")
    chain = _deep_chain(5000)
    path = _write_chain(tmp_path, "deep5000.jsonl", chain)
    report = _verify(path)
    assert report.valid is False
    refusals = _refusal_errors(report)
    assert refusals, "a 5000-deep chain must refuse at a named bound"
    text = refusals[0]
    assert "graph_depth" in text
    assert "observed=257" in text  # cap default 256: first node over the cap
    assert "cap=256" in text


# ---------------------------------------------------------------------------
# (b) oversized parent array refuses at the parent-count bound, named
# ---------------------------------------------------------------------------


def test_oversize_parent_array_refuses_at_count_bound_named(tmp_path, monkeypatch):
    """One merge receipt citing 300 distinct parents (under the 32 KiB
    payload cap, so the receipt parses) refuses at the fan-out bound with a
    named per-line refusal; the rest of the bundle grades normally. The
    bundle-bytes override lifts the byte cap out of the way so the
    parent-count bound is the one under test."""
    monkeypatch.setenv("RAUCLE_VERIFY_MAX_BUNDLE_BYTES", "10000000")
    roots = [_mint(Operation.USER_INPUT, []) for _ in range(300)]
    wide = _mint(Operation.MERGE, [r.receipt_hash for r in roots])
    path = _write_chain(tmp_path, "wide300.jsonl", roots + [wide])
    report = _verify(path)
    assert report.valid is False
    refusals = _refusal_errors(report)
    assert refusals, "an oversized parent array must refuse at a named bound"
    text = refusals[0]
    assert "parent_count" in text
    assert "observed=300" in text
    assert "cap=256" in text
    # the refusal is per-line, not bundle-fatal: every receipt graded
    assert report.receipt_count == 301


# ---------------------------------------------------------------------------
# (c) memoised traversal: work counter + verdict parity
# ---------------------------------------------------------------------------


def _fib_diamond(depth: int):
    """Fibonacci diamond: receipt r(d) cites r(d-1) and r(d-2). The number
    of root paths grows like Fibonacci(d), so an unmemoised depth walk
    re-expands the shared subgraphs exponentially while a memoised one
    expands every receipt exactly once."""
    r0 = _mint(Operation.USER_INPUT, [])
    r1 = _mint(Operation.MODEL_CALL, [r0.receipt_hash])
    by_depth = {0: r0, 1: r1}
    prev2, prev1 = r0.receipt_hash, r1.receipt_hash
    for d in range(2, depth + 1):
        nxt = _mint(Operation.MODEL_CALL, [prev1, prev2])
        by_depth[d] = nxt
        prev2, prev1 = prev1, nxt.receipt_hash
    return by_depth


def _naive_ancestor_visits(parents_of: dict, start: str) -> int:
    """The unmemoised baseline: every root path re-descends, no caching."""
    total = 0
    stack = [start]
    while stack:
        total += 1
        for parent in parents_of.get(stack.pop(), []):
            stack.append(parent)
    return total


def test_memoised_traversal_work_counter_and_parities(tmp_path, monkeypatch):
    chain = list(_fib_diamond(18).values())
    parents_of = {r.receipt_hash: list(r.parents) for r in chain}
    total_edges = sum(len(p) for p in parents_of.values())
    path = _write_chain(tmp_path, "fib18.jsonl", chain)

    monkeypatch.delenv("RAUCLE_VERIFY_BOUNDS", raising=False)
    report = _verify(path)
    assert report.valid is True
    # Work counter: exactly one edge examination per adjacency entry and one
    # expansion per receipt (visit-set keyed caching did the work once).
    assert report.traversal_edges_examined == total_edges
    assert report.traversal_receipts_expanded == len(chain)
    # The unmemoised baseline re-walks shared subgraphs: far more work on the
    # same graph (the counter is the honest proof of "visibly faster").
    naive = _naive_ancestor_visits(parents_of, chain[-1].receipt_hash)
    assert naive >= 100 * report.traversal_receipts_expanded
    # verdict parity: the unbounded (legacy) verifier agrees on every shared
    # field, and the memoised pass changed no verdict on this small graph.
    legacy = _verify(
        path, extra_env={"RAUCLE_VERIFY_BOUNDS": "off"}, unset=["RAUCLE_VERIFY_MAX_BUNDLE_BYTES"]
    )
    for field in (
        "valid",
        "receipt_count",
        "signature_failures",
        "parent_link_failures",
        "taint_monotonicity_failures",
        "capability_violations",
        "unauthorised_sanitisations",
        "tampered_receipts",
        "errors",
    ):
        assert getattr(report, field) == getattr(legacy, field), field


def test_small_graph_verdict_parity_bounds_on_vs_off(tmp_path, monkeypatch):
    """Verdict parity on small graphs, including a tampered one: the memoised
    bounded pass is pure performance and bounds, never a verdict change."""
    chain = _deep_chain(12)
    path = _write_chain(tmp_path, "small12.jsonl", chain)
    bounded = _verify(path)
    legacy = _verify(path, extra_env={"RAUCLE_VERIFY_BOUNDS": "off"})
    for field in (
        "valid",
        "receipt_count",
        "signature_failures",
        "parent_link_failures",
        "taint_monotonicity_failures",
        "errors",
    ):
        assert getattr(bounded, field) == getattr(legacy, field), field
    # a tampered copy: identical failure surfacing in both modes
    lines = path.read_text().splitlines()
    bad = json.loads(lines[-1])
    lines[-1] = json.dumps({"receipt_hash": "sha256:" + "0" * 64, "jws": bad["jws"]})
    tampered_path = tmp_path / "tampered12.jsonl"
    tampered_path.write_text("\n".join(lines) + "\n")
    bounded_t = _verify(tampered_path)
    legacy_t = _verify(tampered_path, extra_env={"RAUCLE_VERIFY_BOUNDS": "off"})
    assert bounded_t.valid is False and legacy_t.valid is False
    assert bounded_t.errors == legacy_t.errors


# ---------------------------------------------------------------------------
# (d) cycles refused by name
# ---------------------------------------------------------------------------


def test_cycle_refused_by_name_at_traversal_seam(tmp_path, monkeypatch):
    """Defensive cycle detection at the traversal seam: a crafted map where
    two receipts alias each other's hashes (corrupted data, the house
    receipt_index precedent) is refused by name - the walk terminates with a
    named refusal, never spins."""
    chain = _deep_chain(4)
    forged_a = _mint(Operation.MODEL_CALL, [])
    forged_b = _mint(Operation.MODEL_CALL, [])
    # corrupted map (the house receipt_index precedent): two receipts whose
    # parents alias each other's hashes, i.e. a parent graph that is not
    # acyclic. Content addressing makes this unreachable through the public
    # API; the traversal must still refuse it by name and terminate.
    forged_a.parents = [forged_b.receipt_hash]
    forged_b.parents = [forged_a.receipt_hash]
    crafted = {
        forged_a.receipt_hash: forged_a,
        forged_b.receipt_hash: forged_b,
    }
    monkeypatch.delenv("RAUCLE_VERIFY_BOUNDS", raising=False)
    verifier = ProvenanceVerifier(public_keys=_public_keys())
    report = provenance_mod.VerificationReport(valid=True, receipt_count=0)
    with pytest.raises(provenance_mod.ProvenanceVerifierBoundsExceeded) as excinfo:
        verifier._verify_ancestry_bounds(crafted, report)
    assert excinfo.value.limit == "cycle"

    # and through the public API the same detector stays silent: honest
    # content-addressed bundles can never present a cycle to the walk.
    path = _write_chain(tmp_path, "honest4.jsonl", chain)
    public_report = _verify(path)
    assert public_report.valid is True
    assert not _refusal_errors(public_report)


def test_bounds_refusal_class_is_a_named_value_error():
    """The refusal class follows the house named-refusal contract: a
    ValueError subclass carrying limit/observed/cap, message naming itself."""
    exc = provenance_mod.ProvenanceVerifierBoundsExceeded(
        "graph_depth", 257, 256, "receipt ancestry depth exceeded"
    )
    assert isinstance(exc, ValueError)
    assert exc.limit == "graph_depth"
    assert exc.observed == 257
    assert exc.cap == 256
    assert "ProvenanceVerifierBoundsExceeded" in str(exc)


# ---------------------------------------------------------------------------
# (e) bounds-disabled env restores legacy; default ON
# ---------------------------------------------------------------------------


def test_bounds_disabled_env_restores_legacy_and_default_is_on(tmp_path, monkeypatch):
    """Documented migration window: RAUCLE_VERIFY_BOUNDS=off restores the
    legacy unbounded verifier (deep chains verify as today); the default is
    bounds ON - the fail-closed posture is a deliberate, stated choice."""
    chain = _deep_chain(300)
    path = _write_chain(tmp_path, "deep300.jsonl", chain)

    monkeypatch.delenv("RAUCLE_VERIFY_BOUNDS", raising=False)
    bounded = _verify(path)
    assert bounded.valid is False
    assert _refusal_errors(bounded), "bounds must be ON by default (fail-closed)"

    legacy = _verify(path, extra_env={"RAUCLE_VERIFY_BOUNDS": "off"})
    assert legacy.valid is True, "bounds-off must restore the legacy verdict"
    assert not _refusal_errors(legacy)
    assert legacy.traversal_receipts_expanded == 0
    assert legacy.traversal_edges_examined == 0


def test_bounds_env_overrides_and_fail_closed_garbage(tmp_path, monkeypatch):
    """Per-bound env overrides are honoured; a garbage override refuses
    loudly (fail-closed: an ambiguous opt-out does not exist)."""
    chain = _deep_chain(10)
    path = _write_chain(tmp_path, "deep10.jsonl", chain)

    # depth override honoured: the same 10-deep chain passes under a raised cap
    monkeypatch.setenv("RAUCLE_VERIFY_MAX_DEPTH", "64")
    assert _verify(path).valid is True

    # ...and refuses under a lower one, naming the observed value
    monkeypatch.setenv("RAUCLE_VERIFY_MAX_DEPTH", "5")
    report = _verify(path)
    text = _refusal_errors(report)[0]
    assert "graph_depth" in text and "observed=6" in text

    # nodes override: a 4-receipt bundle refuses at the node budget
    monkeypatch.delenv("RAUCLE_VERIFY_MAX_DEPTH", raising=False)
    monkeypatch.setenv("RAUCLE_VERIFY_MAX_NODES", "3")
    bundle = _deep_chain(3)
    nodes_path = _write_chain(
        tmp_path, "four.jsonl", bundle + [_mint(Operation.MODEL_CALL, [bundle[-1].receipt_hash])]
    )
    report = _verify(nodes_path)
    text = _refusal_errors(report)[0]
    assert "node_count" in text and "observed=4" in text

    # bundle bytes override: the byte bound binds when lowered below the chain
    monkeypatch.delenv("RAUCLE_VERIFY_MAX_NODES", raising=False)
    monkeypatch.setenv("RAUCLE_VERIFY_MAX_BUNDLE_BYTES", "1000")
    report = _verify(path)
    text = _refusal_errors(report)[0]
    assert "bundle_bytes" in text

    # garbage override: refuse to construct, naming the env var
    monkeypatch.delenv("RAUCLE_VERIFY_MAX_BUNDLE_BYTES", raising=False)
    monkeypatch.setenv("RAUCLE_VERIFY_MAX_DEPTH", "not-a-number")
    with pytest.raises(ValueError) as excinfo:
        ProvenanceVerifier(public_keys=_public_keys())
    assert "RAUCLE_VERIFY_MAX_DEPTH" in str(excinfo.value)

    # garbage mode value: an ambiguous opt-out does not exist
    monkeypatch.delenv("RAUCLE_VERIFY_MAX_DEPTH", raising=False)
    monkeypatch.setenv("RAUCLE_VERIFY_BOUNDS", "maybe")
    with pytest.raises(ValueError) as excinfo:
        ProvenanceVerifier(public_keys=_public_keys())
    assert "RAUCLE_VERIFY_BOUNDS" in str(excinfo.value)


# ---------------------------------------------------------------------------
# (f) real receipts from the existing suite corpus verify unchanged
# ---------------------------------------------------------------------------


def test_demo_bundle_corpus_verifies_unchanged_under_bounds(monkeypatch):
    """The existing demo-bundle corpus chain (real signed receipts) verifies
    with the bounds ON exactly as without them: field-for-field parity."""
    import base64

    pubkey_pem = DEMO_BUNDLE_PUBKEY.read_bytes()
    first = json.loads(DEMO_BUNDLE_CHAIN.read_text().splitlines()[0])
    seg = first["jws"].split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(seg + "=" * ((4 - len(seg) % 4) % 4)))
    kid = payload["agent_key_id"]

    # Checker D1 (24 Nov): the two legs must be built from DIFFERENT envs -
    # the bounded leg runs with bounds on (env cleared), the legacy leg with
    # RAUCLE_VERIFY_BOUNDS=off, so the parity claim actually compares the two
    # traversal regimes instead of two identical bounds-on runs.
    monkeypatch.setenv("RAUCLE_VERIFY_BOUNDS", "on")
    bounded = ProvenanceVerifier(public_keys={kid: pubkey_pem}).verify_chain(DEMO_BUNDLE_CHAIN)
    monkeypatch.setenv("RAUCLE_VERIFY_BOUNDS", "off")
    legacy = ProvenanceVerifier(public_keys={kid: pubkey_pem}).verify_chain(DEMO_BUNDLE_CHAIN)
    # sanity: the corpus is genuinely valid under BOTH regimes (not parity on two refusals)
    assert bounded.valid is True and bounded.receipt_count == 3
    assert legacy.valid is True and legacy.receipt_count == 3
    assert bounded.errors == legacy.errors
    assert bounded.to_dict() == legacy.to_dict()


def test_rich_suite_style_chain_parity_and_report_body_shape(tmp_path, monkeypatch):
    """A suite-style chain using the shipped receipt surface (handoff,
    sanitisation, tenant, merge) verifies unchanged with bounds ON, and the
    report body shape stays byte-stable (no new keys, pack reproducibility)."""
    root = _mint(Operation.USER_INPUT, [], taint=("external_user",))
    h = root.receipt_hash
    model = _mint(Operation.MODEL_CALL, [h])
    h = model.receipt_hash
    tool = _mint(
        Operation.TOOL_CALL,
        [h],
        taint=("external_user", "rag:corpus-a"),
        tool="tool-a",
    )
    handoff = _mint(
        Operation.AGENT_HANDOFF,
        [tool.receipt_hash],
        taint=("external_user", "rag:corpus-a"),
    )
    sanitised = _mint(
        Operation.SANITISATION,
        sorted([tool.receipt_hash, handoff.receipt_hash]),
        taint=("external_user",),
        corpus="removed:rag:corpus-a",
        tool="sanitiser-a",
    )
    merge = _mint(
        Operation.MERGE,
        sorted([handoff.receipt_hash, sanitised.receipt_hash]),
        taint=("external_user", "rag:corpus-a"),
    )
    chain = [root, model, tool, handoff, sanitised, merge]
    path = _write_chain(tmp_path, "rich.jsonl", chain)

    monkeypatch.delenv("RAUCLE_VERIFY_BOUNDS", raising=False)
    bounded = _verify(path)
    legacy = _verify(path, extra_env={"RAUCLE_VERIFY_BOUNDS": "off"})
    assert bounded.valid is True and legacy.valid is True
    assert bounded.to_dict() == legacy.to_dict()
    # the Q19 counters ride the report object as diagnostics only: the report
    # body (to_dict) stays byte-stable for the v1.0 report shape consumers.
    assert bounded.traversal_edges_examined > 0
    assert "traversal_edges_examined" not in bounded.to_dict()
    assert set(bounded.to_dict()) == set(legacy.to_dict())
