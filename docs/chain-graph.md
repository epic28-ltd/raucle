# Chain reconstruction graph (P1.1a)

`raucle/chain_graph.py` resolves the **complete authority graph** for one
action receipt: the originating authority, every delegation hop
(parent-receipt-hash links and capability-token `parent_id` chains),
the policy version in force at decision time, and any lease/revocation
events the chain carries inline.

Entry points:

- `resolve_chain_graph(receipt_hash, records, ...) -> graph` — pure
  resolver over a receipt-corpus snapshot.
- `resolve_chain_graph_for_gateway(gateway, receipt_hash)` — same
  resolution against a live gateway's configured receipt store, audit
  chain and delegation ledger.
- `GET /api/chains/{receipt_hash}` (admin app) — read-only HTTP surface,
  auth-respecting (receipts role), 404 for unknown hashes, work bounded
  server-side (`depth` ≤ 20, `breadth` ≤ 1000).

## Schema

```jsonc
{
  "root": "<receipt_hash>",                    // or {"state": "unknown"} shape under "nodes"
  "nodes": [
    {"id", "kind", ...}                        // kinds below
  ],
  "edges": [{"from", "to", "kind", "found"}],  // kinds: parent, delegation,
                                               // delegation_parent, policy_binding, deployment
  "unknown": [{"kind", "reference", "reason"}],  // explicit unresolvable links
  "pruned": [{"kind", "reference", "reason"}],   // cut by depth/breadth cap
  "truncated": false,
  "depth_limit": 5,
  "breadth_limit": 200,
  "derived_only_from_verified_receipt_links": true
}
```

### Node kinds

- `receipt` — a provenance receipt. Carries operation, agent_id, key_id,
  `iat` (the recorded decision time), signature status
  (`verified` / `key_absent` / `invalid` / `malformed`), parents, ruleset
  hash, gate summary, its delegation binding (from `x_gate.authorization`),
  and inline `events` (`lease_grant`, `lease_redeemed`, `revocation`,
  `policy_deploy`) each stamped with the receipt's own `iat` — verification
  at event time, as recorded, never reconstructed.
- `delegation` — one capability-token hop resolved from a delegation-ledger
  record (token id, issuer, parent token id, constraints, expiry).
- `policy` — the policy version in force at decision time:
  `policy_ref`, `rule_id`, `ruleset_hash` (the rule-content digest the
  receipt binds), and a binding state:
  - `deployment_bound` — matched BY DIGEST to phase-5 `policy_deployed`
    chain events (`x_policy_deploy.policy_digest`, or the event's
    `gate_receipt_hash`); the matched events hang off the node as
    `audit_event` nodes with their chain receipt hash and timestamps.
  - `receipt_rule_digest_only` — the receipt binds the rule content
    digest but no deployment event matched.
  - `unbound` — no digest, no ref. Stated, never inferred.
- `audit_event` — a `policy_deployed` hash-chain record bound by digest.

## Trust statement

The graph is derived **ONLY from verified receipt links** — parent
receipt hashes are followed exactly as recorded in the receipts; the
resolver adds no authority of its own.

- A node whose signature cannot be verified is an explicit node state
  (`key_absent`, `invalid`), never a graph failure and never silently
  skipped.
- A reference the corpus cannot resolve lands in `unknown` as
  `not_found`; nothing is inferred across a broken link.
- Anything cut by the depth or breadth cap lands in `pruned` with its
  reason and sets `truncated`.
- `policy_deployed` events bind by DIGEST only — a coincidental name
  match never binds.
- Output is deterministic: nodes/edges/unknown/pruned are sorted, and no
  wall-clock value enters the graph.
