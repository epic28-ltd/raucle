# Deployment topologies

Where raucle sits, how it scales, and how availability works without a
consensus protocol. Read with `docs/gateway-security.md` (auth modes,
receipts) and `docs/security/key-operations.md` (keys).

## Where raucle sits

Raucle does not proxy model traffic. Agents keep calling Claude, GPT,
Gemini or your own weights exactly as before. Raucle sits in front of what
agents **do** - the tool calls - not what they think:

```
Claude / GPT / your weights          (unchanged model path)
        |
  [agent framework]  --- in-process handler/middleware (observability)
        |    \
        |     --- or HTTP POST /gate from the tool wrapper (enforcement)
        v
  [raucle gateway]  -> policy -> signed receipt -> segmented chain + index
        |
        v
  [tools: your systems of record]
```

Model routing (multi-provider failover, cost limits) is a separate product
category on the model path (LiteLLM, Portkey, your cloud's router). The two
compose: the router picks the brain, raucle guards the hands.

## The trust boundary, stated plainly

An in-process integration (LangChain handler, Agent Framework middleware)
is observability and correctness, not a security boundary: a control
co-resident with the agent process cannot resist a compromised host.

The boundary is the out-of-process gate plus **credential isolation**:
agents hold capability tokens, never raw tool secrets. Tool execution
verifies the gate's signature before running anything. A compromised agent
ends up holding tokens that can do three specific things until midnight -
and a bypass leaves an action with no corresponding receipt, which the
tamper-evident chain makes provable rather than merely suspected.

```
[agent: tokens only] -> [gate: hardened host] -> [tool layer: holds the
                                               secrets, verifies signatures]
```

## Topology 1: single node (default)

One gateway container, one chain, one index. The honest limits:

- **Write path is single-process by design**: a chain needs one sequencer;
  that is what makes it tamper-evident. Run exactly one gateway instance
  per chain directory.
- SQLite (index) is same-host only (WAL is not NFS-safe); the segments
  directory is plain files, so backup is a copy.
- Sizing: at the demo's measured ~1 ms gate decision, one node handles
  thousands of decisions per second with the signing cost off the hot path.

Suits: pilots, single-namespace deployments, the majority of regulated
department use.

## Topology 2: hot standby (availability)

The chain is the state; the process is replaceable.

- A shared volume holds `/data` (segments, index, keys, registry).
- The standby mounts the volume and runs the same gateway, paused.
- Failover is manual-first (a documented operator action: stop primary,
  start standby, verify with `/health` and `provenance verify`). One
  writer at a time is the invariant; arbitration tooling can later watch
  `/health` and automate the stop-then-start sequence.
- On failback, the same procedure in reverse. Segments make the story
  boring: the standby appends to the next segment, never edits history.

The single-writer rule is not a limitation to apologise for; it is the
tamper-evidence. Distributed consensus (Raft) over receipts would make the
chain depend on cluster state - the opposite of offline-verifiable
evidence.

## Topology 3: namespace sharding (scale-out)

One gateway + chain per agent namespace (or per tenant). A router at the
edge (Caddy/Envoy) sends each agent's traffic to its shard.

- Each shard is independently verifiable: pack, audit, rotate keys.
- The panel/API fans out for cross-shard queries (a documented pattern,
  not yet a shipped feature; the export API serves per-shard today).
- Trigger: when a single namespace's write rate or retention exceeds one
  node, shard it. Do not shard before that - every shard adds operations.

## Edge patterns

- **TLS:** Caddy terminates TLS (the repo Caddyfile; `{$DOMAIN}` from the
  compose environment). Certificates live in the caddy volume and survive
  redeploys.
- **mTLS:** client certificates at the edge (Caddy `client_auth`), mapping
  to per-agent credentials; the gate still enforces tokens.
- **OIDC federation:** enterprises already federate at the edge; a verified
  edge identity can stand in for per-agent keys in the gateway's `apikey`
  mode by mapping through the credential store. The gate's own token mode
  does not need it.
- **Multi-host writes:** not supported on the default SQLite/JSONL stack -
  that is the documented Postgres trigger for Raucle Cloud deployments.

## Retention and legal holds

Segments make retention a file operation: archive or delete segments older
than your policy; hold a segment by copying it. Sealed segments are pure
chains - a copy IS the evidence, and `audit-pack build --chain
seg-000123.jsonl ...` produces the regulator bundle from any of them.
Deleting a segment deletes the receipts - decide retention before the
first GDPR conversation, not during it.