# ADR 0008: Replay state, execution idempotency and receipt-ingress boundaries

- **Status:** Proposed
- **Date:** 2026-11-26
- **Owners:** Raucle engineering
- **Parent programme:** [Enterprise Readiness Programme #106](https://github.com/epic28-ltd/raucle-agent-assurance/issues/106)
- **Implementation tracking:** [Raucle issue #340](https://github.com/epic28-ltd/raucle/issues/340)

## Context

The enterprise-readiness proposal asks for a distributed nonce/state store and describes a
`pending → consumed | failed` state machine intended to prevent duplicate execution across
multiple Raucle instances. The current code has several distinct state surfaces. They must
not be conflated:

1. **Cross-organisation handshake replay protection.** `raucle/replay_store.py` defines
   `ReplayStore.consume(replay_key)`; `SqliteReplayStore` uses a primary-key uniqueness
   constraint and an atomic `BEGIN IMMEDIATE` insert. `raucle/handshake.py:accept_call`
   requires this store and consumes `key_id:token_id:nonce` before making the decision.
   Tests cover mandatory injection, missing nonce rejection, restart persistence and
   concurrent threads.
2. **Receipt sidecar request authentication.** The X3 sidecar authenticates `POST /submit`
   using HMAC-SHA256 over a fresh `X-Raucle-Nonce` and the exact request body. The nonce is
   not persisted or replay-checked. The sidecar specification explicitly records captured
   request replay as a residual risk. A replay can append a duplicate envelope; it does not
   re-run a tool.
3. **Receipt-chain sequencing.** The receipt sidecar is deliberately one writer per chain.
   It serialises append order and owns the SQLite index. Gateway replicas may scale behind
   it, but the sidecar itself is pinned to one replica.
4. **Downstream tool execution.** The gateway authorises tool calls; it does not execute
   arbitrary external side effects. A consumed nonce at the gate does not prove that a
   downstream tool executed once, or at all.

The deployment-topology documentation states that the default SQLite/JSONL stack is
same-host only and does not support multi-host writes. It identifies PostgreSQL as the
multi-host trigger for Raucle Cloud deployments.

## Decision

### 1. Keep the state machines separate

Do not introduce one generic "distributed nonce store" that silently conflates:

- a handshake request that must be accepted at most once;
- an authenticated receipt append that must not be replayed;
- an external tool operation whose side effect may need idempotency.

Each operation has a different key scope, retention rule, retry contract and failure mode.
They may share a database service, but must have separate tables/namespaces and explicit
APIs.

### 2. Preserve SQLite for the existing single-host handshake mode

The current `SqliteReplayStore` is a valid single-host persistent atomic implementation.
Keep its default retain-forever behaviour and existing API compatibility. Do not place its
WAL database on NFS or claim it coordinates active-active hosts.

The existing consume-before-decision rule is safety-first: if the process crashes after
consuming a nonce but before returning an acknowledgement, the request is not reprocessed.
That can lose an operation's opportunity to complete, but it prevents a retry from being
accepted as a second attempt. Document this as at-most-once handling, not exactly-once
execution.

### 3. Prefer a PostgreSQL-backed atomic claim for the first multi-host handshake backend

For the first supported multi-host topology, evaluate PostgreSQL as the shared authority,
consistent with the deployment-topology documentation. The core operation should be a
single insert protected by a unique constraint, scoped by deployment/tenant and the
protocol's key/token/nonce identity. Use database transactions and the database clock;
do not implement check-then-insert in application code.

A Redis `SET NX` implementation is not selected as the first authoritative backend:
asynchronous replication and failover can lose an acknowledged claim unless the deployment
accepts and proves a specific durability/consistency configuration. NATS JetStream message
deduplication is not equivalent to indefinite replay retention; its duplicate window and
consumer semantics must be accounted for explicitly.

PostgreSQL is not a magic multi-region consensus layer. The first supported topology should
be a single authoritative writer/primary with documented HA/failover behaviour. Active-active
multi-region acceptance requires a strongly consistent database/consensus design and
dedicated failover tests; it is not implied by using PostgreSQL.

This ADR records a preferred evaluation direction, not a shipped backend or an availability
guarantee. The implementation issue must validate driver/dependency policy, deployment
operations, backup/restore and failure semantics before selecting the production interface.

### 4. Specify retention and ambiguous outcomes explicitly

- Replay-key retention must be at least the maximum lifetime of any token/request that can
  still be presented, plus documented clock-skew and retry allowance.
- Retain forever unless a bounded retention period is configured and justified by token
  expiry policy.
- An insert timeout or lost connection during commit is an **unknown outcome**. The caller
  must not assume the claim failed and blindly retry the side effect. It must query by the
  same idempotency key or return a named indeterminate result.
- Store unavailability, partition, failed health checks or an unresolvable commit outcome
  must fail closed for operations whose replay protection is mandatory.
- Expiry cleanup must not race with acceptance of a still-valid token.

### 5. Add replay protection to receipt-sidecar ingestion as a separate change

The sidecar HMAC nonce should become a persisted, bounded-lifetime request identifier, with
the exact request-body digest bound to it. A duplicate nonce with the same body should return
the prior accepted result without appending again; the same nonce with a different body must
be refused. The nonce must be consumed atomically before enqueue/append, and the protocol
must define what happens if the process crashes after claim but before append.

The sidecar remains one writer per chain. Replay protection does not make the receipt chain
multi-writer or make sidecar HA safe. A future standby/failover design needs explicit writer
fencing so two sidecars cannot both append to the same chain.

### 6. Do not promise exactly-once external tool effects from a gate nonce

For a tool operation with an external side effect, a gate cannot atomically commit both its
own state and an arbitrary downstream system's state. A crash can occur after the downstream
effect but before the acknowledgement/receipt is observed.

If exactly-once *effect* is required, the executor and target system must participate through
a stable idempotency key and a query/reconciliation contract, or through a transaction
protocol supported by the target. Otherwise document the honest guarantee (for example,
at-most-once gate acceptance or at-least-once delivery with target idempotency), not
"exactly once".

A future execution broker may use `pending`, leases and fencing tokens, but it must define
lease expiry, stale-worker rejection and downstream idempotency before claiming that a
`pending → consumed | failed` state machine prevents duplicate effects.

## Consequences

### Positive
- Preserves the already-tested SQLite single-host behaviour.
- Prevents receipt ingestion replay from being confused with tool execution replay.
- Gives multi-host handshake work a concrete database primitive to validate.
- Makes ambiguous commit, failover and retention semantics explicit.
- Avoids claiming active-active multi-region or exactly-once tool execution prematurely.

### Costs and residual risks
- PostgreSQL introduces an operational dependency and requires migration, connection-pool,
  credential, backup/restore and HA work.
- A single-primary topology has a regional availability boundary.
- Sidecar duplicate-submit handling requires durable idempotency records and a crash-recovery
  contract.
- Arbitrary downstream tool effects remain outside Raucle's atomic transaction boundary
  unless the executor and target cooperate.

## Required validation before implementation is declared complete

- Concurrent same-key claims from independent processes: exactly one succeeds.
- Distinct keys remain independent under concurrency.
- Restart persistence and retention boundary tests.
- Primary failover during claim, including lost response after commit.
- Database timeout/partition/unavailable tests prove fail-closed behaviour.
- Sidecar same-nonce/same-body retry does not append twice.
- Sidecar same-nonce/different-body request is refused.
- Sidecar crash after nonce claim but before append recovers without silently losing or
  duplicating the accepted request.
- No test or documentation equates a gate decision with successful downstream execution.

## References

- `raucle/replay_store.py` and `tests/test_handshake.py`
- `raucle/handshake.py`
- `raucle/sidecar.py` and `docs/spec/x3-sidecar-v0.1.md`
- `docs/deployment-topologies.md`
- [Enterprise-readiness implementation issue #340](https://github.com/epic28-ltd/raucle/issues/340)
