# 20. Production hardening

**Time: 90 min · Pre-req: the gateway running (compose or bare).**

By the end you will have a deployment that passes the CTO checks: agents
authenticated, receipts signed and restart-safe, queries working, evidence
exportable.

## Step 1: pick an auth mode (5 min)

```bash
# off: trusted internal networks ONLY (declared identity, boot-log warning)
# apikey: per-agent keys (quick start)
# token: capability tokens verified against the trust registry (deployment-grade)
export RAUCLE_GATE_AUTH=apikey

# Issue per-agent keys (shown once, stored hashed):
raucle agents issue-key --agent-id agent:pay --store /data/agent-credentials.jsonl
raucle agents revoke-key --agent-id agent:pay --store /data/agent-credentials.jsonl
```

Agents send `X-Api-Key: rak_...` (apikey) or `X-Capability-Token: {...}`
(token mode). Auth failures return a **receipted DENY**, not a bare 401 -
an unauthenticated attempt is itself evidence.

## Step 2: turn on segmented receipts + index (5 min)

```bash
export RAUCLE_RECEIPT_STORE_DIR=/data/receipts-segments
export RAUCLE_RECEIPT_SEGMENT_MAX_BYTES=67108864   # 64 MiB, default
```

Every `/gate` decision now emits a signed receipt; the SQLite index builds
beside the segments. `receipt_id` in each response is the receipt's content
hash.

## Step 3: the restart test (5 min)

```bash
docker compose restart raucle-gateway
# boot log: "loaded gateway signing key ... (key_id=<same id>)"
curl -s http://localhost:8090/health
```

The signing key persists; tokens and receipts verify across restarts. A
corrupt key file fails closed instead of silently regenerating.

## Step 4: verify evidence offline (10 min)

```bash
# a receipt from the store verifies with the standard verifier
raucle provenance verify /data/receipts-segments/seg-000000.jsonl \
    --pubkeys /data/gateway-signing-pub.pem --require-pq   # when PQ is on

# or hand the whole segment to the audit pack builder (offline-verifiable
# regulator bundle):
raucle audit-pack build /data/receipts-segments/seg-000000.jsonl \
    --pubkeys /data/gateway-signing-pub.pem \
    --sign-key /data/audit-key.pem --out /tmp/pack
raucle audit-pack verify /tmp/pack
```

## Step 5: query and walk ancestry (10 min)

```bash
AK=<admin key>
# filter by agent, tool, decision, trace, time
curl -s "http://localhost:8091/api/receipts?agent_id=agent:pay&decision=deny" \
    -H "Authorization: $AK"

# the incident question: everything upstream of one decision
curl -s "http://localhost:8091/api/receipts/<receipt-hash>/ancestors" \
    -H "Authorization: $AK"

# your own copy in your data platform
curl -s "http://localhost:8091/api/receipts/export?since=<epoch>" \
    -H "Authorization: $AK" > receipts.jsonl
```

The panel's Receipts tab does all of this visually (filter bar, ancestry
drill-down, export).

## Step 6: the security checklist (15 min)

- [ ] `RAUCLE_GATE_AUTH` is not `off` for anything internet-adjacent
- [ ] TLS at the edge (Caddy config: `{$DOMAIN}` from the environment)
- [ ] `RAUCLE_HEALTH_KEY` set (unauthenticated probes reveal nothing)
- [ ] Admin keys in `users.jsonl` (persisted), MFA on the admin account
- [ ] Signing-key PEM backed up offline (escrow: two copies, two locations)
- [ ] Retention decided (segment age policy) before the first audit
- [ ] SIEM forwarding on (`RAUCLE_SIEM_*`) if you have a SOC

## Step 7: know your runbooks (10 min)

- Key rotation (procedure maps to `tests/test_key_rotation_e2e.py`):
  `docs/security/key-operations.md`
- Single node / standby / sharding: `docs/deployment-topologies.md`
- Auth modes, receipts, the trust boundary:
  `docs/gateway-security.md`

## What you have at the end

A deployment where the gate authenticates agents, every decision is signed
and restart-safe, receipts query fast and walk causally, regulators get
offline-verifiable packs, and your data platform gets its own stream - with
the chain of record staying yours the whole time.