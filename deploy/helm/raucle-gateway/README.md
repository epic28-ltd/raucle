# raucle-gateway chart

Installs the raucle gateway (policy gate, signed receipts, trust registry,
admin panel) with persistent chain storage.

```bash
helm install rg deploy/helm/raucle-gateway \
  --set config.adminKey=change-me \
  --set config.gateAuth=apikey
```

Hard requirements the chart enforces:

- `config.adminKey` is REQUIRED (the template fails without it).
- Without `sidecar.enabled`, `replicaCount` stays 1: one writer per
  chain is the tamper-evidence contract
  (see `docs/deployment-topologies.md`).
- With `sidecar.enabled=true` the constraint MOVES, it does not vanish:
  gateway replicas may scale (they submit minted receipts to the
  sidecar and mount the data volume read-only), and the sidecar
  Deployment is pinned to one replica with a Recreate strategy: it is
  THE single writer of the chain and the index. Never scale it.

X3 slice 4 values (spec: `docs/spec/x3-sidecar-v0.1.md`):

| Value | Meaning |
| --- | --- |
| `sidecar.enabled` | run the single-writer receipt sidecar Deployment + Service |
| `sidecar.secret` | REQUIRED when enabled; `RAUCLE_RECEIPT_SIDECAR_SECRET` on both processes, never argv |
| `sidecar.port` | sidecar listen port inside the cluster (default 8092, ClusterIP only, never the ingress) |
| `sidecar.maxQueue` | bound on the submit queue; overflow is a named refusal the gateway receipts as an advisory |
| `sidecar.receiptStoreDir` / `sidecar.receiptIndexPath` | the store the sidecar owns (gateways get the URL, not the paths) |
| `sidecar.receiptSegmentMaxBytes` | segment rollover threshold in bytes; reaches the sidecar as `--max-segment-bytes` |
| `sidecar.indexCacheMb` | SQLite page cache cap for the receipt index; reaches the sidecar as `--index-cache-mb` (`RAUCLE_INDEX_CACHE_MB` is the gateway's own knob) |
| `sidecar.replicaCount` | pinned at 1; the single-writer honest note above |

Honest notes for the sidecar mode:

- The sidecar service is reachable with a shared secret, not a
  capability: keep it ClusterIP-only, never behind the public ingress.
- The PVC is ReadWriteOnce, so with persistence enabled the sidecar
  and the gateway replicas must share one node unless you switch the
  claim to ReadWriteMany.
- In sidecar mode the gateways run without a local index, so their
  receipt query surfaces answer as any no-index deployment does; the
  chain and the index live on the sidecar's volume.
- The gateways mount `/data` read-only in this mode, so the signing key
  has its own writable volume (mounted at `/keys`, claim
  `<fullname>-signer-key` with persistence, an emptyDir otherwise; the
  chart points `RAUCLE_SIGNER_KEY_PATH` there). Replicas share the key
  volume: the first replica creates the key, the rest adopt it, so the
  deployment mints under one gate identity. An unwritable key path is a
  named boot refusal (`signer_key_unwritable`) that asks for a restart.

Policies mount as a ConfigMap (edit `policies` in values). Without the
sidecar, keys, receipts, index and registry live on the PVC under
`/data`. In sidecar mode the gateways mount `/data` read-only (the
sidecar owns the store and the index) and the signing key lives on its
own writable volume (see the notes above). See
`docs/getting-started/20-production-hardening.md` for the rest of the
checklist.
