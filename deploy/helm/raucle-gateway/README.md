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

Policies mount as a ConfigMap (edit `policies` in values). Keys, receipts,
index and registry live on the PVC under `/data`. See
`docs/getting-started/20-production-hardening.md` for the rest of the
checklist.
