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
- `replicaCount` stays 1: one writer per chain is the tamper-evidence
  contract (see `docs/deployment-topologies.md`).

Policies mount as a ConfigMap (edit `policies` in values). Keys, receipts,
index and registry live on the PVC under `/data`. See
`docs/getting-started/20-production-hardening.md` for the rest of the
checklist.
