# raucle sidecar for Azure AI Foundry's MCP Gateway

This directory holds the artefacts for deploying raucle as an
APIM-routed component against Azure AI Foundry's MCP gateway: an APIM
policy that routes (and guards) the MCP operation, and a Bicep template
for the sidecar's Container App.

## Status: proposed integration (M2 class)

Read this section first. This is a **PROPOSED integration** of M2 class
under [docs/proposals/foundry-mcp-gateway.md](../../docs/proposals/foundry-mcp-gateway.md)
(the maturity table there maps the APIM policy + customer walkthrough to
M2, the Bicep template to M3, and the recorded end-to-end walkthrough to
M4). Relabelled as such following an external review of these artefacts.

**What exists today (shipped raucle surfaces):**

- The detection REST server: `raucle serve` (ports/routes
  `/scan`, `/scan/batch`, `/scan/output`, `/scan/tool`).
- The capability gateway: `POST /gate`
  (`Dockerfile.gateway` + `docker-compose.gateway.yml`) - it produces
  the signed, content-addressed capability receipts, hash-chained for
  tamper evidence and verifiable offline by any third party holding
  your published issuer public key.
- The detection MCP server: `raucle mcp serve` (stdio).

**What is not shipped (the proposed Foundry MCP forwarder):**

- The `serve --mode foundry-sidecar` executable - that CLI mode does
  not exist (`raucle serve --mode` choices are `strict`, `standard`,
  `permissive`), so no artefact here presents it as a deploy command.
- `RAUCLE_BACKEND_URL` call forwarding with tools/call gating, and
  per-call receipt emission from the sidecar container. These land with
  the registered proxy integration; until then the Bicep template runs
  the shipped detection server and marks the forwarder wiring PROPOSED.

**The honest path today:** point the APIM backend at a gateway
deployment (`POST /gate`) or a detection-server deployment
(`raucle serve`); the no-bypass guarantee comes from the network
rule (see [Deployment acceptance](#deployment-acceptance) below), with
the APIM policy's direct-route guard as defence in depth.

The sidecar exists because [Foundry's own docs](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/governance)
state plainly:

> *"AI gateways don't log tool traces."*

Today the trace is produced by the capability gateway's receipts
(`POST /gate`); extending that receipt trail to a Foundry-attached
APIM deployment is precisely the proposed forwarder.

## Prerequisites

Before deploying, you need:

| | What | Why |
|---|---|---|
| 1 | An existing Foundry-attached APIM instance | The sidecar sits behind APIM as a backend pool member. |
| 2 | A Container App Environment in the APIM VNet | The sidecar runs as a Container App that the APIM ingress can reach over private networking. |
| 3 | A Key Vault entry with your raucle issuer Ed25519 private key | The PROPOSED forwarder signs receipts with this. Generate with `raucle cap keygen` and store via `az keyvault secret set --vault-name ... --name raucle-issuer-private-key --file issuer.key`. Prepare it now; the shipped detection server reads no secret. |
| 4 | A Storage Account + Blob container for the audit log | The PROPOSED forwarder writes the hash-chained receipt log here. A 1 GB container is more than enough for ~10⁷ receipts. |
| 5 | A public URL where you publish your issuer pubkey + policy registry | External verifiers fetch from this. Typically `https://<your-org>/.well-known/`. |

## Five-step deploy

### 1. Mint and store the issuer key

```bash
# Locally (or in a CI runner with appropriate role assignments):
raucle cap keygen acme.bank.kyc-platform --out issuer
# Produces: issuer.key (private), issuer.pub (public)

# Push the private key to Key Vault:
az keyvault secret set \
  --vault-name kv-acme-foundry \
  --name raucle-issuer-private-key \
  --file issuer.key

# Publish the public key on your .well-known/ endpoint:
cp issuer.pub /var/www/acme.bank/.well-known/raucle-issuer.pub
```

### 2. Provision the sidecar

Copy `bicep/parameters.example.json` to `bicep/parameters.json`, fill in
the resource ids for your environment, then:

```bash
az deployment group create \
  --resource-group rg-acme-foundry \
  --template-file deploy/foundry-mcp-sidecar/bicep/main.bicep \
  --parameters @deploy/foundry-mcp-sidecar/bicep/parameters.json
```

This creates:

- A user-assigned managed identity with Key Vault Secrets User +
  Storage Blob Data Contributor (backs the PROPOSED forwarder).
- A Container App running `raucle serve --host 0.0.0.0 --port 8080
  --mode standard` - the shipped detection REST server. The template is
  deployable as-is; the PROPOSED forwarder wiring it provisions is
  commented in the template (see [Status](#status-proposed-integration-m2-class)).
- An APIM Backend pool member pointing at the sidecar's internal FQDN.
- Three APIM Named Values (`raucle-sidecar-fqdn`, `raucle-mcp-path`,
  `raucle-mcp-backend-host`) the policy XML references.

The deployment takes ~5 minutes. The sidecar starts with 2 replicas
(one warm) as capacity headroom.

### 3. Apply the APIM policy

Apply `apim-policy.xml` to the APIM operation that fronts your MCP
server. In the Azure portal: APIM → APIs → [your MCP API] → All
operations → Policies → paste the XML. Or via CLI:

```bash
az apim api operation policy create \
  --resource-group rg-acme-foundry \
  --service-name apim-acme-foundry \
  --api-id mcp-api \
  --operation-id mcp-invoke \
  --xml-content "$(cat deploy/foundry-mcp-sidecar/apim-policy.xml)"
```

After this step the APIM operation routes to the configured backend
service, and the policy's direct-route guard denies (named 403) any
request whose Host header names the MCP backend host directly.
Enforcement of the no-bypass boundary itself is NOT delivered by this
step alone - it requires the network rule in
[Deployment acceptance](#deployment-acceptance) below.

### Deployment acceptance

Enforcement requires BOTH (a) the sidecar route AND (b) the network
rule; without (b) the boundary is advisory. All three conditions must
hold before calling the deployment enforced:

1. **The sidecar route is live.** Requests through the APIM operation
   route to the configured backend service, and the policy's
   direct-route guard answers a direct-Host attempt with the named 403.
   Verify both paths with the API trace, per the operator verification
   steps in the `apim-policy.xml` comment.
2. **The MCP server's inbound network rules accept only the sidecar's
   egress IP.** This is the primary no-bypass control: with (a) alone,
   direct calls that bypass APIM keep working wherever the network
   permits.
3. **A direct call to the MCP server must fail.** With (1) and (2) in
   place, a direct call to the MCP server that bypasses the APIM route
   must be refused by the network layer. This is the
   deployment-acceptance row the external review recorded for the
   sidecar artefacts; an unenforced boundary must not be signed off.

### 4. Publish your verification material

External verifiers (regulators, auditors, partner organisations) need
to fetch your published material to verify receipts. Publish at the
URLs you configured in `verificationBaseUrl`:

```
https://acme.bank/.well-known/raucle-issuer.pub      # the issuer public key (PEM)
https://acme.bank/.well-known/raucle-policies/       # the policy registry (one file per policy_proof_hash)
https://acme.bank/raucle-proofs/                     # (optional) the Lean 4 development tree
```

The verifier-side walkthrough is in
[raucle.com /demo](https://raucle.com/demo/) — share that link with
your auditors.

### 5. Smoke-test

Today's deployment answers `GET /health` on the sidecar routes (curl
the Container App's internal FQDN) and the `/scan` endpoints from an
authorised caller:

```bash
# Health (the route the Container App probes):
curl -f "https://<sidecar-fqdn>/health"

# A scan through the detection server. If RAUCLE_API_KEY is set on the
# container app, pass Authorization: Bearer <key> on every request:
curl -s -X POST "https://<sidecar-fqdn>/scan/tool" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $RAUCLE_API_KEY" \
  -d '{"tool_name": "db_query", "arguments": {"q": "SELECT 1"}}' | jq .
```

The receipt-into-audit-container smoke test belongs to the PROPOSED
forwarder: once the registered proxy integration lands, trigger an MCP
call from your Foundry agent (any normal interaction will do), then
list and decode the most recent receipt from the audit container -
expect a fully-populated receipt with `decision: "ALLOW"`, the
signature, the `policy_proof_hash`, and the attenuation chain.

```bash
az storage blob list \
  --account-name stacmefoundryaudit \
  --container-name raucle-audit \
  --output table

az storage blob download \
  --account-name stacmefoundryaudit \
  --container-name raucle-audit \
  --name "$(az storage blob list --account-name stacmefoundryaudit \
              --container-name raucle-audit --query '[-1].name' -o tsv)" \
  --file /tmp/latest-receipt.json
cat /tmp/latest-receipt.json | jq .
```

## Operational notes

Notes describing receipt writing, Blob audit durability or per-call
signing below describe the PROPOSED forwarder state; they ship with
the registered proxy integration. Notes about the detection server
apply today.

- **Issuer key rotation.** Generate a new key with
  `raucle cap keygen`, push it to Key Vault under the same
  secret name, and bump the Container App revision. The sidecar
  picks up the new key on the next request. The previous receipts
  remain verifiable indefinitely under the old public key — publish
  rotated public keys alongside their valid-for timestamps.

- **Audit log durability.** The HashChainSink flushes every receipt
  to Blob Storage with a checkpoint every 1000 entries. A pod restart
  loses no more than the configured checkpoint window. For stronger
  guarantees, set `RAUCLE_AUDIT_CHECKPOINT_EVERY=1` (flush every
  receipt) at a small latency cost.

- **APIM cold-start.** APIM adds ~5-10ms on a warm path; the sidecar
  adds ~5ms more for the gate check + receipt emission. Plan for
  ~25-40ms total over a cold gateway (warm: ~15ms).

- **Composability with AGT.** If you also run the Microsoft Agent
  Governance Toolkit, register raucle as a Policy Decision Point via
  the proposed [AGT PDP contract](../../docs/proposals/agt-pdp-contract.md).
  Until that contract lands upstream, the sidecar and AGT compose
  independently: AGT's in-process policy engine runs at the agent
  framework layer; raucle's gate runs at the network/APIM layer.
  Receipts capture both.

## Status

This directory is the **M2-class PROPOSED integration artefact** for
[`docs/proposals/foundry-mcp-gateway.md`](../../docs/proposals/foundry-mcp-gateway.md):
the APIM policy (routing + direct-route guard) and the walkthrough text
are the M2 deliverable, the Bicep template is the proposal's M3 item,
and the recorded end-to-end walkthrough stays an M4 milestone (it lands
in that later wave alongside an opinionated sample MCP server; the demo
redeploy queue owns it, not this directory).

Shipped raucle surfaces today: the detection REST server
(`raucle serve`), the capability gateway (`POST /gate`, receipt
emission) and the detection MCP server (`raucle mcp serve`). The
Foundry MCP forwarder (the `--mode foundry-sidecar` executable,
`RAUCLE_BACKEND_URL` forwarding with tools/call gating) is unshipped
pending the registered proxy integration and is never presented as a
deployable command here. Relabelled following an external review of
these artefacts.

For questions or to discuss a production deployment, email
`oss@raucle.com`.
