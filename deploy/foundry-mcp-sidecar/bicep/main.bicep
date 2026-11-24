// raucle sidecar — Bicep template for Azure AI Foundry MCP gateway integration.
//
// PROPOSED INTEGRATION state (M2-class artefact; see README "Status"):
// the Container App provisioned here runs the SHIPPED entry point
// (`raucle serve`, the detection REST server). The receipt-emitting
// Foundry MCP forwarder and its issuer-key/audit-blob wiring are
// marked PROPOSED (commented) pending the registered proxy
// integration, and the managed identity + role assignments below back
// that proposed state.
//
// Provisions the Container App inside the same VNet as the customer's
// Foundry-attached APIM instance, plus an APIM Backend pool member
// pointing at it and the Named Values the policy XML expects. Run via:
//
//   az deployment group create \
//     -g <resource-group> \
//     -f deploy/foundry-mcp-sidecar/bicep/main.bicep \
//     -p @deploy/foundry-mcp-sidecar/bicep/parameters.example.json
//
// Companion docs:
//   - deploy/foundry-mcp-sidecar/README.md   (customer walkthrough)
//   - deploy/foundry-mcp-sidecar/apim-policy.xml
//   - docs/proposals/foundry-mcp-gateway.md  (design rationale)

@description('Azure region for the sidecar resources. Should match the region of the existing APIM instance.')
param location string = resourceGroup().location

@description('Container App Environment resource ID (existing). The sidecar deploys into this environment so it shares the APIM VNet.')
param containerAppEnvironmentId string

@description('Existing APIM service name (Foundry-attached).')
param apimServiceName string

@description('URL of the customer\'s existing MCP server. The sidecar forwards admitted calls here.')
param mcpBackendUrl string

@description('Existing Key Vault resource ID holding the raucle issuer Ed25519 private key.')
param keyVaultId string

@description('Key Vault secret name for the issuer private key PEM.')
param issuerKeySecretName string = 'raucle-issuer-private-key'

@description('Existing Storage Account resource ID for the audit log container.')
param auditStorageAccountId string

@description('Blob container name for the hash-chained audit log.')
param auditContainerName string = 'raucle-audit'

@description('raucle container image. Default pins the current release tag; see the pin comment below for the digest capture and provenance discipline.')
param raucleImage string = 'ghcr.io/epic28-ltd/raucle:v0.23.8'
// IMAGE PIN DISCIPLINE (Q21, per the Q9 digest-pinning convention):
//   - The default above pins the CURRENT release tag. The previous
//     default (ghcr.io/epic28-ltd/raucle:v0.12.0) was an antique mutable
//     tag and is deliberately gone.
//   - Provenance: release tag v0.23.8 resolves to source commit
//     27fce30497ad07e6605558c2566ccd0da1b9c658 (verified at pin time,
//     24 Nov 2026, against the PEP 740 provenance attestation of the
//     raucle 0.23.8 PyPI release: the Sigstore publishing certificate
//     of https://pypi.org/integrity/raucle/0.23.8/raucle-0.23.8.tar.gz/provenance
//     binds the tag push of publish.yml to that commit; the git tag
//     points at the same commit).
//   - Digest: pin the immutable digest IN ADDITION to the tag (Q9
//     convention, Dockerfile.gateway / docker-compose.gateway.yml
//     style) once the image is present in a registry this deployment
//     can pull from, i.e. change the default to
//     '<registry>/raucle:v0.23.8@sha256:<digest>' recorded via:
//       docker buildx imagetools inspect <registry>/raucle:v0.23.8
//   - Honest caveats at pin time: this repository's own pipelines
//     publish to PyPI only (publish.yml) - no workflow publishes a
//     container image - and ghcr.io/epic28-ltd/raucle did not resolve
//     for anonymous pulls when this template was updated, so no digest
//     is recorded here. Build the image from the pinned source commit
//     (Dockerfile.gateway: docker build -f Dockerfile.gateway .) and
//     push it to YOUR registry, then set this parameter (template is
//     deployable as-is against your registry) and record the digest
//     captured with the command above.

@description('Issuer string (e.g. "acme.bank.kyc-platform"). Embedded in every emitted receipt.')
param issuerId string

@description('Base URL the deploying organisation publishes its issuer pubkey + policy registry at. Used by external verifiers.')
param verificationBaseUrl string

// ---------------------------------------------------------------------------
// User-assigned managed identity — used by the sidecar to read the Key
// Vault secret and write to the audit storage container.

resource sidecarIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: 'raucle-sidecar-identity'
  location: location
}

// Grant the identity Key Vault secret-read access (for the issuer key)
// and Storage Blob Data Contributor on the audit container.
resource kvAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVaultId, sidecarIdentity.id, 'kv-secrets-user')
  scope: resourceGroup()  // refined to the KV scope by the customer if needed
  properties: {
    // "Key Vault Secrets User" role definition id (Azure built-in)
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '4633458b-17de-408a-b874-0445c86b69e6'
    )
    principalId: sidecarIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource blobAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(auditStorageAccountId, sidecarIdentity.id, 'blob-contributor')
  scope: resourceGroup()
  properties: {
    // "Storage Blob Data Contributor" role definition id
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
    )
    principalId: sidecarIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// The sidecar Container App itself.

resource sidecar 'Microsoft.App/containerApps@2025-01-01' = {
  name: 'raucle-sidecar'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${sidecarIdentity.id}': {}
    }
  }
  properties: {
    environmentId: containerAppEnvironmentId
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: false   // VNet-internal — APIM is the only entry point.
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
      secrets: [
        // PROPOSED (unshipped forwarder): the issuer-key secret backs the
        // receipt-signing forwarder (RAUCLE_ISSUER_KEY_PEM in the proposed
        // env block above). The shipped detection server reads no secret,
        // so the shipped container config carries none. Re-enable the
        // entry below together with the proposed env block.
        // {
        //   name: 'issuer-key-pem'
        //   keyVaultUrl: '${reference(keyVaultId, '2024-11-01').vaultUri}secrets/${issuerKeySecretName}'
        //   identity: sidecarIdentity.id
        // }
      ]
    }
    template: {
      containers: [
        {
          name: 'raucle'
          image: raucleImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          // The SHIPPED entry point: `raucle serve` flags are
          // --host / --port / --mode with choices strict|standard|
          // permissive (raucle/cli.py). The proposed forwarder command
          // (--mode foundry-sidecar) is an unshipped executable and is
          // deliberately NOT presented here: this template deploys the
          // detection REST server today (proposed-state labelling per
          // README "Status").
          command: [
            'raucle'
            'serve'
            '--host'
            '0.0.0.0'   // bind the ingress-facing interface, not 127.0.0.1
            '--port'
            '8080'
            '--mode'
            'standard'
          ]
          env: [
            // Shipped detection server: no extra environment required.
            //
            // PROPOSED (unshipped forwarder — do not enable until the
            // registered proxy integration lands; see README "Status"):
            //   { name: 'RAUCLE_BACKEND_URL', value: mcpBackendUrl }
            //   { name: 'RAUCLE_ISSUER_ID', value: issuerId }
            //   { name: 'RAUCLE_ISSUER_KEY_PEM', secretRef: 'issuer-key-pem' }
            //   { name: 'RAUCLE_AUDIT_BLOB_ACCOUNT', value: split(auditStorageAccountId, '/')[8] }
            //   { name: 'RAUCLE_AUDIT_BLOB_CONTAINER', value: auditContainerName }
            //   { name: 'RAUCLE_VERIFICATION_BASE_URL', value: verificationBaseUrl }
            //   { name: 'AZURE_CLIENT_ID', value: sidecarIdentity.properties.clientId }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: { path: '/health', port: 8080 }  // GET /health is the shipped liveness route
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: { path: '/health', port: 8080 }  // single public health route ships today; readiness and liveness share it
              initialDelaySeconds: 3
              periodSeconds: 5
            }
          ]
        }
      ]
      scale: {
        minReplicas: 2  // capacity headroom; the sub-100µs gate-latency target belongs to the proposed forwarder
        maxReplicas: 20
        rules: [
          {
            name: 'http-scale'
            http: { metadata: { concurrentRequests: '50' } }
          }
        ]
      }
    }
  }
}

// ---------------------------------------------------------------------------
// APIM Backend pool member pointing at the sidecar's internal FQDN.

resource apimBackend 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  name: '${apimServiceName}/raucle-sidecar'
  properties: {
    description: 'raucle sidecar — gates every Foundry MCP tool call'
    url: 'https://${sidecar.properties.configuration.ingress.fqdn}'
    protocol: 'http'
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
  }
}

// ---------------------------------------------------------------------------
// APIM Named Values that the policy XML expects.

resource nvSidecarFqdn 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  name: '${apimServiceName}/raucle-sidecar-fqdn'
  properties: {
    displayName: 'raucle-sidecar-fqdn'
    value: sidecar.properties.configuration.ingress.fqdn
    secret: false
  }
}

resource nvMcpPath 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  name: '${apimServiceName}/raucle-mcp-path'
  properties: {
    displayName: 'raucle-mcp-path'
    value: '/mcp'
    secret: false
  }
}

resource nvMcpBackendHost 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  name: '${apimServiceName}/raucle-mcp-backend-host'
  properties: {
    displayName: 'raucle-mcp-backend-host'
    // The MCP server's own hostname, derived from mcpBackendUrl. The
    // policy's direct-route guard denies requests whose Host header
    // names this host (see apim-policy.xml block 5).
    value: split(mcpBackendUrl, '/')[2]
    secret: false
  }
}

// ---------------------------------------------------------------------------
// Outputs

output sidecarFqdn string = sidecar.properties.configuration.ingress.fqdn
output sidecarIdentityClientId string = sidecarIdentity.properties.clientId
output apimBackendId string = apimBackend.id
