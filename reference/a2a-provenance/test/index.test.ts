import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

import {
  RAUCLE_A2A_EXTENSION_URI, raucleAgentCardExtension, raucleCardMetadata,
  emitHandoff, attachToMessage, verifyHandoff, exportPublicKeyB64,
} from "../src/index.js";

const subtle = webcrypto.subtle;
async function keypair() {
  return (await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
}

// Two agents: A (caller/orchestrator) and B (callee/payments).
async function setup() {
  const a = await keypair();
  const issuerPriv = { privateKey: a.privateKey, iss: "https://a-corp.example/raucle", agentId: "agent:a-corp.orchestrator", keyId: "k_a1" };
  const aPubB64 = await exportPublicKeyB64(a.publicKey);
  const callerCard = {
    url: "https://agents.a-corp.example/orch",
    skills: [],
    extensions: [raucleAgentCardExtension()],
    metadata: raucleCardMetadata({ iss: issuerPriv.iss, keyId: issuerPriv.keyId, publicKey: aPubB64 }),
  };
  const calleeCard = {
    url: "https://agents.acme.example/pay",
    skills: [{ id: "transfer" }, { id: "balance" }],
    extensions: [raucleAgentCardExtension()],
    metadata: raucleCardMetadata({ iss: "https://acme.example/raucle", keyId: "k_pay1", publicKey: "irrelevant" }),
  };
  return { issuerPriv, callerCard, calleeCard };
}

test("agent card extension + metadata are well-formed", () => {
  const ext = raucleAgentCardExtension();
  assert.equal(ext.uri, RAUCLE_A2A_EXTENSION_URI);
  const md = raucleCardMetadata({ iss: "https://x/raucle", keyId: "k1", publicKey: "AAAA" }, { transfer: "deadbeef" });
  assert.equal(md[RAUCLE_A2A_EXTENSION_URI].issuer.key_id, "k1");
  assert.equal(md[RAUCLE_A2A_EXTENSION_URI].skill_capabilities!.transfer, "deadbeef");
});

test("emit + attach + verify a valid hand-off", async () => {
  const { issuerPriv, callerCard, calleeCard } = await setup();
  const receipt = await emitHandoff({
    issuer: issuerPriv, skill: "transfer", targetUrl: calleeCard.url,
    input: { amount: 500, to: "acct-1" }, parents: ["root-task-id-".padEnd(64, "0").slice(0, 64)],
  });
  // chain context: provenance requires non-user_input to have a parent; here parents is set.
  const msg = attachToMessage({ messageId: "m1", role: "ROLE_USER", parts: [] }, receipt);
  assert.ok((msg.extensions as string[]).includes(RAUCLE_A2A_EXTENSION_URI));
  const jws = (msg.metadata as any)[RAUCLE_A2A_EXTENSION_URI].receipt;

  const res = await verifyHandoff(jws, callerCard, calleeCard);
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.skill, "transfer");
});

test("rejects a hand-off for a skill the callee does not advertise", async () => {
  const { issuerPriv, callerCard, calleeCard } = await setup();
  const receipt = await emitHandoff({
    issuer: issuerPriv, skill: "delete_everything", targetUrl: calleeCard.url,
    input: {}, parents: ["x".repeat(64)],
  });
  const res = await verifyHandoff(receipt.jws, callerCard, calleeCard);
  assert.equal(res.ok, false);
  assert.match(res.reason!, /not advertised/);
});

test("rejects a hand-off aimed at a different target agent", async () => {
  const { issuerPriv, callerCard, calleeCard } = await setup();
  const receipt = await emitHandoff({
    issuer: issuerPriv, skill: "transfer", targetUrl: "https://evil.example/pay",
    input: {}, parents: ["x".repeat(64)],
  });
  const res = await verifyHandoff(receipt.jws, callerCard, calleeCard);
  assert.equal(res.ok, false);
  assert.match(res.reason!, /!= this agent|target/);
});

test("rejects a receipt signed by the wrong key (forged caller)", async () => {
  const { callerCard, calleeCard } = await setup();
  const evil = await keypair();
  const receipt = await emitHandoff({
    issuer: { privateKey: evil.privateKey, iss: "https://a-corp.example/raucle", agentId: "agent:a-corp.orchestrator", keyId: "k_a1" },
    skill: "transfer", targetUrl: calleeCard.url, input: {}, parents: ["x".repeat(64)],
  });
  // callerCard still advertises agent A's real key, so the forged receipt must fail verification.
  const res = await verifyHandoff(receipt.jws, callerCard, calleeCard);
  assert.equal(res.ok, false);
  assert.match(res.reason!, /verification/);
});

test("enforces a declared per-skill capability hash", async () => {
  const { issuerPriv, callerCard, calleeCard } = await setup();
  // callee now REQUIRES a capability hash for 'transfer'
  (calleeCard.metadata as any)[RAUCLE_A2A_EXTENSION_URI].skill_capabilities = { transfer: "cap-hash-xyz" };
  const receipt = await emitHandoff({
    issuer: issuerPriv, skill: "transfer", targetUrl: calleeCard.url, input: {}, parents: ["x".repeat(64)],
  });
  // receipt does not cite the capability hash → rejected
  const res = await verifyHandoff(receipt.jws, callerCard, calleeCard);
  assert.equal(res.ok, false);
  assert.match(res.reason!, /requires capability/);
});
