import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

import { createRaucleSession, evaluatePolicy, RauclePolicyDenied, type VercelTool } from "../src/index.js";
import { verify, buildChain, type Receipt } from "../../provenance-ts/dist/index.js";

const subtle = webcrypto.subtle;

async function keypair() {
  return (await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
}

function issuerFrom(priv: webcrypto.CryptoKey) {
  return { privateKey: priv, iss: "https://acme.example/raucle", agentId: "agent:acme.web", keyId: "k_web1" };
}

// A mock Vercel AI SDK tool: { description, parameters, execute }.
function transferTool(): VercelTool {
  return {
    description: "Transfer funds",
    parameters: {},
    execute: async (args: { amount: number; to: string }) => ({ ok: true, ...args }),
  };
}

test("evaluatePolicy enforces the constraint kinds", () => {
  const p = { maxValue: { amount: 1000 }, allowedValues: { to: ["acct-1", "acct-2"] } };
  assert.equal(evaluatePolicy(p, { amount: 500, to: "acct-1" }).decision, "ALLOW");
  assert.equal(evaluatePolicy(p, { amount: 5000, to: "acct-1" }).decision, "BLOCK");
  assert.equal(evaluatePolicy(p, { amount: 500, to: "attacker" }).decision, "BLOCK");
  assert.equal(evaluatePolicy(undefined, { anything: 1 }).decision, "ALLOW");
});

test("ALLOW runs the tool and emits a verifiable receipt", async () => {
  const { privateKey, publicKey } = await keypair();
  const receipts: Receipt[] = [];
  const r = await createRaucleSession({
    issuer: issuerFrom(privateKey),
    policies: { transfer: { maxValue: { amount: 1000 }, allowedValues: { to: ["acct-1"] } } },
    onReceipt: (rec) => { receipts.push(rec); },
  });
  const tools = r.gateTools({ transfer: transferTool() });
  const result = await tools.transfer.execute!({ amount: 500, to: "acct-1" });

  assert.deepEqual(result, { ok: true, amount: 500, to: "acct-1" }); // original ran
  // root + one decision receipt, both verify against the pubkey
  assert.equal(receipts.length, 2);
  for (const rec of receipts) await verify(rec.jws, publicKey);
  const decision = receipts[1];
  assert.equal(decision.payload.operation, "guardrail_scan");
  assert.equal(decision.payload.guardrail_verdict, "ALLOW");
  assert.deepEqual(decision.payload.parents, [r.rootId]); // chained to the session root
});

test("BLOCK throws, does not run the tool, and emits a BLOCK receipt", async () => {
  const { privateKey, publicKey } = await keypair();
  const receipts: Receipt[] = [];
  let ran = false;
  const r = await createRaucleSession({
    issuer: issuerFrom(privateKey),
    policies: { transfer: { maxValue: { amount: 1000 } } },
    onReceipt: (rec) => { receipts.push(rec); },
  });
  const tools = r.gateTools({
    transfer: { ...transferTool(), execute: async (a: any) => { ran = true; return a; } },
  });

  await assert.rejects(
    () => tools.transfer.execute!({ amount: 999999, to: "acct-1" }),
    RauclePolicyDenied,
  );
  assert.equal(ran, false); // side effect blocked before execution
  const decision = receipts.at(-1)!;
  assert.equal(decision.payload.guardrail_verdict, "BLOCK");
  await verify(decision.jws, publicKey);
});

test("failClosed=false returns a structured denial instead of throwing", async () => {
  const { privateKey } = await keypair();
  const r = await createRaucleSession({
    issuer: issuerFrom(privateKey),
    policies: { transfer: { maxValue: { amount: 10 } } },
    failClosed: false,
  });
  const tools = r.gateTools({ transfer: transferTool() });
  const out = (await tools.transfer.execute!({ amount: 999, to: "x" })) as { error: string };
  assert.match(out.error, /raucle denied/);
});

test("emitted receipts form a valid chain (root + decisions)", async () => {
  const { privateKey, publicKey } = await keypair();
  const receipts: Receipt[] = [];
  const r = await createRaucleSession({
    issuer: issuerFrom(privateKey),
    policies: { a: {}, b: {} },
    onReceipt: (rec) => { receipts.push(rec); },
  });
  const tools = r.gateTools({
    a: { execute: () => Promise.resolve("a") },
    b: { execute: () => Promise.resolve("b") },
  });
  await tools.a.execute!({});
  await tools.b.execute!({});
  // verify each, then confirm closure + taint monotonicity over the DAG
  const verified: Receipt[] = [];
  for (const rec of receipts) verified.push(await verify(rec.jws, publicKey));
  const chain = buildChain(verified);
  assert.equal(chain.receipts.length, 3); // root + 2 decisions
});

test("custom gate overrides the built-in policy evaluator", async () => {
  const { privateKey } = await keypair();
  const seen: string[] = [];
  const r = await createRaucleSession({
    issuer: issuerFrom(privateKey),
    gate: (toolName) => { seen.push(toolName); return { decision: toolName === "ok" ? "ALLOW" : "BLOCK", reason: "custom" }; },
  });
  const tools = r.gateTools({ ok: { execute: () => Promise.resolve(1) }, no: { execute: async () => 2 } });
  assert.equal(await tools.ok.execute!({}), 1);
  await assert.rejects(() => tools.no.execute!({}), RauclePolicyDenied);
  assert.deepEqual(seen, ["ok", "no"]);
});
