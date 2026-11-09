#!/usr/bin/env node
/* X2 acceptance harness: runs the verifier core extracted from the SHIPPED
   page (assets/verifier/x2-verifier.html) against the committed fixture pack.
   Usage: node tests/verifier_harness/x2_harness.mjs <repo-root>
   Prints one JSON verdict object; exits 0 only if every expectation holds. */
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const root = process.argv[2] || process.cwd();
const htmlPath = path.join(root, "assets", "verifier", "x2-verifier.html");
const packDir = path.join(root, "assets", "verifier", "fixtures", "fixture-pack");
const html = fs.readFileSync(htmlPath, "utf8");
const m = html.match(/<script id="x2-verifier-core">([\s\S]*?)<\/script>/);
if (!m) {
  console.error("verifier core block not found in shipped page");
  process.exit(1);
}
vm.runInThisContext(m[1], { filename: "x2-verifier-core" });
const X2V = globalThis.X2V;
if (!X2V) {
  console.error("X2V not exported by the core block");
  process.exit(1);
}
const td = new TextDecoder();
function packFiles(mutate) {
  const index = JSON.parse(fs.readFileSync(path.join(packDir, "PACK.json"), "utf8"));
  const members = index.members.map((mm) => mm.path).concat("PACK.json");
  const out = [];
  for (const p of members) {
    let bytes = new Uint8Array(fs.readFileSync(path.join(packDir, ...p.split("/"))));
    if (mutate) bytes = mutate(p, bytes);
    out.push({ path: p, bytes });
  }
  return out;
}
const PUBKEY_PATH = (JSON.parse(fs.readFileSync(path.join(packDir, "PACK.json"), "utf8")))
  .members.filter((mm) => mm.role === "public-key")[0].path;
const failures = [];
function expect(cond, label, detail) {
  if (!cond) failures.push(label + (detail ? " :: " + JSON.stringify(detail).slice(0, 300) : ""));
}
function allGreen(v) {
  return v.valid === true && v.lines.every((l) => l.status === "green" && l.reasons.length === 0);
}

const results = {};

// 1. named-clean fixture pack
const clean = await X2V.verifyPack(packFiles());
results.clean = {
  ok: clean.ok, integrity_ok: clean.integrity_ok, index_signature_ok: clean.index_signature_ok,
  manifest_signature_ok: clean.manifest_signature_ok, signer_key_id: clean.signer_key_id,
  receipt_count: clean.receipt_count, receipts_green: allGreen({ valid: clean.chain_valid, lines: clean.lines }),
};
expect(clean.ok === true, "fixture pack verifies named-clean", clean.checks);
expect(clean.chain_valid && allGreen({ valid: true, lines: clean.lines }), "every fixture receipt green", clean.lines);
expect(clean.receipt_count === 2, "fixture receipt count is 2", clean.receipt_count);

// 2. custodian pin round-trips on the clean verdict
const pinned = await X2V.verifyPack(packFiles(), { expected_signer: clean.signer_key_id });
expect(pinned.signer_trusted === true, "pinned custodian signer matches", pinned.signer_key_id);
const wrongPin = await X2V.verifyPack(packFiles(), { expected_signer: "0".repeat(16) });
expect(wrongPin.ok === false && wrongPin.signer_trusted === false, "wrong signer pin denies", wrongPin.checks);

// 3. tampered member bytes -> integrity hash mismatch
const tampered = await X2V.verifyPack(packFiles((p, b) => (p === "chain.jsonl" ? new Uint8Array([...b, 0x41]) : b)));
expect(tampered.ok === false && tampered.integrity_ok === false, "tampered member denied", tampered.checks);
expect(JSON.stringify(tampered.checks).includes("hash mismatch"), "named hash-mismatch reason", tampered.checks);

// 4. tampered manifest body -> signature deny
const manifestTampered = await X2V.verifyPack(packFiles((p, b) => {
  if (p !== "manifest.json") return b;
  const mf = JSON.parse(td.decode(b));
  mf.body.red = 99;
  return new TextEncoder().encode(JSON.stringify(mf));
}));
expect(manifestTampered.manifest_signature_ok === false, "tampered manifest denied", manifestTampered.checks);

// 5. tampered index (member digest rewritten) -> index signature deny
const indexTampered = await X2V.verifyPack(packFiles((p, b) => {
  if (p !== "PACK.json") return b;
  const idx = JSON.parse(td.decode(b));
  idx.members[0].sha256 = "sha256:" + "9".repeat(64);
  return new TextEncoder().encode(JSON.stringify(idx));
}));
expect(indexTampered.index_signature_ok === false, "tampered index denied", indexTampered.checks);

// 6. unindexed extra file -> envelope-malleability deny
const extra = await X2V.verifyPack([...packFiles(), { path: "rogue.json", bytes: new TextEncoder().encode("{}") }]);
expect(extra.ok === false, "unindexed extra file denied", extra.checks);

// 7. per-receipt named failure detail on a doctored chain (signature leg)
const chain = td.decode(fs.readFileSync(path.join(packDir, "chain.jsonl")));
const tamperLine = (line, f) => {
  const env = JSON.parse(line);
  const parts = env.jws.split(".");
  const payload = Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const bad = f(payload, parts[2]);
  parts[1] = Buffer.from(bad.payload).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  env.jws = parts.join(".");
  return JSON.stringify(env);
};
// flip a byte INSIDE the signed header (signature + hash both fail, signature named first)
const head = chain.split("\n");
const env0 = JSON.parse(head[0]);
const p0 = env0.jws.split(".");
const hdrBytes = Buffer.from(p0[0].replace(/-/g, "+").replace(/_/g, "/"), "base64");
hdrBytes[hdrBytes.length - 6] ^= 0x20; // mutate the typ literal
p0[0] = Buffer.from(hdrBytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
env0.jws = p0.join(".");
const doctored = [...head];
doctored[0] = JSON.stringify(env0);
const chainRes = await X2V.verifyChainText(doctored.join("\n"), {});
expect(chainRes.valid === false, "doctored chain denied", chainRes);
const l0 = chainRes.lines[0];
expect(l0.status === "red" && l0.reasons.length > 0, "per-receipt named reasons present", l0.reasons);
expect(chainRes.lines.length === 2 && chainRes.lines[1].status === "red",
  "sibling receipts keep independent per-line verdicts", chainRes.lines[1].reasons);

// 7b. dangling parent -> named DAG violation
const linesOnly = chain.trim().split("\n");
const childOnly = await X2V.verifyChainText(linesOnly[1] + "\n", Object.create(null));
expect(childOnly.lines[0].status === "red" &&
  JSON.stringify(childOnly.lines[0].reasons).includes("does not appear in the chain"),
  "dangling parent named", childOnly.lines[0].reasons);

// 8. unknown key id -> fail-closed named reason
const noKey = await X2V.verifyChainText(chain, Object.create(null));
expect(noKey.valid === false && noKey.lines.every((l) =>
  JSON.stringify(l.reasons).includes("no public key supplied")),
  "missing keys fail closed with named reason", noKey);

// 9. single pasted receipt: green with the pack's pubkey, warn without, red with wrong key
const pem = td.decode(fs.readFileSync(path.join(packDir, ...PUBKEY_PATH.split("/"))));
const firstLine = JSON.parse(chain.split("\n")[0]);
const singleGood = await X2V.verifySingleJWS(firstLine.jws, pem);
expect(singleGood.sig_ok === true && singleGood.hash_ok === true && singleGood.status === "green",
  "single receipt verifies against pack pubkey", singleGood);
const singleNoKey = await X2V.verifySingleJWS(firstLine.jws, null);
expect(singleNoKey.status === "warn" && singleNoKey.hash_ok === true &&
  JSON.stringify(singleNoKey.reasons).includes("no public key supplied"),
  "single receipt without key fails closed (warn, hash green)", singleNoKey);
const badPem = pem.replace(/[a-zA-Z0-9+/=]/g, "x").slice(0, pem.length);
let badPemCaught = false;
const badPemRes = await X2V.verifySingleJWS(firstLine.jws, badPem);
badPemCaught = badPemRes.status === "red";
expect(badPemCaught, "corrupt PEM is rejected, never mis-verified", badPemRes);

if (failures.length) {
  console.log(JSON.stringify({ ok: false, failures }, null, 2));
  process.exit(1);
}
console.log(JSON.stringify({ ok: true, results }, null, 2));
