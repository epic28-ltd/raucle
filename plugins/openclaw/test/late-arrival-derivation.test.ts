/**
 * Late-arrival outcome derivation, pinned against the SHIPPED index.ts path
 * (PR #322 verdict D5).
 *
 * The earlier pin re-declared the derivation inline (a copy of recordLateArrival's
 * logic) and never exercised the real handler, so it stayed green against the
 * pre-fix shape. This file drives registerPlugin's typed before_tool_call
 * handler with a scanner that settles after the deadline, and pins exactly what
 * the shipped decision path writes into the bounded decision log for BOTH
 * failure modes: the outcome derives from the ACTIVE failure mode, the reason
 * stays inside the declared DecisionReasonCode vocabulary, no receipt binds to
 * a post-seal scan, and the entry carries the call's actual acknowledgement
 * state (D3).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { registerPlugin, type ManagerLike } from "../index.ts";
import type { ScanResult } from "../src/scanner-client.ts";
import { createMockHostApi } from "./helpers.ts";

function lateScan(): ScanResult {
  return {
    verdict: "CLEAN",
    confidence: 0.98,
    injection_detected: false,
    categories: [],
    attack_technique: "",
    matched_rules: [],
    action: "allow",
    notes: [],
  };
}

function okManager(): ManagerLike {
  return {
    start: async () => undefined,
    isRunning: true,
    secret: "s3cret",
    secretFingerprint: "sha256:deadbeefdeadbeef",
  };
}

/** Scanner whose scanToolCall promise resolves only once it is released. */
function lateScanner() {
  let release: ((r: ScanResult) => void) | null = null;
  const client = {
    scan: () => new Promise<ScanResult>(() => undefined),
    scanOutput: () => new Promise<ScanResult>(() => undefined),
    scanToolCall: () => new Promise<ScanResult>((resolve) => { release = resolve; }),
  };
  return { client, settle: (result: ScanResult = lateScan()) => release?.(result) };
}

function register(failureMode: "closed" | "open") {
  const host = createMockHostApi({
    pluginConfig: {
      failureMode,
      scanToolCalls: true,
      scanInbound: false,
      scanOutbound: false,
      // The shipped handler derives its deadline from config.scanTimeoutMs;
      // a tiny value seals the call long before the scanner settles.
      scanTimeoutMs: 20,
    },
  });
  const scanner = lateScanner();
  const handle = registerPlugin(host.api as never, {
    skipStartup: true,
    createManager: () => okManager(),
    createScanner: () => scanner.client as never,
  });
  const reg = host.typed.find((r) => r.name === "before_tool_call");
  if (!reg) {
    throw new Error("tool gate must be registered");
  }
  const handler = reg.handler as (
    event: { toolName?: string; params?: Record<string, unknown> },
    ctx?: unknown,
  ) => Promise<unknown>;
  return { handle, handler, settle: scanner.settle };
}

function settleDelay(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 25));
}

for (const [failureMode, expected] of [
  ["closed", { outcome: "denied", coverageState: "enforced", reasonCode: "plugin_hook_blocked" }],
  ["open", { outcome: "unknown", coverageState: "unknown", reasonCode: "plugin_hook_failed_open" }],
] as const) {
  test(`late-arrival outcome derives from the shipped handler path (failureMode=${failureMode})`, async () => {
    const { handle, handler, settle } = register(failureMode);

    // The deadline seals the call before the scanner settles; the handler
    // returns its sealed decision.
    const result = (await handler({ toolName: "exec", params: {} }, {
      agentId: "a1",
    })) as Record<string, unknown>;
    if (failureMode === "closed") {
      assert.equal(result?.block, true, "closed mode returns the explicit block decision");
    } else {
      assert.equal(result, undefined, "open mode continues the sealed call");
    }

    // The abandoned scan then settles: the shipped watcher must record a
    // discarded entry derived from the ACTIVE failure mode.
    settle();
    await settleDelay();
    const late = handle.decisionLog
      .entries()
      .find((e) => e.discarded === "late-arrival-after-seal");
    if (!late) {
      throw new Error("the shipped late watcher recorded no discarded entry");
    }
    assert.equal(late.outcome, expected.outcome, "outcome derives from the active failure mode");
    assert.equal(late.coverageState, expected.coverageState, "coverage derives from the active failure mode");
    assert.equal(late.reasonCode, expected.reasonCode, "the reason stays in the DecisionReasonCode vocabulary");
    assert.equal(late.receipt.bound, "none", "no receipt binds to a post-seal scan");
    assert.equal(late.receipt.issued, false, "a post-seal scan mints no receipt");
    assert.equal(
      late.authorityAcknowledged,
      false,
      "no receiptAuthority was exposed for this call, so the log must say so (D3 truth)"
    );
  });
}

test("a CLEAN verdict arriving after the seal never becomes an allow receipt", async () => {
  const { handle, handler, settle } = register("closed");
  await handler({ toolName: "exec", params: {} }, { agentId: "a1" });
  settle(lateScan());
  await settleDelay();
  const allow = handle.decisionLog.entries().find((e) => e.receipt.bound === "allowed");
  assert.equal(allow, undefined, "the discarded clean verdict never mints an allow receipt");
  const denied = handle.decisionLog
    .entries()
    .find((e) => e.discarded === "late-arrival-after-seal");
  if (!denied) {
    throw new Error("closed mode records the discarded late-arrival entry");
  }
  const scannerEvidence = denied.scanner ?? null;
  if (!scannerEvidence || "unavailable" in scannerEvidence) {
    throw new Error("closed mode records the late verdict as scanner evidence, not an unavailable marker");
  }
  assert.equal(scannerEvidence.verdict, "CLEAN", "the scanner family records the late verdict");
  assert.equal(denied.outcome, "denied", "F104: the sealed call stays UNAUTHORISED, never allow-equivalent");
});
