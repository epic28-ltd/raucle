/**
 * Startup gate, bounded hook work and outcome-bound receipt tests (Q14 2b).
 *
 * Pinned behaviours:
 * - The bounded startup wait completes BEFORE the gate is treated as active;
 *   closed mode plus a scanner that never becomes ready REFUSES activation
 *   (named), and every gated call then returns the explicit block decision.
 * - Hook work is bounded under the host's 15s before_tool_call budget: the
 *   scan carries a deadline, and a late-arriving scan after the deadline is
 *   discarded - it NEVER writes a receipt implying the call proceeded.
 * - Receipts bind to the ACTUAL final outcome (allowed/denied/none) and the
 *   scanner verdict + ruleset identity stay in SEPARATE fields from any
 *   authorisation evidence (finding 101: a CLEAN verdict never appears as an
 *   authorisation decision and vice versa).
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  registerPlugin,
  activationRefused,
  type PluginActivationError,
  type PluginDeps,
} from "../index.ts";
import type { ManagerLike } from "../index.ts";
import { createMockHostApi } from "./helpers.ts";
import { DecisionLog } from "../src/decision-log.ts";
import type { ScanResult } from "../src/scanner-client.ts";

function scanResult(verdict: string, deadlineHint = false): ScanResult {
  return {
    verdict,
    confidence: verdict === "CLEAN" ? 0.99 : 0.97,
    injection_detected: verdict !== "CLEAN",
    categories: deadlineHint ? [] : [],
    attack_technique: "",
    matched_rules: verdict === "MALICIOUS" ? ["tool.rule.x"] : [],
    action: "allow",
    notes: [],
  };
}

function readyManager(): ManagerLike {
  return {
    start: async () => undefined,
    isRunning: true,
    secret: "boot-secret",
    secretFingerprint: "sha256:deadbeefdeadbeef",
  };
}

function failingManager(): ManagerLike {
  return {
    start: () => {
      const err = new Error(
        "raucle scanner on port 8900 did not prove its identity within 15000ms"
      ) as Error & { kind?: string };
      err.kind = "scanner-not-ready";
      return Promise.reject(err);
    },
    isRunning: false,
    secret: "boot-secret",
    secretFingerprint: "sha256:deadbeefdeadbeef",
  };
}

function slowClient(delayMs: number, result: ScanResult, ignoreAbort = true) {
  let pending: Array<(v: ScanResult) => void> = [];
  const client = {
    scan: () => new Promise<ScanResult>((r) => pending.push(r)),
    scanOutput: () => new Promise<ScanResult>((r) => pending.push(r)),
    scanToolCall: (): Promise<ScanResult> =>
      new Promise<ScanResult>((r) => {
        setTimeout(() => r(result), delayMs);
      }),
    // test utility: flush all pending
    _flush: () => {
      const p = pending;
      pending = [];
      for (const res of p) res(result);
    },
  };
  void ignoreAbort;
  return client;
}

function okClientNow(result: ScanResult) {
  return {
    scan: async () => result,
    scanOutput: async () => result,
    scanToolCall: async () => result,
  };
}

function toolHandlerOf(handle: ReturnType<typeof registerPlugin>): (
  event: unknown,
  ctx: Record<string, unknown>,
) => Promise<unknown> {
  const reg = handle.registrations.find((r) => r.name === "before_tool_call");
  assert.ok(reg, "tool gate must be registered");
  return reg.handler as never;
}

function baseConfig(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { scanToolCalls: true, scanInbound: true, scanOutbound: true, ...extra };
}

test("closed mode: a scanner that never becomes ready refuses plugin activation (named)", async () => {
  const host = createMockHostApi({ pluginConfig: baseConfig() });
  const handle = registerPlugin(host.api as never, {
    skipStartup: false,
    createManager: () => failingManager(),
    createScanner: () => okClientNow(scanResult("CLEAN")) as never,
  });
  await handle.startup;
  assert.equal(handle.startupState.refused, true, "closed mode refuses activation on failure");
  assert.match(handle.startupState.reason ?? "", /scanner-not-ready|identity|refused/i);
  const refusalLog = host.logs.map((l) => l.msg).find((m) => m.includes("ACTIVATION REFUSED"));
  assert.ok(refusalLog, "the refusal is named in the log");

  // Every gated call after refusal returns the EXPLICIT block decision.
  const handler = toolHandlerOf(handle);
  const result = (await handler({ toolName: "exec", params: {} }, { agentId: "a1" })) as Record<
    string,
    unknown
  >;
  assert.equal(result?.block, true, "a refused plugin never lets traffic through silently");
  assert.match(String(result?.blockReason), /refused|not ready|scanner/i);
});

test("open mode: a failed startup continues with a named warning (no refusal)", async () => {
  const host = createMockHostApi({ pluginConfig: baseConfig({ failureMode: "open" }) });
  const handle = registerPlugin(host.api as never, {
    skipStartup: false,
    createManager: () => failingManager(),
    createScanner: () => okClientNow(scanResult("CLEAN")) as never,
  });
  await handle.startup;
  assert.equal(handle.startupState.refused, false, "open mode does not refuse");
  const warn = host.logs
    .filter((l) => l.level === "warn" || l.level === "error")
    .map((l) => l.msg)
    .find((m) => m.includes("startup"));
  assert.ok(warn, "the failed startup is named in a warning");
});

test("a successful startup logs the status summary: hooks, reachability with boot secret, failureMode", async () => {
  const host = createMockHostApi({ pluginConfig: baseConfig({ failureMode: "closed" }) });
  const handle = registerPlugin(host.api as never, {
    skipStartup: false,
    createManager: () => readyManager(),
    createScanner: () => okClientNow(scanResult("CLEAN")) as never,
  });
  await handle.startup;
  const summary = host.logs.map((l) => l.msg).find((m) => m.includes("STARTUP"));
  assert.ok(summary, "startup summary is logged");
  assert.match(summary, /hooks=/);
  assert.match(summary, /failureMode=closed/);
  assert.match(summary, /secret=sha256:/, "the summary names the boot-secret fingerprint");
  assert.doesNotMatch(summary, /boot-secret/, "the raw secret never appears in logs");
});

test("bounded hook work: a scan hitting the deadline returns an explicit block in closed mode", async () => {
  const host = createMockHostApi({ pluginConfig: baseConfig({ scanTimeoutMs: 150 }) });
  const handle = registerPlugin(host.api as never, {
    skipStartup: true,
    createManager: () => readyManager(),
    createScanner: () => slowClient(600, scanResult("CLEAN")) as never,
  });
  const handler = toolHandlerOf(handle);
  const started = Date.now();
  const result = (await handler({ toolName: "exec", params: {} }, { agentId: "a1" })) as Record<
    string,
    unknown
  >;
  const elapsed = Date.now() - started;
  assert.equal(result?.block, true, "deadline + closed mode = explicit block");
  assert.match(String(result?.blockReason), /deadline|timed out/i);
  assert.ok(elapsed < 500, `the handler bounded its own work (took ${elapsed}ms)`);

  // The late scan resolves afterwards; it must NOT mint an allow receipt.
  const lateGuard = new Promise<void>((done) => setTimeout(done, 700));
  await lateGuard;
  const entries = handle.decisionLog.entries();
  const lateAllow = entries.find(
    (e) => e.receipt.bound === "allowed" && e.hook === "before_tool_call"
  );
  assert.equal(
    lateAllow,
    undefined,
    "a scan arriving after the deadline never writes an allow receipt"
  );
  const late = entries.find((e) => e.discarded === "late-arrival-after-seal");
  assert.ok(late, "the late scan is recorded as discarded");
  assert.equal(late.receipt.bound, "none", "no receipt binds to a post-deadline scan");
  assert.equal(late.outcome, "denied", "F104: the sealed call renders UNAUTHORISED, never allow-equivalent");
});

test("the receipt binds to the ACTUAL final outcome for completed calls", async () => {
  const host = createMockHostApi({ pluginConfig: baseConfig() });
  const handle = registerPlugin(host.api as never, {
    skipStartup: true,
    createManager: () => readyManager(),
    createScanner: () => okClientNow(scanResult("CLEAN")) as never,
  });
  const handler = toolHandlerOf(handle);
  await handler({ toolName: "exec", params: {} }, { agentId: "a1" });
  let entries = handle.decisionLog.entries();
  assert.equal(entries.length, 1);
  assert.equal(entries[0].receipt.bound, "allowed");
  assert.equal(entries[0].receipt.issued, true);
  assert.equal(entries[0].outcome, "allowed");
  assert.equal(entries[0].coverageState, "enforced");

  const host2 = createMockHostApi({ pluginConfig: baseConfig() });
  const handle2 = registerPlugin(host2.api as never, {
    skipStartup: true,
    createManager: () => readyManager(),
    createScanner: () => okClientNow(scanResult("MALICIOUS")) as never,
  });
  const handler2 = toolHandlerOf(handle2);
  const blocked = (await handler2(
    { toolName: "exec", params: {} },
    { agentId: "a2" }
  )) as Record<string, unknown>;
  assert.equal(blocked?.block, true);
  entries = handle2.decisionLog.entries();
  assert.equal(entries[0].receipt.bound, "denied");
  assert.equal(entries[0].outcome, "denied");
});

test("scanner verdict and ruleset identity stay SEPARATE from authorisation evidence", async () => {
  const host = createMockHostApi({ pluginConfig: baseConfig() });
  const handle = registerPlugin(host.api as never, {
    skipStartup: true,
    createManager: () => readyManager(),
    createScanner: () => okClientNow(scanResult("CLEAN")) as never,
  });
  const handler = toolHandlerOf(handle);
  await handler({ toolName: "exec", params: {} }, { agentId: "a1" });
  const entry = handle.decisionLog.entries()[0];
  // authorisation family:
  assert.ok(entry.outcome === "allowed" || entry.outcome === "denied" || entry.outcome === "unknown");
  assert.ok(entry.coverageState === "enforced" || entry.coverageState === "unknown");
  // scanner family, fully disjoint:
  assert.equal(entry.scanner?.verdict, "CLEAN");
  assert.ok(Array.isArray(entry.scanner?.matchedRules));
  // structural separation: no authorisation field carries scanner data and
  // no scanner field carries an authorisation decision.
  const authKeys = new Set(["outcome", "coverageState", "reasonCode", "receipt"]);
  const scannerKeys = new Set(Object.keys(entry.scanner ?? {}));
  for (const key of authKeys) {
    assert.equal(
      scannerKeys.has(key),
      false,
      `scanner family must not restate authorisation field ${key}`
    );
  }
  assert.equal(
    entry.scanner && "outcome" in entry.scanner ? (entry.scanner as Record<string, unknown>).outcome : undefined,
    undefined,
    "a CLEAN verdict never doubles as an authorisation decision"
  );
});

test("a scanner-unavailable decision carries no scanner verdict fields at all", async () => {
  const failing = {
    scan: () => Promise.reject(new Error("connect ECONNREFUSED")),
    scanOutput: () => Promise.reject(new Error("connect ECONNREFUSED")),
    scanToolCall: () => Promise.reject(new Error("connect ECONNREFUSED")),
  };
  const host = createMockHostApi({ pluginConfig: baseConfig({ failureMode: "closed" }) });
  const handle = registerPlugin(host.api as never, {
    skipStartup: true,
    createManager: () => readyManager(),
    createScanner: () => failing as never,
  });
  const handler = toolHandlerOf(handle);
  const result = (await handler({ toolName: "exec", params: {} }, { agentId: "a1" })) as Record<
    string,
    unknown
  >;
  assert.equal(result?.block, true);
  const entry = handle.decisionLog.entries()[0];
  assert.equal(entry.scanner?.verdict, undefined, "no scanner verdict exists; none may be recorded");
  assert.equal(entry.scanner?.unavailable, true);
  assert.equal(entry.scanner?.reasonClass, "connection-refused");
  assert.equal(entry.receipt.bound, "denied", "closed-mode failure blocks and receipt binds denied");
});

test("the decision log is bounded (ring buffer)", () => {
  const log = new DecisionLog(3);
  for (let i = 0; i < 10; i++) {
    log.record({
      ts: i,
      hook: "before_tool_call",
      toolName: `t${i}`,
      outcome: "allowed",
      coverageState: "enforced",
      reasonCode: "plugin_hook_allowed",
      authorityAcknowledged: false,
      scanner: { unavailable: true, reasonClass: "unknown" },
      receipt: { issued: false, bound: "none" },
    });
  }
  const entries = log.entries();
  assert.equal(entries.length, 3, "bounded log keeps at most maxEntries");
  assert.deepEqual(entries.map((e) => e.toolName), ["t7", "t8", "t9"], "oldest evicted");
});

test("activationRefused errors carry their kind", () => {
  const err = activationRefused("startup-refused", "test") as PluginActivationError;
  assert.equal(err.kind, "startup-refused");
});
