/**
 * Host admission-authority integration tests (Q14 2c).
 *
 * On hosts that thread an admission-token receipt (Gateway-mediated calls),
 * the typed runner records every returned handler decision itself through
 * recordBeforeToolCallDecision (host src/plugins/hooks.ts) - but only when the
 * caller identity supplies receiptAuthority. The plugin acknowledges an
 * exposed authority callback exactly once per gated call, returns explicit
 * typed decisions so host records stay truthful, maps its outcomes into the
 * host vocabulary (allowed/denied/unknown x enforced/unknown), and renders any
 * host-recorded unknown policy outcome as UNAUTHORISED in its own evidence
 * (F104: never as allow-equivalent).
 */

import assert from "node:assert/strict";
import test from "node:test";

import raucleClaw from "../index.ts";
import type { ManagerLike, PluginDeps } from "../index.ts";
import {
  hostDecisionForPluginOutcome,
  renderHostOutcomeForPluginEvidence,
} from "../src/host-decision.ts";
import { createMockHostApi } from "./helpers.ts";
import type { ScanResult } from "../src/scanner-client.ts";

function scanResult(verdict: string): ScanResult {
  return {
    verdict,
    confidence: verdict === "CLEAN" ? 0.99 : 0.97,
    injection_detected: verdict !== "CLEAN",
    categories: [],
    attack_technique: "",
    matched_rules: verdict === "MALICIOUS" ? ["rule.injection.direct"] : [],
    action: "allow",
    notes: [],
  };
}

function okManager(): ManagerLike {
  return { start: async () => undefined, isRunning: true, secret: "s3cret", secretFingerprint: "sha256:deadbeefdeadbeef" };
}

function registerWith(
  client: unknown,
  pluginConfig: Record<string, unknown> = {}
): ReturnType<typeof createMockHostApi> {
  const host = createMockHostApi({ pluginConfig });
  const deps: PluginDeps = {
    skipStartup: true,
    createManager: () => okManager(),
    createScanner: () => client as never,
  };
  raucleClaw.register(host.api, deps);
  return host;
}

function toolHandler(host: ReturnType<typeof createMockHostApi>): (
  event: { toolName?: string; params?: Record<string, unknown> },
  ctx: Record<string, unknown>,
) => Promise<unknown> {
  const reg = host.typed.find((r) => r.name === "before_tool_call");
  assert.ok(reg, "tool gate must be registered");
  return reg.handler as never;
}

test("an exposed receiptAuthority callback fires exactly once per gated call", async () => {
  const cases: Array<{ client: unknown; failureMode?: string; expectBlock: boolean }> = [
    { client: stubOk(scanResult("CLEAN")), expectBlock: false },
    { client: stubOk(scanResult("MALICIOUS")), expectBlock: true },
    {
      client: stubFailing(new Error("scanner down")),
      failureMode: "closed",
      expectBlock: true,
    },
    {
      client: stubFailing(new Error("scanner down")),
      failureMode: "open",
      expectBlock: false,
    },
  ];
  for (const c of cases) {
    const host = registerWith(c.client, c.failureMode ? { failureMode: c.failureMode } : {});
    const handler = toolHandler(host);
    const authorityCalls: number[] = [];
    const ctx = {
      agentId: "a1",
      receiptAuthority: () => {
        authorityCalls.push(1);
      },
    };
    await handler({ toolName: "exec", params: {} }, ctx);
    assert.equal(
      authorityCalls.length,
      1,
      `authority callback must fire exactly once (expected block=${c.expectBlock})`
    );
    const result = (await handler({ toolName: "exec", params: {} }, ctx)) as Record<
      string,
      unknown
    >;
    assert.equal(authorityCalls.length, 2, "each gated call re-acknowledges once");
    assert.equal(Boolean(result?.block), c.expectBlock);
  }
});

test("the decision maps into the host decision-record vocabulary", () => {
  assert.deepEqual(hostDecisionForPluginOutcome("allow"), {
    outcome: "allowed",
    coverageState: "enforced",
    reasonCode: "plugin_hook_allowed",
  });
  assert.deepEqual(hostDecisionForPluginOutcome("block"), {
    outcome: "denied",
    coverageState: "enforced",
    reasonCode: "plugin_hook_blocked",
  });
  // The unscanned-continue (open mode, scanner unavailable) is NOT an allow:
  // truthful mapping is unknown/unknown with the host's fail-open reason code.
  assert.deepEqual(hostDecisionForPluginOutcome("continue-without-verdict"), {
    outcome: "unknown",
    coverageState: "unknown",
    reasonCode: "plugin_hook_failed_open",
  });
});

test("F104: a host-recorded unknown policy outcome renders as UNAUTHORISED in plugin evidence", () => {
  // never allow-equivalent:
  assert.equal(renderHostOutcomeForPluginEvidence("unknown"), "denied");
  assert.equal(renderHostOutcomeForPluginEvidence("denied"), "denied");
  assert.equal(renderHostOutcomeForPluginEvidence("allowed"), "allowed");
});

test("a missing authority callback degrades gracefully (plugin-side evidence only)", async () => {
  const host = registerWith(stubOk(scanResult("CLEAN")));
  const handler = toolHandler(host);
  const result = (await handler({ toolName: "exec", params: {} }, { agentId: "a1" })) as Record<
    string,
    unknown
  >;
  assert.equal(result?.block, undefined, "the allow path still returns a decision");
});

function stubOk(result: ScanResult) {
  return {
    scan: async () => result,
    scanOutput: async () => result,
    scanToolCall: async () => result,
  };
}

function stubFailing(err: Error) {
  return {
    scan: () => Promise.reject(err),
    scanOutput: () => Promise.reject(err),
    scanToolCall: () => Promise.reject(err),
  };
}
