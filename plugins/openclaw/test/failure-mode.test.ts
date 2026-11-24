/**
 * failureMode closed/open posture tests (Q14 section 1 + F95 correction).
 *
 * The OpenClaw hook runner defaults to FAIL-OPEN for before_tool_call on the
 * shared runner (src/plugins/hooks.ts: failurePolicyByHook[hookName] ??
 * "fail-open"; only before_agent_run and before_channel_ingress default
 * fail-closed there), so the plugin must NEVER rely on exception-based
 * blocking: every scanner failure in closed mode returns an EXPLICIT typed
 * block decision, never a thrown error whose outcome depends on host policy.
 */

import assert from "node:assert/strict";
import test from "node:test";

import raucleClaw from "../index.ts";
import type { ManagerLike, PluginDeps } from "../index.ts";
import { createMockHostApi } from "./helpers.ts";
import { resolveConfig } from "../src/types.ts";
import { classifyScanError } from "../src/scanner-client.ts";

type Captured = { name: string; handler?: (...args: unknown[]) => unknown };

function capture(host: ReturnType<typeof createMockHostApi>, name: string): Captured["handler"] {
  const reg = host.typed.find((r) => r.name === name);
  assert.ok(reg, `expected a ${name} registration`);
  return reg.handler as Captured["handler"];
}

function stubManager(running = true): ManagerLike {
  return {
    start: async () => undefined,
    isRunning: running,
    secret: "test-secret",
    secretFingerprint: "sha256:deadbeefdeadbeef",
  };
}

type StubClient = {
  scan: (prompt: string, mode?: string) => Promise<never>;
  scanOutput: (output: string, originalPrompt?: string, mode?: string) => Promise<never>;
  scanToolCall: (toolName: string, args: Record<string, unknown>, mode?: string) => Promise<never>;
};

function stubClient(err: unknown): StubClient {
  const reject = (): Promise<never> => Promise.reject(err);
  return { scan: reject, scanOutput: reject, scanToolCall: reject };
}

function registerWithFailureMode(
  failureMode: "closed" | "open" | undefined,
  opts: { scannerError: unknown; managerRunning?: boolean } = { scannerError: new Error("boom") },
) {
  const pluginConfig: Record<string, unknown> = {};
  if (failureMode !== undefined) {
    pluginConfig.failureMode = failureMode;
  }
  const host = createMockHostApi({ pluginConfig });
  const deps: PluginDeps = {
    skipStartup: true,
    createManager: () => stubManager(opts.managerRunning ?? true),
    createScanner: () => stubClient(opts.scannerError) as never,
  };
  raucleClaw.register(host.api, deps);
  return { host, logs: host.logs };
}

test("resolveConfig defaults failureMode to closed (house fail-closed posture)", () => {
  assert.equal(resolveConfig({}).failureMode, "closed");
  assert.equal(resolveConfig({ failureMode: "open" }).failureMode, "open");
  // Anything unrecognised stays fail-closed.
  assert.equal(resolveConfig({ failureMode: "wild" }).failureMode, "closed");
});

test("closed mode: scanner timeout returns an EXPLICIT block decision (never a throw)", async () => {
  const { host } = registerWithFailureMode("closed", {
    scannerError: (() => {
      const e = new Error("The operation was aborted due to timeout");
      (e as Error & { name: string }).name = "TimeoutError";
      return e;
    })(),
  });
  const handler = capture(host, "before_tool_call") as (
    event: unknown,
    ctx: unknown,
  ) => Promise<Record<string, unknown> | undefined>;
  const result = await handler({ toolName: "exec", params: { cmd: "ls" } }, { agentId: "a1" });
  assert.ok(result, "closed mode must not return undefined on scanner failure");
  assert.equal(result.block, true);
  assert.match(String(result.blockReason), /timeout/i);
});

test("closed mode: connection-refused, malformed-response and http-500 each name their reason class", async () => {
  const cases: Array<[unknown, RegExp]> = [
    [
      (() => {
        const e = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:8900"), {
          code: "ECONNREFUSED",
        }) as Error & { code: string };
        return e;
      })(),
      /connection-refused/,
    ],
    [new SyntaxError("Unexpected token < in JSON at position 0"), /malformed-response/],
    [
      (() => {
        const e = new Error("raucle /scan/tool failed: 500 Internal Server Error");
        (e as Error & { status: number }).status = 500;
        return e;
      })(),
      /http-500/,
    ],
  ];
  for (const [err, pattern] of cases) {
    const { host } = registerWithFailureMode("closed", { scannerError: err });
    const handler = capture(host, "before_tool_call") as (
      event: unknown,
      ctx: unknown,
    ) => Promise<Record<string, unknown> | undefined>;
    const result = await handler({ toolName: "exec", params: {} }, { agentId: "a1" });
    assert.ok(result?.block === true, `expected explicit block for ${pattern}`);
    assert.match(String(result.blockReason), pattern);
  }
});

test("closed mode: a scanner error blocks with a NAMED advisory log carrying the reason class", async () => {
  const { host, logs } = registerWithFailureMode("closed", {
    scannerError: (() => {
      const e = new Error("aborted");
      (e as Error & { name: string }).name = "TimeoutError";
      return e;
    })(),
  });
  const handler = capture(host, "before_tool_call") as (
    event: unknown,
    ctx: unknown,
  ) => Promise<unknown>;
  await handler({ toolName: "exec", params: {} }, { agentId: "a1" });
  const advisory = logs.map((l) => l.msg).find((m) => m.includes("SCANNER FAILURE"));
  assert.ok(advisory, "expected a NAMED scanner failure advisory");
  assert.match(advisory, /timeout/);
  assert.match(advisory, /closed/);
});

test("open mode: the same scanner error continues (undefined) with the named log", async () => {
  const { host, logs } = registerWithFailureMode("open", {
    scannerError: (() => {
      const e = new Error("aborted");
      (e as Error & { name: string }).name = "TimeoutError";
      return e;
    })(),
  });
  const handler = capture(host, "before_tool_call") as (
    event: unknown,
    ctx: unknown,
  ) => Promise<unknown>;
  const handlerPromise = handler({ toolName: "exec", params: {} }, { agentId: "a1" });
  await assert.doesNotReject(handlerPromise);
  const outcome = await handlerPromise;
  assert.equal(outcome, undefined, "open mode continues the protected operation");
  const advisory = logs.map((l) => l.msg).find((m) => m.includes("SCANNER FAILURE"));
  assert.ok(advisory, "open mode logs the same named advisory");
  assert.match(advisory, /timeout/);
  assert.match(advisory, /open/);
});

test("closed mode: inbound scanner failure injects the named block instruction", async () => {
  const { host } = registerWithFailureMode("closed", {
    scannerError: (() => {
      const e = new Error("aborted");
      (e as Error & { name: string }).name = "TimeoutError";
      return e;
    })(),
  });
  const handler = capture(host, "before_prompt_build") as (
    event: unknown,
    ctx: unknown,
  ) => Promise<Record<string, string> | undefined>;
  const result = await handler({ prompt: "hello there agent" }, { agentId: "a1" });
  assert.ok(result, "inbound closed mode must inject a block instruction");
  assert.match(result.systemPrompt ?? "", /unavailable|blocked/i);
  assert.match(result.systemPrompt ?? "", /timeout/);
});

test("closed mode: outbound scanner failure cancels the send with a named reason", async () => {
  const { host } = registerWithFailureMode("closed", {
    scannerError: (() => {
      const e = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:8900"), {
        code: "ECONNREFUSED",
      });
      return e;
    })(),
  });
  const handler = capture(host, "message_sending") as (
    event: unknown,
    ctx: unknown,
  ) => Promise<Record<string, unknown> | undefined>;
  const result = await handler({ content: "outbound message body" }, { agentId: "a1" });
  assert.ok(result, "outbound closed mode must cancel");
  assert.equal(result.cancel, true);
  assert.match(String(result.cancelReason), /connection-refused/i);
});

test("a dead scanner process classifies as process-dead and blocks in closed mode", async () => {
  const { host } = registerWithFailureMode("closed", {
    scannerError: new Error("fetch failed"),
    managerRunning: false,
  });
  const handler = capture(host, "before_tool_call") as (
    event: unknown,
    ctx: unknown,
  ) => Promise<Record<string, unknown> | undefined>;
  const result = await handler({ toolName: "exec", params: {} }, { agentId: "a1" });
  assert.equal(result?.block, true);
  assert.match(String(result.blockReason), /process-dead/);
});

test("classifyScanError maps the named reason classes", () => {
  const timeoutErr = new Error("aborted");
  (timeoutErr as Error & { name: string }).name = "TimeoutError";
  const abortErr = new Error("This operation was aborted");
  (abortErr as Error & { name: string }).name = "AbortError";
  const connErr = Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
  const http500 = Object.assign(new Error("failed: 500"), { status: 500 });
  const http403 = Object.assign(new Error("failed: 403"), { status: 403 });

  assert.equal(classifyScanError(timeoutErr), "timeout");
  assert.equal(classifyScanError(abortErr), "timeout");
  assert.equal(classifyScanError(connErr), "connection-refused");
  assert.equal(classifyScanError(http500), "http-500");
  assert.equal(classifyScanError(http403), "auth-refused");
  assert.equal(classifyScanError(new SyntaxError("Unexpected token < in JSON at position 0")), "malformed-response");
  assert.equal(classifyScanError(new Error("mystery")), "unknown");
});
