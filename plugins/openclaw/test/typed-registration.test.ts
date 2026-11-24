/**
 * Typed hook registration contract tests (Q14 2c).
 *
 * The OpenClaw typed runner (api.on) is the only invocation path for underscore
 * hook names such as before_tool_call: registrations made through the internal
 * api.registerHook(...) system produce a warning and are never invoked by the
 * typed runner (host docs/plugins/hooks.md; openclaw issue #55745 pins
 * api.on availability to release v2026.4.22). These tests pin the migration.
 */

import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import test from "node:test";

import raucleClaw, { describeRuntimeRegistration, toolGateCoversTool } from "../index.ts";
import { createMockHostApi } from "./helpers.ts";

const SCANNED_HOOK_NAMES = [
  "before_prompt_build",
  "message_sending",
  "before_tool_call",
  "llm_output",
];

function registerOnMockHost(pluginConfig: Record<string, unknown> = {}) {
  const host = createMockHostApi({ pluginConfig });
  // Dependencies are stubbed here only where the default construction would
  // touch the filesystem or network; the mock host never spawns a scanner.
  raucleClaw.register(host.api, { skipStartup: true });
  return host;
}

test("every scanned hook registers through the typed api.on surface", () => {
  const host = registerOnMockHost();
  const typedNames = host.typed.map((r) => r.name);
  for (const name of SCANNED_HOOK_NAMES) {
    assert.ok(
      typedNames.includes(name),
      `hook ${name} must be registered via api.on (typed), got typed=[${typedNames.join(", ")}]`,
    );
  }
});

test("no underscore hook name is registered through the internal registerHook system", () => {
  const host = registerOnMockHost();
  const underscoreLegacy = host.legacy.filter((r) => r.name.includes("_"));
  assert.deepEqual(
    underscoreLegacy,
    [],
    `api.registerHook never runs underscore names on the typed runner; got ${JSON.stringify(
      underscoreLegacy.map((r) => r.name),
    )}`,
  );
});

test("the tool gate registration omits matcher so every registered tool is covered", () => {
  const host = registerOnMockHost();
  const toolGate = host.typed.find((r) => r.name === "before_tool_call");
  assert.ok(toolGate, "tool gate must be registered");
  assert.equal(
    (toolGate.opts as Record<string, unknown> | undefined)?.matcher,
    undefined,
    "a restrict matcher is a coverage hole; omit to match all tools",
  );
});

test("toolGateCoversTool enumerates every representative tool as covered", () => {
  const representative = [
    "exec",
    "apply_patch",
    "browser",
    "message",
    "web_search",
    "spawn_agent",
    "custom_operator_tool",
  ];
  for (const toolName of representative) {
    assert.equal(
      toolGateCoversTool({ name: "before_tool_call", opts: {} }, toolName),
      true,
      `tool ${toolName} must pass the effective matcher`,
    );
  }
});

test("the plugin pins the minimum OpenClaw host version where the typed runner exists", () => {
  const pkg = JSON.parse(readText(new URL("../package.json", import.meta.url)));
  assert.equal(
    pkg.openclaw?.install?.minHostVersion,
    ">=2026.4.22",
    "typed api.on exists since v2026.4.22 (openclaw issue #55745)",
  );
});

test("describeRuntimeRegistration reports before_tool_call under typedHooks for inspection", () => {
  const host = registerOnMockHost();
  const runtime = describeRuntimeRegistration();
  assert.equal(runtime.pluginId, "raucle");
  assert.ok(Array.isArray(runtime.typedHooks));
  const toolHook = runtime.typedHooks.find(
    (h: { name: string }) => h.name === "before_tool_call",
  );
  assert.ok(toolHook, "inspect output must list before_tool_call under typedHooks");
  assert.equal(toolHook.enabled, true);
  assert.equal(toolHook.matcher, null, "null matcher = all tools");
});

test("a host without the typed api surface refuses activation instead of legacy registration", () => {
  const host = createMockHostApi({ supportsTypedHooks: false });
  assert.throws(
    () => raucleClaw.register(host.api, { skipStartup: true }),
    (err: Error & { kind?: string }) => {
      assert.equal(err.kind, "host-too-old");
      assert.match(err.message, /api\.on|typed/i);
      return true;
    },
    "legacy registration of underscore names is a silent no-op; refuse loudly",
  );
  assert.equal(host.typed.length, 0);
  assert.equal(host.legacy.length, 0);
});

function readText(url: URL): string {
  return readFileSync(url, "utf-8");
}
