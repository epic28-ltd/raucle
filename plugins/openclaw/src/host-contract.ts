/**
 * OpenClaw host contract facts and vocabulary (Q14 2c).
 *
 * Verified against the OpenClaw host source (openclaw/openclaw main,
 * src/plugins/hooks.ts, src/plugins/hook-before-tool-call-result.ts,
 * src/agents/agent-tools.before-tool-call.policy.ts) and docs
 * (docs/plugins/hooks.md, docs/plugins/hooks/reference.md):
 *
 * - Typed plugin hooks register through api.on(name, handler, opts?). The
 *   internal api.registerHook(...) system never invokes underscore hook names
 *   such as before_tool_call (it only logs a warning).
 * - api.on opts: matcher (omit = all tools; empty lists invalid), priority,
 *   registrationId, timeoutMs.
 * - before_tool_call result shape:
 *   { params?, block?, blockReason?, requireApproval? }.
 *   block: true is terminal; block: false is no decision.
 * - Hook runner failure defaults: before_agent_run, before_channel_ingress and
 *   before_model_request are fail-closed; every other hook (including
 *   before_tool_call) defaults to fail-open on the shared runner
 *   (hooks.ts: failurePolicyByHook[hookName] ?? "fail-open") although some
 *   host runners pin fail-closed. The plugin therefore NEVER relies on
 *   exception-based blocking: every failure path returns an explicit decision.
 * - When the host threads an admission-token receipt (Gateway-mediated calls,
 *   agent-tools.before-tool-call.policy.ts callerIdentity) the typed runner
 *   records every handler result itself via recordBeforeToolCallDecision with
 *   this vocabulary: outcome allowed | denied | unknown, coverageState
 *   enforced | unknown, reasonCode plugin_hook_allowed | plugin_hook_blocked |
 *   plugin_hook_approval_required | plugin_hook_failed_open |
 *   plugin_hook_failed_closed.
 * - The typed before_tool_call context carries an optional abortSignal that
 *   aborts when the owning tool call is cancelled (hook timeout expiry does
 *   not abort it). Handlers must pass it to cancellable I/O.
 */

/** The minimum OpenClaw release that provides the typed plugin hook API. */
export const MIN_HOST_VERSION = ">=2026.4.22";

/** Registered hook names (the typed plugin hook catalogue names we use). */
export const TypedHookNames = {
  beforePromptBuild: "before_prompt_build",
  messageSending: "message_sending",
  beforeToolCall: "before_tool_call",
  llmOutput: "llm_output",
  messageReceived: "message_received",
  inboundClaim: "inbound_claim",
} as const;

export type TypedHookName = (typeof TypedHookNames)[keyof typeof TypedHookNames];

/** The host hook runner fails open by default for before_tool_call. */
export const HOST_TOOL_HOOK_HOOK_NAME = "before_tool_call";
/** Host budget for before_tool_call hooks: 15 seconds (hook reference). */
export const HOST_TOOL_HOOK_BUDGET_MS = 15000;
/** The host hook runner default for before_tool_call: fail-open. */
export const HOST_TOOL_HOOK_DEFAULT_FAILURE_POLICY = "fail-open";

/**
 * Host decision-record vocabulary for before_tool_call handler outcomes
 * (recordBeforeToolCallDecision in hooks.ts). The plugin maps its own
 * decisions into these fields so operator-side correlation stays truthful.
 */
export const HostDecisionVocabulary = {
  outcomes: ["allowed", "denied", "unknown"] as const,
  coverageStates: ["enforced", "unknown"] as const,
  reasonCodes: [
    "plugin_hook_allowed",
    "plugin_hook_blocked",
    "plugin_hook_approval_required",
    "plugin_hook_failed_open",
    "plugin_hook_failed_closed",
  ] as const,
};

export type HostDecisionOutcome = (typeof HostDecisionVocabulary.outcomes)[number];
export type HostCoverageState = (typeof HostDecisionVocabulary.coverageStates)[number];
export type HostReasonCode = (typeof HostDecisionVocabulary.reasonCodes)[number];

/** An explicit typed before_tool_call result (hook-native decision shape). */
export type ToolGateResult = {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
};

export function toolGateBlock(reason: string): ToolGateResult {
  return { block: true, blockReason: reason };
}

/** The typed before_tool_call context (subset the plugin consumes). */
export type ToolGateContext = {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolCallId?: string;
  abortSignal?: AbortSignal;
  /**
   * Forward-compatibility hook: hosts that expose an admission-token authority
   * callback to plugins deliver it here. Absent on hosts that keep the receipt
   * path host-internal; the plugin degrades to plugin-side evidence then.
   */
  receiptAuthority?: () => void;
};

type ApiOn = (name: string, handler: unknown, opts?: Record<string, unknown>) => void;

/**
 * Detect the typed hook surface. Registers through api.registerHook(...) are a
 * silent no-op for underscore hook names on the typed runner, so a host
 * without api.on must be refused, never silently degraded.
 */
export function typedHookSurfaceAvailable(
  api: Record<string, unknown>,
): api is { on: ApiOn } & Record<string, unknown> {
  return typeof (api as { on?: unknown }).on === "function";
}

/** Effective matcher coverage for a captured registration + tool name. */
export function registrationCoversTool(
  registration: { opts?: Record<string, unknown> },
  toolName: string,
): boolean {
  const matcher = registration.opts?.matcher;
  if (matcher === undefined || matcher === null) {
    return true; // omitted matcher = all tools (host contract)
  }
  if (Array.isArray(matcher)) {
    return matcher.includes(toolName);
  }
  return false;
}
