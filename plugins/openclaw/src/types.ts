/**
 * Plugin configuration types.
 */

export interface RaucleClawConfig {
  enabled?: boolean;
  mode?: "strict" | "standard" | "permissive";
  /** Scanner unavailability posture: "closed" blocks protected operations, "open" continues (default closed). */
  failureMode?: "closed" | "open";
  /** Per-call scan deadline in ms, aligned under the host's 15s hook budget (default 10000). */
  scanTimeoutMs?: number;
  /** Per-boot scan secret; when unset the manager generates crypto.randomUUID per boot. */
  scanSecret?: string;
  serverPort?: number;
  rulesDir?: string;
  alertChannel?: string;
  blockOnMalicious?: boolean;
  scanInbound?: boolean;
  scanOutbound?: boolean;
  scanToolCalls?: boolean;
  pythonPath?: string;
  agentOverrides?: Record<string, AgentOverride>;
}

export interface AgentOverride {
  mode?: "strict" | "standard" | "permissive";
  scanInbound?: boolean;
  scanOutbound?: boolean;
  scanToolCalls?: boolean;
}

/** Host budget for before_tool_call hooks; our deadline must fire before it. */
const HOST_HOOK_BUDGET_MS = 15000;
/** Safety margin under the host budget so our explicit refusal lands first. */
const DEADLINE_MARGIN_MS = 3000;

function clampTimeoutMs(raw: unknown): number | undefined {
  if (typeof raw !== "number" || !Number.isFinite(raw)) return undefined;
  const upper = HOST_HOOK_BUDGET_MS - DEADLINE_MARGIN_MS;
  return Math.min(Math.max(Math.floor(raw), 100), upper);
}

export function resolveConfig(raw: Record<string, unknown>): RaucleClawConfig {
  const failureMode = raw.failureMode as RaucleClawConfig["failureMode"] | undefined;
  const timeoutRaw = raw.scanTimeoutMs as number | undefined;
  return {
    enabled: (raw.enabled as boolean) ?? true,
    mode: (raw.mode as RaucleClawConfig["mode"]) ?? "standard",
    failureMode: failureMode === "open" ? "open" : "closed",
    // Clamp the per-call scan deadline under the host's 15s before_tool_call
    // budget: our own deadline must always fire before the host's.
    scanTimeoutMs: clampTimeoutMs(timeoutRaw),
    scanSecret: raw.scanSecret as string | undefined,
    serverPort: (raw.serverPort as number) ?? 8900,
    rulesDir: raw.rulesDir as string | undefined,
    alertChannel: raw.alertChannel as string | undefined,
    blockOnMalicious: (raw.blockOnMalicious as boolean) ?? true,
    scanInbound: (raw.scanInbound as boolean) ?? true,
    scanOutbound: (raw.scanOutbound as boolean) ?? true,
    scanToolCalls: (raw.scanToolCalls as boolean) ?? true,
    pythonPath: raw.pythonPath as string | undefined,
    agentOverrides: raw.agentOverrides as Record<string, AgentOverride> | undefined,
  };
}

export function getAgentMode(
  config: RaucleClawConfig,
  agentId?: string,
): string {
  if (agentId && config.agentOverrides?.[agentId]?.mode) {
    return config.agentOverrides[agentId].mode!;
  }
  return config.mode ?? "standard";
}

export function shouldScanInbound(
  config: RaucleClawConfig,
  agentId?: string,
): boolean {
  if (agentId && config.agentOverrides?.[agentId]?.scanInbound !== undefined) {
    return config.agentOverrides[agentId].scanInbound!;
  }
  return config.scanInbound ?? true;
}

export function shouldScanOutbound(
  config: RaucleClawConfig,
  agentId?: string,
): boolean {
  if (agentId && config.agentOverrides?.[agentId]?.scanOutbound !== undefined) {
    return config.agentOverrides[agentId].scanOutbound!;
  }
  return config.scanOutbound ?? true;
}

export function shouldScanToolCalls(
  config: RaucleClawConfig,
  agentId?: string,
): boolean {
  if (agentId && config.agentOverrides?.[agentId]?.scanToolCalls !== undefined) {
    return config.agentOverrides[agentId].scanToolCalls!;
  }
  return config.scanToolCalls ?? true;
}
