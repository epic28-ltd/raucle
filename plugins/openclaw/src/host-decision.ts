/**
 * Host admission-authority integration and vocabulary mapping (Q14 2c).
 *
 * Host facts (verified against openclaw/openclaw main source):
 * - The typed runner records every before_tool_call handler result itself via
 *   recordBeforeToolCallDecision, but ONLY when the caller identity supplies
 *   receiptAuthority (an admission-token receipt; Gateway-mediated calls).
 * - Recorded vocabulary: outcome allowed | denied | unknown, coverageState
 *   enforced | unknown, reasonCode plugin_hook_allowed | plugin_hook_blocked |
 *   plugin_hook_approval_required | plugin_hook_failed_open |
 *   plugin_hook_failed_closed.
 * - The plugin's job is to return EXPLICIT typed decisions so those records
 *   stay truthful, and to acknowledge an authority callback exposed to the
 *   plugin (ctx.receiptAuthority) exactly once per gated call.
 */

import type { ToolGateContext } from "./host-contract.ts";

export type PluginDecisionKind = "allow" | "block" | "continue-without-verdict";

export type HostDecisionVocabularyRecord = {
  outcome: "allowed" | "denied" | "unknown";
  coverageState: "enforced" | "unknown";
  reasonCode:
    | "plugin_hook_allowed"
    | "plugin_hook_blocked"
    | "plugin_hook_failed_open"
    | "plugin_hook_failed_closed";
};

/**
 * Map a plugin decision kind into the host's own decision-record vocabulary.
 * Our closed-mode outcomes must record as enforced/denied (never unknown);
 * the open-mode unscanned continue records truthfully as unknown/unknown
 * with the host's fail-open reason code.
 */
export function hostDecisionForPluginOutcome(
  decision: PluginDecisionKind
): HostDecisionVocabularyRecord {
  switch (decision) {
    case "block":
      return { outcome: "denied", coverageState: "enforced", reasonCode: "plugin_hook_blocked" };
    case "continue-without-verdict":
      return {
        outcome: "unknown",
        coverageState: "unknown",
        reasonCode: "plugin_hook_failed_open",
      };
    case "allow":
    default:
      return {
        outcome: "allowed",
        coverageState: "enforced",
        reasonCode: "plugin_hook_allowed",
      };
  }
}

/**
 * F104: any host-recorded unknown policy outcome surfaces as UNAUTHORISED /
 * denied in the plugin's own decision log and receipt surfaces - never as an
 * allow-equivalent.
 */
export function renderHostOutcomeForPluginEvidence(
  hostOutcome: "allowed" | "denied" | "unknown"
): "allowed" | "denied" {
  return hostOutcome === "allowed" ? "allowed" : "denied";
}

/**
 * Acknowledge an exposed admission-authority callback exactly once per gated
 * call. Absent on hosts that keep the receipt path host-internal (the
 * documented degradation: plugin-side evidence only, no host-recognised
 * decision record): a missing callback is a non-fatal, expected state.
 */
export function acknowledgeAuthority(ctx: ToolGateContext | undefined): boolean {
  const authority = ctx?.receiptAuthority;
  if (typeof authority !== "function") {
    return false;
  }
  try {
    authority();
    return true;
  } catch {
    // A failing host authority fence must not break the plugin's own
    // explicit decision path; the absence of a host record is logged by the
    // decision-log layer.
    return false;
  }
}
