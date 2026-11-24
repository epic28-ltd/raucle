/**
 * Plugin-side bounded decision log (Q14 2b).
 *
 * The plugin is a DETECTION integration: these entries are plugin-local
 * evidence, NOT capability receipts (the README's claim stands). Every gated
 * call records exactly one decision entry whose receipt binds to the ACTUAL
 * final outcome, with the scanner verdict and ruleset identity kept in
 * SEPARATE fields from any authorisation evidence (finding 101) and with any
 * unknowable outcome rendered denied/unknown - never as allow-equivalent
 * (F104). The buffer is bounded: oldest entries evicted past maxEntries.
 */

export type DecisionOutcome = "allowed" | "denied" | "unknown";
export type DecisionCoverage = "enforced" | "unknown";
export type DecisionReasonCode =
  | "plugin_hook_allowed"
  | "plugin_hook_blocked"
  | "plugin_hook_approval_required"
  | "plugin_hook_failed_open"
  | "plugin_hook_failed_closed";

export type ScannerEvidence =
  | {
      verdict: string;
      confidence: number;
      matchedRules: string[];
      categories: string[];
    }
  | { unavailable: true; reasonClass: string };

export type DecisionReceipt = {
  /** A receipt is issued only when the call's final state was actually known here. */
  issued: boolean;
  bound: "allowed" | "denied" | "none";
};

export type DecisionLogEntry = {
  ts: number;
  hook: string;
  toolName?: string;
  agentId?: string;
  /** Authorisation evidence (host vocabulary). Never carries scanner data. */
  outcome: DecisionOutcome;
  coverageState: DecisionCoverage;
  reasonCode: DecisionReasonCode;
  /** Whether the exposed admission-authority callback was acknowledged. */
  authorityAcknowledged: boolean;
  /** Scanner evidence (detection family). Never carries authorisation data. */
  scanner?: ScannerEvidence;
  receipt: DecisionReceipt;
  /** Marks a scan result that arrived after the outcome was sealed. */
  discarded?: "late-arrival-after-seal";
};

export class DecisionLog {
  private readonly maxEntries: number;
  private buffer: DecisionLogEntry[] = [];

  constructor(maxEntries = 256) {
    this.maxEntries = Math.max(1, maxEntries);
  }

  record(entry: DecisionLogEntry): DecisionLogEntry {
    this.buffer.push(entry);
    if (this.buffer.length > this.maxEntries) {
      this.buffer = this.buffer.slice(-this.maxEntries);
    }
    return entry;
  }

  entries(): DecisionLogEntry[] {
    return this.buffer.slice();
  }

  get size(): number {
    return this.buffer.length;
  }
}
