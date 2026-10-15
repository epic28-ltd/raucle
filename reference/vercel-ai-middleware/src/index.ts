/**
 * raucle middleware for the Vercel AI SDK (`ai` ≥ 4).
 *
 * Gates every tool call an AI SDK agent makes against a capability
 * policy and emits a signed Raucle Provenance Receipt
 * (https://raucle.com/spec/provenance/v1) for each ALLOW/DENY decision.
 *
 * The integration point is the tool's `execute` function — the only
 * path from the model's intent to a real side effect, which is exactly
 * where the gate belongs (matching raucle's threat model: block the
 * call before the effect, not the text after it).
 *
 *   import { createRaucleSession } from "@raucle/vercel-ai-middleware";
 *   const raucle = await createRaucleSession({ issuer, policies });
 *   const result = await generateText({
 *     model, prompt,
 *     tools: raucle.gateTools({ transferFunds, lookupBalance }),
 *   });
 *
 * Receipts are produced via the TypeScript reference implementation of
 * the receipt spec, so their content-addressed IDs are byte-identical
 * to receipts emitted by the Python/Go/Rust/C# implementations.
 */

import { webcrypto } from "node:crypto";
import { emit, canonicalString, type Receipt } from "@raucle/provenance";

const subtle = webcrypto.subtle;

// ── Constraint policy (mirrors the capability constraint kinds) ─────

export interface ConstraintPolicy {
  allowedValues?: Record<string, (string | number)[]>;
  forbiddenValues?: Record<string, (string | number)[]>;
  maxValue?: Record<string, number>;
  minValue?: Record<string, number>;
  requiredPresent?: string[];
  forbiddenFieldCombinations?: [string, string][];
}

export type GateVerdict = { decision: "ALLOW" | "BLOCK"; reason?: string };

/** Evaluate a constraint policy against tool-call arguments. */
export function evaluatePolicy(
  policy: ConstraintPolicy | undefined,
  args: Record<string, unknown>,
): GateVerdict {
  if (!policy) return { decision: "ALLOW" };

  const required = checkRequiredPresent(policy, args);
  if (required) return required;
  const allowed = checkAllowedValues(policy, args);
  if (allowed) return allowed;
  const forbidden = checkForbiddenValues(policy, args);
  if (forbidden) return forbidden;
  const max = checkMaxValue(policy, args);
  if (max) return max;
  const min = checkMinValue(policy, args);
  if (min) return min;
  const combos = checkForbiddenCombos(policy, args);
  if (combos) return combos;
  return { decision: "ALLOW" };
}

function checkRequiredPresent(
  policy: ConstraintPolicy,
  args: Record<string, unknown>,
): GateVerdict | undefined {
  for (const f of policy.requiredPresent ?? []) {
    if (args[f] === undefined || args[f] === null) {
      return { decision: "BLOCK", reason: `required field '${f}' missing` };
    }
  }
  return undefined;
}

function checkAllowedValues(
  policy: ConstraintPolicy,
  args: Record<string, unknown>,
): GateVerdict | undefined {
  for (const [f, allowed] of Object.entries(policy.allowedValues ?? {})) {
    if (f in args && !allowed.includes(args[f] as string | number)) {
      return { decision: "BLOCK", reason: `${f}=${String(args[f])} not in allowed set` };
    }
  }
  return undefined;
}

function checkForbiddenValues(
  policy: ConstraintPolicy,
  args: Record<string, unknown>,
): GateVerdict | undefined {
  for (const [f, forbidden] of Object.entries(policy.forbiddenValues ?? {})) {
    if (f in args && forbidden.includes(args[f] as string | number)) {
      return { decision: "BLOCK", reason: `${f}=${String(args[f])} is forbidden` };
    }
  }
  return undefined;
}

function checkMaxValue(
  policy: ConstraintPolicy,
  args: Record<string, unknown>,
): GateVerdict | undefined {
  for (const [f, max] of Object.entries(policy.maxValue ?? {})) {
    if (f in args && typeof args[f] === "number" && args[f] > max) {
      return { decision: "BLOCK", reason: `${f}=${String(args[f])} exceeds max ${max}` };
    }
  }
  return undefined;
}

function checkMinValue(
  policy: ConstraintPolicy,
  args: Record<string, unknown>,
): GateVerdict | undefined {
  for (const [f, min] of Object.entries(policy.minValue ?? {})) {
    if (f in args && typeof args[f] === "number" && args[f] < min) {
      return { decision: "BLOCK", reason: `${f}=${String(args[f])} below min ${min}` };
    }
  }
  return undefined;
}

function checkForbiddenCombos(
  policy: ConstraintPolicy,
  args: Record<string, unknown>,
): GateVerdict | undefined {
  for (const [a, b] of policy.forbiddenFieldCombinations ?? []) {
    if (a in args && b in args) {
      return { decision: "BLOCK", reason: `fields '${a}' and '${b}' must not co-occur` };
    }
  }
  return undefined;
}

// ── Vercel AI SDK tool shape (structural — no hard dep on `ai`) ─────

export interface VercelTool {
  description?: string;
  parameters?: unknown;
  execute?: (args: any, options?: any) => unknown;
}

export class RauclePolicyDenied extends Error {
  constructor(public tool: string, public reason: string) {
    super(`raucle denied tool '${tool}': ${reason}`);
    this.name = "RauclePolicyDenied";
  }
}

export interface Issuer {
  privateKey: webcrypto.CryptoKey;
  iss: string;
  agentId: string; // matches ^agent:[a-z0-9][a-z0-9_\-./]{0,127}$
  keyId: string;
}

export interface RaucleOptions {
  issuer: Issuer;
  /** Per-tool constraint policies for the built-in evaluator. */
  policies?: Record<string, ConstraintPolicy>;
  /** Custom gate (e.g. backed by an HTTP call to a hosted gate). Overrides `policies`. */
  gate?: (tool: string, args: Record<string, unknown>) => GateVerdict | Promise<GateVerdict>;
  /** Sink for every emitted receipt (stream to a SIEM, append to a log, …). */
  onReceipt?: (receipt: Receipt) => void | Promise<void>;
  /** On BLOCK: throw (default) or return a structured error the model sees. */
  failClosed?: boolean;
  /** Label for the session-root receipt (the user task). */
  sessionLabel?: string;
}

async function sha256Hex(s: string): Promise<string> {
  const d = await subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Buffer.from(d).toString("hex");
}

export interface RaucleSession {
  /** The session-root (user_input) receipt id every decision chains to. */
  rootId: string;
  /** Wrap a record of Vercel AI SDK tools so each is gated + receipted. */
  gateTools<T extends Record<string, VercelTool>>(tools: T): T;
}

/**
 * Create a gating session. Emits a `user_input` root receipt for the
 * session, then chains a signed `guardrail_scan` receipt to it for
 * every tool call the agent attempts.
 */
export async function createRaucleSession(opts: RaucleOptions): Promise<RaucleSession> {
  const { issuer } = opts;
  const failClosed = opts.failClosed ?? true;
  const rootHash = await sha256Hex(opts.sessionLabel ?? "session");

  const root = await emit(
    {
      iss: issuer.iss,
      iat: Math.floor(Date.now() / 1000),
      agent_id: issuer.agentId,
      agent_key_id: issuer.keyId,
      operation: "user_input",
      parents: [],
      input_hash: rootHash,
      output_hash: rootHash,
      taint: ["untrusted_user"],
    },
    issuer.privateKey,
  );
  await opts.onReceipt?.(root);

  const gateTools = <T extends Record<string, VercelTool>>(tools: T): T => {
    const out: Record<string, VercelTool> = {};
    for (const [name, tool] of Object.entries(tools)) {
      const original = tool.execute;
      out[name] = {
        ...tool,
        execute: async (args: Record<string, unknown>, options?: unknown) => {
          const verdict = opts.gate
            ? await opts.gate(name, args)
            : evaluatePolicy(opts.policies?.[name], args);

          const argsHash = await sha256Hex(canonicalString(args ?? {}));
          const rulesetHash = await sha256Hex(
            canonicalString((opts.policies?.[name] as unknown) ?? { gate: "custom" }),
          );
          const receipt = await emit(
            {
              iss: issuer.iss,
              iat: Math.floor(Date.now() / 1000),
              agent_id: issuer.agentId,
              agent_key_id: issuer.keyId,
              operation: "guardrail_scan",
              parents: [root.id],
              input_hash: argsHash,
              output_hash: argsHash,
              taint: ["untrusted_user"],
              ruleset_hash: rulesetHash,
              guardrail_verdict: verdict.decision === "BLOCK" ? "MALICIOUS" : "CLEAN",
              tool: name,
            },
            issuer.privateKey,
          );
          await opts.onReceipt?.(receipt);

          if (verdict.decision === "BLOCK") {
            const reason = verdict.reason ?? "policy violation";
            if (failClosed) throw new RauclePolicyDenied(name, reason);
            return { error: `raucle denied: ${reason}`, receipt_id: receipt.id };
          }
          if (!original) return undefined;
          return original(args, options);
        },
      };
    }
    return out as T;
  };

  return { rootId: root.id, gateTools };
}
