/**
 * Raucle ⇄ A2A binding — reference helper.
 *
 * Implements the profile in `standards/a2a/README.md`: declare the
 * Raucle extension on an A2A Agent Card, emit a signed `agent_handoff`
 * provenance receipt when invoking another agent's skill, attach it to
 * the A2A Message, and verify a received hand-off offline against the
 * caller's published issuer key.
 *
 * Built on the TypeScript receipt reference implementation, so the
 * receipts are byte-identical to those produced by the Python/Go/Rust/C#
 * implementations and verifiable by any of them.
 */

import { webcrypto } from "node:crypto";
import { emit, verify, canonicalString, type Receipt } from "@raucle/provenance";

const subtle = webcrypto.subtle;

export const RAUCLE_A2A_EXTENSION_URI = "https://raucle.com/spec/a2a/provenance/v1";

// ── Agent Card declaration ─────────────────────────────────────────

export interface AgentExtension {
  uri: string;
  description: string;
  version: string;
  required: boolean;
}

export function raucleAgentCardExtension(): AgentExtension {
  return {
    uri: RAUCLE_A2A_EXTENSION_URI,
    description:
      "Signed provenance receipts + per-skill capability authorisation for inter-agent calls.",
    version: "1",
    required: false,
  };
}

export interface IssuerPublic {
  iss: string;
  keyId: string;
  /** Raw Ed25519 public key, base64. */
  publicKey: string;
}

export interface RaucleCardMetadata {
  receipt_version: "1";
  issuer: { iss: string; key_id: string; public_key: string };
  skill_capabilities?: Record<string, string>;
}

/** Build the Agent Card `metadata` entry keyed by the extension URI. */
export function raucleCardMetadata(
  issuer: IssuerPublic,
  skillCapabilities?: Record<string, string>,
): Record<string, RaucleCardMetadata> {
  return {
    [RAUCLE_A2A_EXTENSION_URI]: {
      receipt_version: "1",
      issuer: { iss: issuer.iss, key_id: issuer.keyId, public_key: issuer.publicKey },
      ...(skillCapabilities ? { skill_capabilities: skillCapabilities } : {}),
    },
  };
}

// ── Emit a hand-off receipt ────────────────────────────────────────

export interface IssuerPrivate {
  privateKey: webcrypto.CryptoKey;
  iss: string;
  agentId: string;
  keyId: string;
}

async function sha256Hex(s: string): Promise<string> {
  const d = await subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Buffer.from(d).toString("hex");
}

/** Export a raw Ed25519 public key as base64 for the Agent Card. */
export async function exportPublicKeyB64(publicKey: webcrypto.CryptoKey): Promise<string> {
  const raw = new Uint8Array(await subtle.exportKey("raw", publicKey));
  return Buffer.from(raw).toString("base64");
}

export interface HandoffInput {
  issuer: IssuerPrivate;
  /** The callee skill id being invoked. */
  skill: string;
  /** The callee agent's URL (A2A Agent Card `url`). */
  targetUrl: string;
  /** The skill input (canonicalised + hashed into the receipt). */
  input: unknown;
  /** Parent receipt ids — the caller's task/session root (chain context). */
  parents: string[];
}

/** Emit a signed `agent_handoff` provenance receipt for an A2A skill call. */
export async function emitHandoff(opts: HandoffInput): Promise<Receipt> {
  const h = await sha256Hex(canonicalString(opts.input ?? {}));
  return emit(
    {
      iss: opts.issuer.iss,
      iat: Math.floor(Date.now() / 1000),
      agent_id: opts.issuer.agentId,
      agent_key_id: opts.issuer.keyId,
      operation: "agent_handoff",
      parents: opts.parents,
      input_hash: h,
      output_hash: h,
      taint: ["untrusted_user"],
      x_a2a_skill: opts.skill,
      x_a2a_target: opts.targetUrl,
    },
    opts.issuer.privateKey,
  );
}

/** Attach a hand-off receipt to an outgoing A2A Message. */
export function attachToMessage<M extends Record<string, unknown>>(message: M, receipt: Receipt): M {
  const exts = new Set([...(((message.extensions as string[]) ?? [])), RAUCLE_A2A_EXTENSION_URI]);
  // Spreading undefined is a no-op; no `?? {}` fallback needed.
  const metadata = { ...message.metadata };
  metadata[RAUCLE_A2A_EXTENSION_URI] = { receipt: receipt.jws };
  return { ...message, extensions: [...exts], metadata };
}

// ── Verify a received hand-off ─────────────────────────────────────

export interface VerifyResult {
  ok: boolean;
  reason?: string;
  skill?: string;
  receipt?: Receipt;
}

interface AgentCardLike {
  url: string;
  skills?: { id: string }[];
  metadata?: Record<string, unknown>;
}

function importPub(b64: string): Promise<webcrypto.CryptoKey> {
  const raw = new Uint8Array(Buffer.from(b64, "base64"));
  return subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
}

/**
 * Verify a hand-off receipt (Compact JWS) against the *caller's* Agent
 * Card, and confirm it authorises this call on *this* (callee) card.
 *
 * @param receiptJws  the receipt extracted from the inbound Message
 * @param callerCard  the calling agent's Agent Card (carries the issuer key)
 * @param calleeCard  this agent's Agent Card (target URL + advertised skills)
 */
export async function verifyHandoff(
  receiptJws: string,
  callerCard: AgentCardLike,
  calleeCard: AgentCardLike,
): Promise<VerifyResult> {
  const meta = callerCard.metadata?.[RAUCLE_A2A_EXTENSION_URI] as RaucleCardMetadata | undefined;
  if (!meta?.issuer?.public_key) {
    return { ok: false, reason: "caller card has no raucle issuer key" };
  }
  let receipt: Receipt;
  try {
    receipt = await verify(receiptJws, await importPub(meta.issuer.public_key));
  } catch (e) {
    return { ok: false, reason: `receipt failed verification: ${(e as Error).message}` };
  }
  const p: Record<string, unknown> = receipt.payload;
  if (p.operation !== "agent_handoff") {
    return { ok: false, reason: `operation is ${String(p.operation)}, expected agent_handoff` };
  }
  if (p.x_a2a_target !== calleeCard.url) {
    return { ok: false, reason: `receipt target ${String(p.x_a2a_target)} != this agent ${calleeCard.url}` };
  }
  const skill = p.x_a2a_skill as string | undefined;
  const advertised = new Set((calleeCard.skills ?? []).map((s) => s.id));
  if (!skill || !advertised.has(skill)) {
    return { ok: false, reason: `skill '${String(skill)}' is not advertised by this agent` };
  }
  // Optional capability-envelope check: if the callee binds this skill to
  // a proven capability hash, require the receipt to cite it.
  const calleeMeta = calleeCard.metadata?.[RAUCLE_A2A_EXTENSION_URI] as RaucleCardMetadata | undefined;
  const requiredCap = calleeMeta?.skill_capabilities?.[skill];
  if (requiredCap && (p as Record<string, unknown>).x_capability_proof_hash !== requiredCap) {
    return { ok: false, reason: `skill '${skill}' requires capability ${requiredCap}; receipt does not cite it` };
  }
  return { ok: true, skill, receipt };
}
