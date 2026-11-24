/**
 * HTTP client for the raucle REST API.
 *
 * Communicates with a locally-running raucle server (started as a background
 * service by the plugin). Every request carries the per-boot scan secret in
 * the X-Raucle-Scan-Token header: the plugin never talks to an unauthenticated
 * local scanner (Q14 section 2). The identity probe is the secret-protected
 * trust proof used by the ServerManager adoption path.
 */

export interface ScanRequest {
  prompt: string;
  mode?: string;
}

export interface ScanResult {
  verdict: string;
  confidence: number;
  injection_detected: boolean;
  categories: string[];
  attack_technique: string;
  matched_rules: string[];
  action: string;
  notes: string[];
  scan_time_ms?: number;
}

export interface HealthResponse {
  status: string;
  version: string;
  mode: string;
  rules_loaded: number;
  auth_enabled: boolean;
}

/** Named scanner failure reason classes (Q14 section 1 advisory vocabulary). */
export type ScanReasonClass =
  | "timeout"
  | "connection-refused"
  | "malformed-response"
  | "http-500"
  | "auth-refused"
  | "http-error"
  | "process-dead"
  | "secret-missing"
  | "identity-mismatch"
  | "unknown";

/**
 * Map an arbitrary scanner failure to the named reason class for the plugin's
 * advisory log and explicit block decisions. The classes mirror the review's
 * required set: timeout, connection-refused, malformed-response, http-500,
 * process-dead.
 */
export function classifyScanError(err: unknown): ScanReasonClass {
  const e = err as (Error & { code?: string; status?: number }) | null | undefined;
  if (!e) return "unknown";
  const name = typeof e.name === "string" ? e.name : "";
  const message = typeof e.message === "string" ? e.message : "";
  if (name === "TimeoutError" || name === "AbortError" || /aborted|timed?\s?out/i.test(message)) {
    return "timeout";
  }
  if (e.status === 401 || e.status === 403) return "auth-refused";
  if (typeof e.status === "number" && e.status >= 500) return "http-500";
  if (typeof e.status === "number") return "http-error";
  const code = typeof e.code === "string" ? e.code : "";
  if (code === "ECONNREFUSED" || code === "ENOTFOUND" || code === "ECONNRESET" || code === "EAI_AGAIN") {
    return "connection-refused";
  }
  if (message.includes("ECONNREFUSED") || message.includes("ENOTFOUND")) {
    return "connection-refused";
  }
  if (e instanceof SyntaxError && /JSON/i.test(message)) {
    return "malformed-response";
  }
  if (/malformed response body/i.test(message)) {
    // _post() rewraps JSON-parse failures as IdentityMismatchError; the wire
    // condition is still a malformed response, not an identity failure.
    return "malformed-response";
  }
  if (/process-dead|process exited/i.test(message)) {
    return "process-dead";
  }
  if (/Invalid API key|Invalid scan token|Missing .*header/i.test(message)) {
    return "auth-refused";
  }
  return "unknown";
}

/**
 * Schema-strict raucle identity body returned by GET /identity (the
 * secret-protected trust probe). Extra or missing fields, wrong types or a
 * non-raucle kind are REJECTED: adoption never trusts an unknown body shape.
 */
export interface RaucleIdentityBody {
  kind: "raucle";
  status: string;
  version: string;
  mode: string;
  rules_loaded: number;
  scan_secret_required: boolean;
}

export type IdentityValidation =
  | { ok: true; body: RaucleIdentityBody }
  | { ok: false; reasonClass: "identity-mismatch"; detail: string };

/** Schema-strict validation of an /identity response body. */
export function validateIdentityBody(raw: unknown): IdentityValidation {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return {
      ok: false,
      reasonClass: "identity-mismatch",
      detail: "identity body is not a JSON object",
    };
  }
  const b = raw as Record<string, unknown>;
  if (b.kind !== "raucle") {
    return {
      ok: false,
      reasonClass: "identity-mismatch",
      detail: `identity body kind is ${JSON.stringify(b.kind)}, not the raucle scanner`,
    };
  }
  if (b.status !== "ok") {
    return {
      ok: false,
      reasonClass: "identity-mismatch",
      detail: `identity body status is ${JSON.stringify(b.status)}`,
    };
  }
  if (typeof b.version !== "string" || !b.version) {
    return {
      ok: false,
      reasonClass: "identity-mismatch",
      detail: "identity body version is not a string",
    };
  }
  if (typeof b.mode !== "string") {
    return {
      ok: false,
      reasonClass: "identity-mismatch",
      detail: "identity body mode is not a string",
    };
  }
  if (typeof b.rules_loaded !== "number") {
    return {
      ok: false,
      reasonClass: "identity-mismatch",
      detail: "identity body rules_loaded is not a number",
    };
  }
  // D1 (PR #322 verdict remedy): a boolean-only check here accepted
  // scan_secret_required:false, letting the manager adopt an UNAUTHENTICATED
  // raucle server (one started without RAUCLE_PLUGIN_SCAN_SECRET answers 200
  // on /identity with a valid raucle body). Adoption requires the ARMED flag:
  // the body must carry scan_secret_required:true, which a server only emits
  // when it enforces the secret-protected probe the adoption round-trip used.
  if (b.scan_secret_required !== true) {
    return {
      ok: false,
      reasonClass: "identity-mismatch",
      detail:
        `identity body scan_secret_required is ${JSON.stringify(b.scan_secret_required)}; ` +
        `an unarmed raucle server (one not enforcing the scan secret) must never be adopted`,
    };
  }
  return {
    ok: true,
    body: {
      kind: "raucle",
      status: b.status,
      version: b.version,
      mode: b.mode,
      rules_loaded: b.rules_loaded,
      scan_secret_required: b.scan_secret_required,
    },
  };
}

/** A scanner error that carries its HTTP status (for classification). */
export class ScannerHttpError extends Error {
  status: number;
  reasonClass: ScanReasonClass;

  constructor(status: number, path: string, statusText: string) {
    super(`raucle ${path} failed: ${status} ${statusText}`);
    this.name = "ScannerHttpError";
    this.status = status;
    this.reasonClass = classifyScanError(this);
  }
}

/** Rejection raised when a body fails the schema-strict identity check. */
export class IdentityMismatchError extends Error {
  reasonClass: ScanReasonClass = "identity-mismatch";
  detail: string;

  constructor(detail: string) {
    super(`raucle identity mismatch: ${detail}`);
    this.name = "IdentityMismatchError";
    this.detail = detail;
  }
}

export type ScannerClientOptions = {
  /** The per-boot scan secret; an empty value is refused (fail-closed). */
  secret: string;
  timeoutMs?: number;
};

export const SCAN_TOKEN_HEADER = "x-raucle-scan-token";

export class ScannerClient {
  private baseUrl: string;
  private timeout: number;
  private secret: string;

  constructor(port: number = 8900, opts: ScannerClientOptions = { secret: "" }) {
    const secret = opts.secret ?? "";
    if (!secret) {
      const err = new Error(
        "raucle scanner client requires a non-empty scan secret (per-boot or operator-configured)"
      ) as Error & { kind?: string };
      err.kind = "secret-missing";
      throw err;
    }
    this.baseUrl = `http://127.0.0.1:${port}`;
    this.timeout = opts.timeoutMs ?? 10000;
    this.secret = secret;
  }

  async scan(prompt: string, mode?: string, opts?: { signal?: AbortSignal }): Promise<ScanResult> {
    const body: ScanRequest = { prompt };
    if (mode) body.mode = mode;
    return this._post("/scan", body, opts);
  }

  async scanOutput(
    output: string,
    originalPrompt?: string,
    mode?: string,
    opts?: { signal?: AbortSignal }
  ): Promise<ScanResult> {
    const body: Record<string, string> = { output };
    if (originalPrompt) body.original_prompt = originalPrompt;
    if (mode) body.mode = mode;
    return this._post("/scan/output", body, opts);
  }

  async scanToolCall(
    toolName: string,
    args: Record<string, unknown>,
    mode?: string,
    opts?: { signal?: AbortSignal }
  ): Promise<ScanResult> {
    const body: Record<string, unknown> = { tool_name: toolName, arguments: args };
    if (mode) body.mode = mode;
    return this._post("/scan/tool", body, opts);
  }

  private async _post(
    path: string,
    body: unknown,
    opts?: { signal?: AbortSignal }
  ): Promise<ScanResult> {
    // The deadline signal arrives alongside our own per-request timeout.
    const signals: AbortSignal[] = [AbortSignal.timeout(this.timeout)];
    if (opts?.signal) signals.push(opts.signal);
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", [SCAN_TOKEN_HEADER]: this.secret },
      body: JSON.stringify(body),
      signal: signals.length > 1 ? AbortSignal.any(signals) : signals[0],
    });

    if (!resp.ok) {
      throw new ScannerHttpError(resp.status, path, resp.statusText);
    }

    try {
      return (await resp.json()) as ScanResult;
    } catch {
      throw new IdentityMismatchError(`${path} returned a malformed response body`);
    }
  }

  /** Secret-protected identity/health probe with schema-strict validation. */
  async identityProbe(): Promise<RaucleIdentityBody> {
    const resp = await fetch(`${this.baseUrl}/identity`, {
      headers: { [SCAN_TOKEN_HEADER]: this.secret },
      signal: AbortSignal.timeout(this.timeout),
    });
    if (!resp.ok) {
      throw new ScannerHttpError(resp.status, "/identity", resp.statusText);
    }
    let raw: unknown;
    try {
      raw = await resp.json();
    } catch {
      throw new IdentityMismatchError("/identity returned a malformed response body");
    }
    const verdict = validateIdentityBody(raw);
    if (!verdict.ok) {
      throw new IdentityMismatchError(verdict.detail);
    }
    return verdict.body;
  }

  async health(): Promise<HealthResponse> {
    const resp = await fetch(`${this.baseUrl}/health`, {
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!resp.ok) {
      throw new ScannerHttpError(resp.status, "/health", resp.statusText);
    }

    try {
      return (await resp.json()) as HealthResponse;
    } catch {
      throw new IdentityMismatchError("/health returned a malformed response body");
    }
  }

  async isReady(): Promise<boolean> {
    try {
      await this.identityProbe();
      return true;
    } catch {
      return false;
    }
  }
}
