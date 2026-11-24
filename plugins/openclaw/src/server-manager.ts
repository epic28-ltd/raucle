/**
 * Manages the lifecycle of the raucle Python REST server.
 *
 * Trust model (Q14 section 2): the manager holds a per-boot scan secret
 * (crypto.randomUUID, or an operator-configured scanSecret that the standalone
 * service receives via RAUCLE_PLUGIN_SCAN_SECRET). An already-answering service
 * on the port is adopted ONLY when it passes the secret-protected /identity
 * probe with a schema-strict raucle identity body; anything else is refused
 * and the manager spawns its own scanner with the secret in the environment.
 * Loopback binding is unchanged.
 */

import { createHash, randomUUID } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { validateIdentityBody, type RaucleIdentityBody } from "./scanner-client.ts";

const SCAN_SECRET_ENV_VAR = "RAUCLE_PLUGIN_SCAN_SECRET";

export type ManagerLogger = {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
};

export interface ServerManagerOptions {
  port: number;
  mode: string;
  rulesDir?: string;
  pythonPath?: string;
  /** Operator-configured scan secret; when absent a per-boot random secret is generated. */
  secret?: string;
  logger: ManagerLogger;
  /** Injectable fetch for tests (defaults to globalThis.fetch). */
  fetchFn?: typeof fetch;
  /** Injectable spawn for tests (defaults to node:child_process.spawn). */
  spawnFn?: typeof spawn;
  readiness?: { timeoutMs: number; intervalMs: number };
}

/** A named start() refusal so the plugin can fail loud and not silently run unscreened. */
export type ScannerNotReadyError = Error & { kind: "scanner-not-ready" };

export class ServerManager {
  private process: ChildProcess | null = null;
  private port: number;
  private mode: string;
  private rulesDir?: string;
  private pythonPath: string;
  private logger: ManagerLogger;
  private restarting = false;
  private stopped = false;
  private ready = false;
  private readonly _secret: string;
  private readonly fetchFn: typeof fetch;
  private readonly spawnFn: typeof spawn;
  private readonly readinessTimeoutMs: number;
  private readonly readinessIntervalMs: number;
  private adopted = false;

  constructor(opts: ServerManagerOptions) {
    this.port = opts.port;
    this.mode = opts.mode;
    this.rulesDir = opts.rulesDir;
    this.pythonPath = opts.pythonPath || "raucle";
    this.logger = opts.logger;
    this._secret = opts.secret && opts.secret.length > 0 ? opts.secret : randomUUID();
    this.fetchFn = opts.fetchFn ?? globalThis.fetch;
    this.spawnFn = opts.spawnFn ?? spawn;
    this.readinessTimeoutMs = opts.readiness?.timeoutMs ?? 15000;
    this.readinessIntervalMs = opts.readiness?.intervalMs ?? 500;
  }

  /** The per-boot scan secret fingerprint (never logged in full). */
  get secretFingerprint(): string {
    return `sha256:${secretFingerprint(this._secret)}`;
  }

  /** The raw secret, shared with the ScannerClient (plugin-internal use). */
  get secret(): string {
    return this._secret;
  }

  async start(): Promise<void> {
    if (this.ready) return;

    // Adoption: an answering service must PROVE raucle identity under the
    // secret. No proof -> refuse adoption and spawn our own scanner.
    const probe = await this.probeIdentity(adoptionProbeTimeoutMs);
    if (probe.ok) {
      this.adopted = true;
      this.ready = true;
      this.logger.info(
        `raucle scanner adopted on port ${this.port} (identity ${probe.body.version}, ` +
          `rules ${probe.body.rules_loaded}; secret-probe passed)`
      );
      return;
    }
    this.logger.warn(
      `raucle scanner adoption refused on port ${this.port} ` +
        `(reasonClass: ${probe.reasonClass}, detail: ${probe.detail}; ` +
        `a pre-existing service that does not answer the secret-protected ` +
        `identity probe is never adopted)`
    );

    this.spawnOwn();
    await this.waitForReady();
    this.ready = true;
  }

  private spawnOwn(): void {
    const isCliCommand = !this.pythonPath.includes("python");
    const args = isCliCommand
      ? ["serve", "--host", "127.0.0.1", "--port", String(this.port), "--mode", this.mode]
      : ["-m", "raucle", "serve", "--host", "127.0.0.1", "--port", String(this.port), "--mode", this.mode];

    if (this.rulesDir) {
      args.push("--rules-dir", this.rulesDir);
    }

    this.logger.info(
      `Starting raucle server on port ${this.port} (mode: ${this.mode}, ` +
        `secret ${this.secretFingerprint} via ${SCAN_SECRET_ENV_VAR})`
    );

    const childEnv: NodeJS.ProcessEnv = {
      ...process.env,
      [SCAN_SECRET_ENV_VAR]: this._secret,
    };

    this.process = this.spawnFn(this.pythonPath, args, {
      stdio: ["ignore", "pipe", "pipe"],
      detached: false,
      env: childEnv,
    });

    this.process.stdout?.on("data", (data: Buffer) => {
      const line = data?.toString?.()?.trim?.();
      if (line) this.logger.info(`[raucle] ${line}`);
    });

    this.process.stderr?.on("data", (data: Buffer) => {
      const line = data?.toString?.()?.trim?.();
      if (line) this.logger.warn(`[raucle] ${line}`);
    });

    this.process.on("exit", (code) => {
      this.logger.warn(`raucle server exited with code ${code}`);
      this.process = null;
      this.ready = false;
      if (!this.stopped && !this.restarting) {
        this.restarting = true;
        setTimeout(() => {
          this.restarting = false;
          if (!this.stopped) {
            this.logger.info("Restarting raucle server...");
            this.start().catch((e) => this.logger.error(`Failed to restart raucle: ${e}`));
          }
        }, 10000);
      }
    });
  }

  private async probeIdentity(
    timeoutMs: number
  ): Promise<
    | { ok: true; body: RaucleIdentityBody }
    | { ok: false; reasonClass: string; detail: string }
  > {
    try {
      const resp = await this.fetchFn(`http://127.0.0.1:${this.port}/identity`, {
        headers: { "x-raucle-scan-token": this._secret },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!resp.ok) {
        return { ok: false, reasonClass: `http-${resp.status}`, detail: resp.statusText };
      }
      const raw: unknown = await resp.json();
      const verdict = validateIdentityBody(raw);
      if (!verdict.ok) {
        return { ok: false, reasonClass: "identity-mismatch", detail: verdict.detail };
      }
      return { ok: true, body: verdict.body };
    } catch (e) {
      const detail = e instanceof Error ? e.message : String(e);
      return { ok: false, reasonClass: "connection-refused", detail };
    }
  }

  /** Bounded secret-protected readiness wait; refuses with a NAMED error. */
  private async waitForReady(): Promise<void> {
    const startTime = Date.now();
    while (Date.now() - startTime < this.readinessTimeoutMs) {
      const probe = await this.probeIdentity(2000);
      if (probe.ok) {
        this.logger.info(
          `raucle server ready on port ${this.port} ` +
            `(identity ${probe.body.version}, secret probe passed)`
        );
        return;
      }
      await new Promise((r) => setTimeout(r, this.readinessIntervalMs));
    }
    const err = new Error(
      `raucle scanner on port ${this.port} did not prove its identity within ` +
        `${this.readinessTimeoutMs}ms (secret ${this.secretFingerprint})`
    ) as ScannerNotReadyError;
    err.kind = "scanner-not-ready";
    throw err;
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.process) {
      this.logger.info("Stopping raucle server");
      this.process.kill("SIGTERM");
      this.process = null;
    }
    this.ready = false;
    this.adopted = false;
  }

  /** True when the plugin has a proven, secret-verified scanner to call. */
  get isRunning(): boolean {
    if (this.adopted) return true;
    return this.process !== null && !this.process.killed;
  }
}

/** Adoption probe budget: short, bounded, only the identity proof counts. */
const adoptionProbeTimeoutMs = 1500;

/** First 16 hex chars of the secret digest; used to verify the same secret both sides. */
function secretFingerprint(secret: string): string {
  return createHash("sha256").update(secret).digest("hex").slice(0, 16);
}
