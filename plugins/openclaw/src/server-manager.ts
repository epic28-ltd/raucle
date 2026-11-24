/**
 * Manages the lifecycle of the raucle Python REST server.
 *
 * Trust model (Q14 section 2): the manager holds a per-boot scan secret
 * (crypto.randomUUID, or an operator-configured scanSecret that the standalone
 * service receives via RAUCLE_PLUGIN_SCAN_SECRET). An already-answering service
 * on the port is adopted ONLY when it passes the secret-protected /identity
 * probe with a schema-strict raucle identity body that carries
 * scan_secret_required:true (the ARMED flag; PR #322 verdict D1): an armed
 * server proves the round-trip - it accepted our token. Anything else is
 * refused and the manager spawns its own scanner with the secret in the
 * environment. Spawn failures respawn on a bounded backoff ladder and give up
 * with a named advisory (PR #322 verdict D2) instead of re-entering an
 * EADDRINUSE restart loop forever. Loopback binding is unchanged.
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
  /**
   * Respawn policy overrides (principally for tests). PR #322 verdict D2: the
   * exit-restart loop ran every 10s forever, so an adoption refusal against an
   * occupied port caused a permanent EADDRINUSE lockout. Defaults: 10s base
   * delay doubling per consecutive round, capped; `maxAttempts` caps the
   * recovery respawns, and the failed spawn AFTER those trips the named
   * give-up advisory: `maxAttempts + 1` consecutive spawn rounds in total
   * never proved identity (the advisory reports that observed exit count).
   */
  respawn?: { baseDelayMs?: number; maxDelayMs?: number; maxAttempts?: number };
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
  private readonly respawnBaseDelayMs: number;
  private readonly respawnMaxDelayMs: number;
  private readonly respawnMaxAttempts: number;
  private adopted = false;
  /** Consecutive spawn rounds that exited without proving identity. */
  private respawnRounds = 0;
  /** True once the respawn ladder gave up (named advisory logged). */
  private respawnAbandoned = false;
  /** The last observed spawn exit code (context for the refusal reason). */
  private lastExitCode: number | null = null;

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
    this.respawnBaseDelayMs = opts.respawn?.baseDelayMs ?? RESPAWN_BASE_DELAY_MS;
    this.respawnMaxDelayMs = opts.respawn?.maxDelayMs ?? RESPAWN_MAX_DELAY_MS;
    this.respawnMaxAttempts = opts.respawn?.maxAttempts ?? RESPAWN_MAX_ATTEMPTS;
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
      this.respawnRounds = 0;
      this.respawnAbandoned = false;
      this.lastExitCode = null;
      this.logger.info(
        `raucle scanner adopted on port ${this.port} (identity ${probe.body.version}, ` +
          `rules ${probe.body.rules_loaded}; secret-protected identity probe passed with ` +
          `scan_secret_required:true)`
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
      this.lastExitCode = typeof code === "number" ? code : null;
      // D2 (PR #322 verdict remedy): respawn on a bounded BACKOFF ladder and
      // give up when a failed spawn lands after maxAttempts recovery respawns
      // (maxAttempts + 1 consecutive failed spawn rounds) with a NAMED
      // advisory - an adoption refusal against an occupied port must not
      // re-enter an EADDRINUSE restart loop every few seconds forever.
      if (!this.stopped && !this.restarting) {
        this.respawnRounds += 1;
        if (this.respawnRounds > this.respawnMaxAttempts) {
          this.respawnAbandoned = true;
          this.logger.error(
            `[raucle] SCANNER RESPAWN ABANDONED (reasonClass=spawn-give-up): the raucle scanner ` +
              `on port ${this.port} exited ${this.respawnMaxAttempts + 1} times in a row without ` +
              `proving its identity (last exit code ${code}; most commonly the port is occupied ` +
              `by a service the adoption probe refused). Free the port or align the ` +
              `RAUCLE_PLUGIN_SCAN_SECRET; gated calls stay blocked until the scanner proves itself.`
          );
          return;
        }
        const delay = Math.min(
          this.respawnBaseDelayMs * 2 ** (this.respawnRounds - 1),
          this.respawnMaxDelayMs
        );
        this.restarting = true;
        setTimeout(() => {
          this.restarting = false;
          if (!this.stopped) {
            this.logger.info(
              `Restarting raucle server after ${delay}ms backoff ` +
                `(respawn round ${this.respawnRounds}/${this.respawnMaxAttempts})...`
            );
            this.start().catch((e) => this.logger.error(`Failed to restart raucle: ${e}`));
          }
        }, delay);
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
      // D2: the child dying while we poll IS the adoption-refusal lockout
      // shape; fail fast (the exit handler owns the bounded respawn ladder)
      // instead of polling a dead listener for the full budget.
      if (this.process === null) {
        break;
      }
      const probe = await this.probeIdentity(2000);
      if (probe.ok) {
        this.logger.info(
          `raucle server ready on port ${this.port} ` +
            `(identity ${probe.body.version}, secret probe passed)`
        );
        this.respawnRounds = 0;
        this.respawnAbandoned = false;
        this.lastExitCode = null;
        return;
      }
      await new Promise((r) => setTimeout(r, this.readinessIntervalMs));
    }
    const detail =
      this.process === null && !this.adopted
        ? `the spawned scanner exited (exit code ${this.lastExitCode ?? "unknown"}) before proving ` +
            `its identity; most commonly the port is occupied by a service the adoption probe ` +
            `refused - the manager respawns on a bounded backoff and gives up by name`
        : `did not prove its identity within ${this.readinessTimeoutMs}ms`;
    const err = new Error(
      `raucle scanner on port ${this.port} ${detail} (secret ${this.secretFingerprint})`
    ) as ScannerNotReadyError;
    err.kind = "scanner-not-ready";
    throw err;
  }

  /** True once the respawn ladder exhausted and gave up with the named advisory. */
  get gaveUpRespawning(): boolean {
    return this.respawnAbandoned;
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

/** D2 respawn ladder defaults: 10s base delay, 60s cap, give up after 5 failed rounds. */
const RESPAWN_BASE_DELAY_MS = 10000;
const RESPAWN_MAX_DELAY_MS = 60000;
const RESPAWN_MAX_ATTEMPTS = 5;

/** First 16 hex chars of the secret digest; used to verify the same secret both sides. */
function secretFingerprint(secret: string): string {
  return createHash("sha256").update(secret).digest("hex").slice(0, 16);
}
