/**
 * Shared in-memory OpenClaw host API mock for the plugin test suite.
 *
 * Captures typed (api.on) and internal (api.registerHook) registrations
 * separately so tests can assert which hook system a registration used.
 */

export type CapturedRegistration = {
  name: string;
  handler?: unknown;
  opts?: Record<string, unknown>;
};

export type MockHostOptions = {
  pluginConfig?: Record<string, unknown>;
  /** When false the mock host lacks the typed api.on surface (old host). */
  supportsTypedHooks?: boolean;
};

export function createMockHostApi(options: MockHostOptions = {}) {
  const typed: CapturedRegistration[] = [];
  const legacy: CapturedRegistration[] = [];
  const logs: Array<{ level: string; msg: string }> = [];

  const logger = {
    info: (msg: string) => logs.push({ level: "info", msg: String(msg) }),
    warn: (msg: string) => logs.push({ level: "warn", msg: String(msg) }),
    error: (msg: string) => logs.push({ level: "error", msg: String(msg) }),
  };

  const api: Record<string, unknown> = {
    pluginConfig: options.pluginConfig ?? {},
    registrationMode: "test",
    logger,
    // Internal hook system: colon-named events and automation side effects.
    registerHook: (name: string, handler: unknown, opts?: Record<string, unknown>) => {
      legacy.push({ name, handler, opts });
    },
  };

  if (options.supportsTypedHooks !== false) {
    api.on = (name: string, handler: unknown, opts?: Record<string, unknown>) => {
      typed.push({ name, handler, opts });
    };
  }

  return { api, typed, legacy, logs, logger };
}

/** Named plugin-side errors surfaced to the host and asserted in tests. */
export const ERROR_KIND_TIMEOUT = "timeout";
export const ERROR_KIND_CONNECTION_REFUSED = "connection-refused";
export const ERROR_KIND_MALFORMED_RESPONSE = "malformed-response";
export const ERROR_KIND_HTTP_500 = "http-500";
export const ERROR_KIND_PROCESS_DEAD = "process-dead";
export const ERROR_KIND_AUTH_REFUSED = "auth-refused";
export const ERROR_KIND_SECRET_MISSING = "secret-missing";
export const ERROR_KIND_IDENTITY_MISMATCH = "identity-mismatch";
export const ERROR_KIND_HOST_TOO_OLD = "host-too-old";
export const ERROR_KIND_STARTUP_REFUSED = "startup-refused";
