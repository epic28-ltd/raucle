/**
 * Local scanner service trust tests (Q14 section 2).
 *
 * Review finding: the plugin posted to http://127.0.0.1:<port> with NO auth
 * and ServerManager adopted any service answering /health. The fix spans both
 * sides: a per-boot random secret (or operator-configured scanSecret) is
 * passed to the spawned scanner via env, every scan request carries the
 * secret header, and adoption of an existing service requires a
 * secret-protected identity probe with a schema-strict raucle body.
 */

import assert from "node:assert/strict";
import test from "node:test";
import type { IncomingMessage, ServerResponse } from "node:http";
import http from "node:http";

import { ScannerClient, classifyScanError, validateIdentityBody } from "../src/scanner-client.ts";
import { ServerManager } from "../src/server-manager.ts";

const RAUCLE_IDENTITY_BODY = {
  kind: "raucle",
  status: "ok",
  version: "0.25.0",
  mode: "standard",
  rules_loaded: 42,
  scan_secret_required: true,
};

function onceServer(
  handler: (req: IncomingMessage, res: ServerResponse, body: string) => void,
): Promise<{ server: http.Server; url: string; requests: Array<{ path?: string; headers: http.IncomingHttpHeaders; body: string }> }> {
  const requests: Array<{ path?: string; headers: http.IncomingHttpHeaders; body: string }> = [];
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let raw = "";
      req.on("data", (c): void => {
        raw += String(c);
      });
      req.on("end", (): void => {
        requests.push({ path: req.url, headers: req.headers, body: raw });
        handler(req, res, raw);
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ server, url: `http://127.0.0.1:${port}`, requests });
    });
  });
}

type HeaderCapture = { gotHeader?: string };

test("the scanner client refuses to run without a secret", () => {
  assert.throws(
    () => new ScannerClient(8900, { secret: "" }),
    (err: Error & { kind?: string }) => err.kind === "secret-missing",
    "an unauthenticated local scanner is the trust hole this lane closes",
  );
});

test("every scan request carries the secret header", async () => {
  const capture: HeaderCapture = {};
  const { server, url } = await onceServer((req, res) => {
    capture.gotHeader = req.headers["x-raucle-scan-token"];
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({
        verdict: "CLEAN",
        confidence: 0.9,
        injection_detected: false,
        categories: [],
        attack_technique: "",
        matched_rules: [],
        action: "allow",
        notes: [],
      })
    );
  });
  try {
    const client = new ScannerClient(Number(url.split(":").pop()), {
      secret: "boot-secret-1",
      timeoutMs: 2000,
    });
    await client.scan("hello world");
    assert.equal(capture.gotHeader, "boot-secret-1");
    await client.scanOutput("some output text");
    assert.equal(capture.gotHeader, "boot-secret-1");
    await client.scanToolCall("exec", { cmd: "ls" });
    assert.equal(capture.gotHeader, "boot-secret-1");
  } finally {
    server.close();
  }
});

test("a wrong secret is refused by the server and classes as auth-refused", async () => {
  const { server, url } = await onceServer((req, res) => {
    if (req.headers["x-raucle-scan-token"] !== "the-real-secret") {
      res.statusCode = 403;
      res.end(JSON.stringify({ detail: "Invalid scan token." }));
      return;
    }
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ verdict: "CLEAN", confidence: 1, injection_detected: false, categories: [], attack_technique: "", matched_rules: [], action: "allow", notes: [] }));
  });
  try {
    const client = new ScannerClient(Number(url.split(":").pop()), { secret: "wrong-boot-secret", timeoutMs: 2000 });
    await assert.rejects(
      client.scan("hello world"),
      (err: Error & { status?: number }) => {
        assert.equal(err.status, 403);
        assert.equal(classifyScanError(err), "auth-refused");
        return true;
      }
    );
  } finally {
    server.close();
  }
});

test("the identity probe returns the strict raucle identity body", async () => {
  let sawHeader: string | undefined;
  const { server, url } = await onceServer((req, res) => {
    sawHeader = req.headers["x-raucle-scan-token"];
    if (req.url === "/identity") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(RAUCLE_IDENTITY_BODY));
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  try {
    const client = new ScannerClient(Number(url.split(":").pop()), { secret: "boot-secret-2", timeoutMs: 2000 });
    const body = await client.identityProbe();
    assert.equal(sawHeader, "boot-secret-2", "the identity probe is secret-protected");
    assert.equal(body.kind, "raucle");
    assert.equal(body.version, "0.25.0");
  } finally {
    server.close();
  }
});

test("identity bodies that are not schema-strict raucle identity are rejected", () => {
  const rejects: unknown[] = [
    { status: "ok", version: "1.0" }, // foreign service, no kind
    { kind: "raucle", status: "ok", version: 5, rules_loaded: 1 }, // wrong version type
    { kind: "raucle", status: "degraded", version: "0.25.0", rules_loaded: 1 }, // wrong status
    { kind: "raucle", status: "ok", version: "0.25.0" }, // missing rules_loaded
    { kind: "raucle", status: "ok", version: "0.25.0", rules_loaded: "42" }, // wrong type
    "not json at all",
  ];
  for (const body of rejects) {
    const verdict = validateIdentityBody(body);
    assert.equal(verdict.ok, false, `expected rejection of ${JSON.stringify(body)}`);
  }
  const ok = validateIdentityBody(RAUCLE_IDENTITY_BODY);
  assert.deepEqual(ok, { ok: true, body: RAUCLE_IDENTITY_BODY });
});

test("the identity probe classes a 401 as auth-refused and foreign JSON as identity-mismatch", async () => {
  const { server, url } = await onceServer((req, res) => {
    if (req.headers["x-raucle-scan-token"] !== "knows-it") {
      res.statusCode = 401;
      res.end(JSON.stringify({ detail: "Missing X-Raucle-Scan-Token header" }));
      return;
    }
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ service: "totally-not-raucle", ok: true }));
  });
  try {
    const port = Number(url.split(":").pop());
    const wrongSecret = new ScannerClient(port, { secret: "nope", timeoutMs: 2000 });
    await assert.rejects(
      wrongSecret.identityProbe(),
      (err: Error & { status?: number }) => err.status === 401
    );
    const knowing = new ScannerClient(port, { secret: "knows-it", timeoutMs: 2000 });
    await assert.rejects(
      knowing.identityProbe(),
      (err: Error & { kind?: string; reasonClass?: string }) => {
        assert.equal(err.reasonClass, "identity-mismatch");
        return true;
      }
    );
  } finally {
    server.close();
  }
});

test("the manager adopts a compatible existing service without spawning", async () => {
  const spawnCalls: unknown[][] = [];
  const manager = new ServerManagerTestable({
    port: 8900,
    mode: "standard",
    logger: nullLogger(),
    fetchFn: async (url: string) => {
      if (String(url).endsWith("/identity")) {
        return okJson(RAUCLE_IDENTITY_BODY);
      }
      return notFoundJson();
    },
    spawnFn: ((...args: unknown[]) => {
      spawnCalls.push(args);
      return fakeChild();
    }) as never,
  });
  await manager.start();
  assert.equal(spawnCalls.length, 0, "a proven raucle service is adopted, not respawned");
  assert.equal(manager.isRunning, true);
  manager.stop();
});

test("the manager refuses an incompatible or foreign service and spawns its own with the secret env", async () => {
  const spawnCalls: Array<{ cmd: string; args: string[]; env: NodeJS.ProcessEnv | undefined }> = [];
  let spawned = false;
  const manager = new ServerManagerTestable({
    port: 8900,
    mode: "standard",
    logger: nullLogger(),
    fetchFn: async (url: string) => {
      if (!spawned) {
        // existing foreign service: 404 on /identity
        return { ok: false, status: 404 } as Response;
      }
      if (String(url).endsWith("/identity")) {
        return okJson(RAUCLE_IDENTITY_BODY);
      }
      return notFoundJson();
    },
    spawnFn: ((cmd: string, args: string[], opts: { env?: NodeJS.ProcessEnv }) => {
      spawned = true;
      spawnCalls.push({ cmd, args, env: opts?.env });
      return fakeChild();
    }) as never,
  });
  await manager.start();
  assert.equal(spawnCalls.length, 1, "incompatible service must not be adopted; spawn our own");
  const call = spawnCalls[0]!;
  assert.ok(call.env, "spawn must receive env");
  assert.match(
    String(call.env["RAUCLE_PLUGIN_SCAN_SECRET"]),
    /.+/,
    "the spawned scanner gets the secret via env"
  );
  assert.ok(String(call.env["RAUCLE_PLUGIN_SCAN_SECRET"]) === manager.secret);
  manager.stop();
});

test("per-boot secrets are random per manager and a configured secret is honoured", () => {
  const a = new ServerManagerTestable({ port: 8900, mode: "standard", logger: nullLogger() });
  const b = new ServerManagerTestable({ port: 8900, mode: "standard", logger: nullLogger() });
  const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  assert.match(a.secret, uuidRe, "per-boot secrets use crypto.randomUUID");
  assert.match(b.secret, uuidRe);
  assert.notEqual(a.secret, b.secret, "secrets differ per boot");
  const pinned = new ServerManagerTestable({ port: 8900, mode: "standard", logger: nullLogger(), secret: "operator-secret" });
  assert.equal(pinned.secret, "operator-secret");
});

test("the readiness wait is bounded and refuses with a named error", async () => {
  const manager = new ServerManagerTestable({
    port: 8900,
    mode: "standard",
    logger: nullLogger(),
    fetchFn: async () => ({ ok: false, status: 503 } as Response),
    spawnFn: (() => fakeChild()) as never,
    readiness: { timeoutMs: 40, intervalMs: 10 },
  });
  await assert.rejects(
    manager.start(),
    (err: Error & { kind?: string }) => {
      assert.equal(err.kind, "scanner-not-ready");
      return true;
    }
  );
  manager.stop();
});

// --- helpers -------------------------------------------------------------

function nullLogger() {
  return { info: () => undefined, warn: () => undefined, error: () => undefined };
}

function okJson(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function notFoundJson(): Response {
  return new Response("not found", { status: 404 });
}

function fakeChild() {
  return {
    stdout: { on: () => undefined },
    stderr: { on: () => undefined },
    on: () => undefined,
    killed: false,
    kill: () => true,
  };
}

/** ServerManager with fetch/spawn injected (the constructor accepts them). */
function ServerManagerTestable(
  opts: ConstructorParameters<typeof ServerManager>[0] & {
    fetchFn?: typeof fetch;
    spawnFn?: never;
    readiness?: { timeoutMs: number; intervalMs: number };
  }
) {
  return new ServerManager(opts);
}
