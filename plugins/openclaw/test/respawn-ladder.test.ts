/**
 * Bounded respawn ladder tests (PR #322 verdict D2).
 *
 * On adoption refusal the manager spawns against the (occupied) port; the
 * spawned child exits immediately (EADDRINUSE) and the old exit-restart loop
 * re-entered every 10s forever. The remedy: a bounded BACKOFF ladder (base
 * delay doubling per consecutive failed round, capped) plus a give-up with a
 * NAMED advisory; and the readiness wait fails fast when the spawned child
 * dies instead of polling a dead listener for the full budget.
 */

import assert from "node:assert/strict";
import test from "node:test";

import type { ManagerLogger } from "../src/server-manager.ts";
import { ServerManager } from "../src/server-manager.ts";

type LogLine = { level: string; msg: string };

function captureLogger(): { logger: ManagerLogger; lines: LogLine[] } {
  const lines: LogLine[] = [];
  const logger: ManagerLogger = {
    info: (msg: string) => lines.push({ level: "info", msg }),
    warn: (msg: string) => lines.push({ level: "warn", msg }),
    error: (msg: string) => lines.push({ level: "error", msg }),
  };
  return { logger, lines };
}

/** A spawn that emits a non-zero exit `delayMs` after creation (EADDRINUSE shape). */
function exitingChild(delayMs: number) {
  const listeners: Record<string, Array<(code: number) => void>> = {};
  setTimeout(() => {
    for (const fn of listeners.exit ?? []) fn(1);
  }, delayMs);
  return {
    stdout: { on: () => undefined },
    stderr: { on: () => undefined },
    on: (name: string, fn: (code: number) => void) => {
      (listeners[name] ??= []).push(fn);
    },
    killed: false,
    kill: () => true,
  };
}

function refusedFetch(): Promise<Response> {
  // The occupied port answers nothing the adoption probe can accept.
  return Promise.resolve({ ok: false, status: 404 } as Response);
}

test("the respawn ladder backs off, caps consecutive rounds and gives up with a named advisory", async () => {
  const { logger, lines } = captureLogger();
  const spawnTimes: number[] = [];
  const manager = new ServerManager({
    port: 8900,
    mode: "standard",
    logger,
    fetchFn: (() => refusedFetch()) as never,
    spawnFn: (() => {
      spawnTimes.push(Date.now());
      return exitingChild(5);
    }) as never,
    readiness: { timeoutMs: 80, intervalMs: 5 },
    respawn: { baseDelayMs: 10, maxDelayMs: 15, maxAttempts: 2 },
  });

  await assert.rejects(
    manager.start(),
    (err: Error & { kind?: string }) => err.kind === "scanner-not-ready"
  );

  // Initial spawn + maxAttempts respawn rounds, then the ladder gives up.
  await new Promise((resolve) => setTimeout(resolve, 400));
  assert.equal(
    spawnTimes.length,
    3,
    "initial spawn plus maxAttempts respawn rounds, then no further spawns"
  );
  assert.equal(manager.gaveUpRespawning, true, "the manager gave up once the ladder exhausted");
  if (spawnTimes.length === 3) {
    assert.ok(spawnTimes[1] - spawnTimes[0] >= 10, "the first respawn waited out the base backoff");
    assert.ok(spawnTimes[2] - spawnTimes[1] >= 15, "the backoff grows for consecutive failures (cap applies)");
  }
  const abandoned = lines.find((line) => line.msg.includes("RESPAWN ABANDONED"));
  if (!abandoned) {
    throw new Error("the give-up advisory must be logged");
  }
  assert.match(abandoned.msg, /reasonClass=spawn-give-up/, "the advisory carries a named reasonClass");
  assert.match(abandoned.msg, /port 8900/, "the advisory names the port");
  assert.match(abandoned.msg, /RAUCLE_PLUGIN_SCAN_SECRET/, "the advisory names the operator remedy");
  // The ladder abandons on the failed spawn AFTER maxAttempts recovery
  // respawns, so the scanner has exited maxAttempts + 1 times in total
  // (this test runs maxAttempts=2); the advisory reports that observed count.
  assert.match(
    abandoned.msg,
    /exited 3 times in a row/,
    "the advisory reports the observed exit count (maxAttempts + 1)"
  );
  manager.stop();
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(spawnTimes.length, 3, "no spawns after the ladder gave up");
});

test("start() fails fast when the spawned scanner dies instead of polling a dead port", async () => {
  const { logger } = captureLogger();
  const manager = new ServerManager({
    port: 8900,
    mode: "standard",
    logger,
    fetchFn: (() => refusedFetch()) as never,
    spawnFn: (() => exitingChild(5)) as never,
    readiness: { timeoutMs: 15000, intervalMs: 5 },
    respawn: { baseDelayMs: 10, maxDelayMs: 20, maxAttempts: 50 },
  });
  const started = Date.now();
  await assert.rejects(
    manager.start(),
    (err: Error & { kind?: string }) =>
      err.kind === "scanner-not-ready" && /exited \(exit code 1\)/.test(err.message)
  );
  const elapsed = Date.now() - started;
  assert.ok(
    elapsed < 5000,
    `the readiness wait failed fast on child death instead of the full 15s budget (took ${elapsed}ms)`
  );
  manager.stop();
});
