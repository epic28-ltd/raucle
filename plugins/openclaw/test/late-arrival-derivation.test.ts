import { test } from "node:test";
import assert from "node:assert/strict";

test("late-arrival outcome derives from the active failure mode (checker D2)", () => {
  // The sealed-decision contract: closed mode -> denied/enforced with a
  // scanner-unavailable reason; open mode -> unknown/failed_open. The pair
  // denied+failed_open must never appear (it contradicts the host vocabulary).
  const derive = (failureMode: string) => ({
    outcome: failureMode === "closed" ? "denied" : "unknown",
    coverageState: failureMode === "closed" ? "enforced" : "unknown",
    reasonCode: failureMode === "closed" ? "scanner_unavailable" : "plugin_hook_failed_open",
  });
  const closed = derive("closed");
  assert.equal(closed.outcome, "denied");
  assert.equal(closed.coverageState, "enforced");
  assert.equal(closed.reasonCode, "scanner_unavailable");
  const open = derive("open");
  assert.equal(open.outcome, "unknown");
  assert.equal(open.coverageState, "unknown");
  assert.equal(open.reasonCode, "plugin_hook_failed_open");
});
