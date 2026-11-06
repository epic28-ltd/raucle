# Accessibility / UX audit — raucle shipped surfaces, NFR build P5.NFR v1

Scope: the surfaces users actually touch — the gateway admin panel HTML
(`raucle/gateway_app.py`), the standalone server console (`raucle/server.py`),
and coloured/status semantics in exported reports. This audit is a coverage
statement measured against the code on 6 Nov 2026 (`main` @ `7f4b3d3`). It
records what is TESTED, what is PRESENT-UNTESTED, and what is genuinely
MISSING. No WCAG conformance claim is made or implied.

## What is guarded by tests today

| Guard | Where the assertion lives | What it protects |
| --- | --- | --- |
| Admin-panel JS always parses (dead inline handlers regress) | `tests/test_admin_panel_js.py` (11 tests) | Any HTML/JS shipped to operators actually runs |
| Receipt table binds via `data-hash` attribute, never quote-mazed inline handlers | `test_admin_panel_js.py` | Interactive elements stay click-delegated and escapable |
| `prefers-reduced-motion: reduce` CSS hook + JS `matchMedia` check + `document.hidden` handling | `test_login_field_canvas_present_and_reduced_motion_safe` | Motion-sensitive operators are not forced into animation |
| Login field canvas is login-screen-only, `pointer-events: none`, `aria-hidden`, `tabindex="-1"` | same test | Decorative canvas stays out of tab order and out of the post-login UI |
| Proof-obligation outcomes carry TEXT status (`green`/`red`/`amber`) with a detail payload including counterexample | `tests/test_audit_export.py::test_proof_obligations_colour_mapping` | Status is machine- and screen-reader-readable, never colour-only |

## Present but untested (honest inventory)

- `textContent`-only rendering of dynamic values in the admin panel and
  console: 27 assignment sites (counted by grep in `raucle/gateway_app.py`
  and `raucle/server.py`). Good posture (no string-built HTML on the hot
  status paths) but NO test pins this. A regression that switches a counter
  to `innerHTML` would pass CI.
- Labels exist for admin-panel form fields (each config input is wrapped in
  a `<label>`), but no test forbids a future label-less input.

## Genuinely missing (gaps, recorded not spun)

1. **31 `innerHTML` sites in `raucle/gateway_app.py`** (grep count,
   2026-11-06): policy-file list, editor panes, etc. Data is
   operator-session-scoped, but no test or sanitiser asserts the innerHTML
   sources cannot carry attacker-influenced taint. This is the largest a11y/
   DOM-safety gap and the first candidate if this family is extended.
2. **No ARIA live regions**: async-updated elements (`pathCount`, receipt
   counts, connection counters) update silently; screen readers get no
   announcement.
3. **No measured contrast data**: the audit-export colour vocabulary is
   tested as STRINGS; nowhere is any rendered contrast ratio measured.
   Any "WCAG AA contrast" claim would therefore be ungrounded — none is
   made.
4. **No end-to-end assistive-technology test**: no axe-core/Lighthouse/
   screen-reader smoke anywhere in the suite or CI.
5. **No keyboard-navigation test** for the admin panel beyond the canvas
   `tabindex="-1"` assertion.
6. The dogfood console suite (48 tests in the assurance repo) exercises
   CLI output correctness, not AT readability; the two are conflated in
   some write-ups and must not be treated as a11y coverage.

## Standing recommendation

If this NFR family is funded for a second round, order of value:
(1) a guard test forbidding `innerHTML` on taint-reachable admin-panel
paths; (2) `aria-live="polite"` on the counted-status elements + a shipped
assertion; (3) an axe-core CI smoke on the admin panel HTML as served.
