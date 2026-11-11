"""The admin panel HTML must ship JavaScript that actually parses.

Chromium discards an entire script block when any statement fails to parse,
which left every inline handler (enterDemo among them) undefined and the
"View Demo" button dead. Regression: the receipt-table builder emitted
showAncestry(\\'', an escaped quote followed by a stray closing quote, so the
outer JS string terminated mid-expression. v0.23.0 regression (ancestry link).

Guards:
- the builder carries the hash in a data attribute (no quote conflicts), and
- if node is available, the whole shipped script block must pass a V8 parse.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from raucle.gateway_app import ADMIN_PANEL_HTML


def test_receipt_rows_carry_hash_in_data_attribute() -> None:
    """The hash rides a data attribute (no quote conflicts) and is escaped."""
    assert "data-hash=\"'+esc(r.receipt_hash||'')+'" in ADMIN_PANEL_HTML


def test_broken_showAncestry_onclick_escape_is_gone() -> None:
    # the faulty pattern: escaped quote followed by a stray terminator quote
    assert "showAncestry(\\''" not in ADMIN_PANEL_HTML
    # the onclick no longer embeds the hash through quote mazes
    assert "showAncestry('" not in ADMIN_PANEL_HTML


def test_row_click_delegation_is_registered_once() -> None:
    # listener fn + one dispatcher entry + the data-hi attributes on rows
    assert ADMIN_PANEL_HTML.count('data-hi="rcptRowClick(event)"') >= 1
    assert ADMIN_PANEL_HTML.count('"rcptRowClick(event)":(ev,el)=>rcptRowClick(ev)') == 1


def test_login_field_canvas_present_and_reduced_motion_safe() -> None:
    assert 'id="field"' in ADMIN_PANEL_HTML
    assert "pointer-events: none" in ADMIN_PANEL_HTML
    assert "prefers-reduced-motion: reduce" in ADMIN_PANEL_HTML
    assert "document.hidden" in ADMIN_PANEL_HTML


def test_field_is_login_screen_only() -> None:
    assert "field.classList.toggle" in ADMIN_PANEL_HTML
    # the observer watches the login card visibility, with no legend/hud
    assert "getElem'+'entById" not in ADMIN_PANEL_HTML


def test_topology_scroll_pans_and_pan_is_clamped() -> None:
    assert "topoPanY -= ev.deltaY" in ADMIN_PANEL_HTML
    assert "deltaY < 0 ? 1.1 : 0.9" not in ADMIN_PANEL_HTML
    assert "topoExtents()" in ADMIN_PANEL_HTML


def test_topology_defaults_to_top_five_framing() -> None:
    assert "frameTopChains" in ADMIN_PANEL_HTML
    assert "frameTopActive" not in ADMIN_PANEL_HTML
    assert "topoFitAllPending" in ADMIN_PANEL_HTML
    assert "topoLayoutCache = null" in ADMIN_PANEL_HTML
    # the layout helper hands back the position map itself, not the cache wrapper
    assert "return pos;" in ADMIN_PANEL_HTML


def test_connections_view_is_live_tail_with_decision_pills() -> None:
    assert "updatePathTail()" in ADMIN_PANEL_HTML
    assert "setDecisionFilter('deny'" in ADMIN_PANEL_HTML
    assert "setDecisionFilter('allow'" in ADMIN_PANEL_HTML
    assert "setDecisionFilter('all'" in ADMIN_PANEL_HTML
    assert 'id="liveMode" checked' not in ADMIN_PANEL_HTML
    # the tail poll only runs while the connections tab is visible
    assert "pathPollId" in ADMIN_PANEL_HTML


def test_login_field_does_not_pop_in_mid_screen() -> None:
    assert "chips[chips.length-1].x = Math.random()" not in ADMIN_PANEL_HTML
    assert "topoSig" in ADMIN_PANEL_HTML
    assert "topoUserZoomed" in ADMIN_PANEL_HTML


def test_field_is_pure_greyscale() -> None:
    i = ADMIN_PANEL_HTML.find("/* --- ambient ledger field")
    j = ADMIN_PANEL_HTML.find("})();", i)
    field_js = ADMIN_PANEL_HTML[i:j]
    for tone in ("#16a34a", "#dd2f45", "#d97706", "22,163,74", "221,47,69", "217,119,6"):
        assert tone not in field_js


def _extract_script_blocks(html: str) -> list[str]:
    return [b for b in re.findall(r"<script[^>]*>(.*?)</script>", html, re.S) if b.strip()]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_shipped_script_parses_under_v8() -> None:
    blocks = _extract_script_blocks(ADMIN_PANEL_HTML)
    assert blocks, "panel must ship its script inline"
    with tempfile.TemporaryDirectory() as td:
        for i, block in enumerate(blocks):
            path = Path(td) / f"script{i:02}.js"
            path.write_text(block)
            proc = subprocess.run(
                ["node", "--check", str(path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert proc.returncode == 0, (
                f"script block {i} fails to parse: {(proc.stderr or proc.stdout).strip()[-300:]}"
            )


# ---------------------------------------------------------------------------
# T-B2: MFA column render contract (both states)
# ---------------------------------------------------------------------------


def test_users_mfa_column_renders_both_states() -> None:
    """The MFA cell must carry both render states and an escaped user id."""
    m = re.search(
        r"u\.mfa_enabled\?'<span[^>]*>Enabled</span>':'<span[^>]*>Off</span>'", ADMIN_PANEL_HTML
    )
    assert m, "MFA cell must render both Enabled and Off states literally"
    assert 'data-user-id="${uid}"' in ADMIN_PANEL_HTML
    assert "const uid=esc(u.user_id||'')" in ADMIN_PANEL_HTML


def test_users_mfa_button_contract_both_states() -> None:
    """Setup button always; Disable button only in the mfa_enabled branch."""
    assert 'data-user-id="${uid}" onclick="userMfaAction(event,\'setup\')"' in ADMIN_PANEL_HTML or (
        'data-user-id="${uid}" data-hi="userMfaAction(event,\'setup\')"' in ADMIN_PANEL_HTML
    )
    assert re.search(
        r"mfa_enabled\?` <button[^>]*userMfaAction\(event,'disable'\)", ADMIN_PANEL_HTML
    )


# ---------------------------------------------------------------------------
# T-S2: innerHTML escaping sweep
# ---------------------------------------------------------------------------

ALLOWLIST = {
    # class-name / css values / generated indices: not server-controlled text
    "selectedSource===n?' active':''",
    "selectedDest===n?' active':''",
    "selectedSource===n?' flow-active':''",
    "dot",
    "i",
    "badge",
    "uid",
    "pct",
    "bx",
    "by",
    "tourStep+1",
    "TOUR_STEPS.length",
    "tourStep+1<TOUR_STEPS.length?'Next':'Start exploring'",
    "TOUR_STEPS.map((_,i)=>`<span class=\"${i===tourStep?'on':''}\"></span>`).join('')",
    "n.status",
    "statusClass",
    "e.colour||getEdgeColor(e.status)",
    "u.mfa_enabled?'<span style=\"color:#22c55e;font-size:12px\">Enabled</span>':'<span style=\"color:#a3a3a3;font-size:12px\">Off</span>'",  # noqa: E501
    'u.mfa_enabled?` <button class="btn btn-secondary" style="padding:4px 10px;font-size:11px" data-user-id="${uid}" onclick="userMfaAction(event,\'disable\')">Disable</button>`:\'\'',  # noqa: E501
    "i===tourStep?'on':''",
}


def _statement_windows_containing_innerhtml(html: str):
    """Yield the full statement text of each innerHTML assignment."""
    for m in re.finditer(r"innerHTML\s*\+?=", html):
        # walk forward to the terminating ';' at depth 0 (paran/brace/bracket)
        i = m.end()
        depth = 0
        quote = None
        while i < len(html):
            ch = html[i]
            if quote:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            else:
                if ch in "'\"`":
                    quote = ch
                elif ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif ch == ";" and depth == 0:
                    break
            i += 1
        yield html[m.start() : i + 1]


def test_innerhtml_templates_escape_every_dynamic_value() -> None:
    """Any ${...} inside an innerHTML template literal must be esc()-wrapped
    (or an explicitly allowlisted non-text value: class names, px offsets,
    generated indices). A new unescaped interpolation fails CI."""
    bad: list[str] = []
    for window in _statement_windows_containing_innerhtml(ADMIN_PANEL_HTML):
        j = 0
        while j < len(window):
            if window[j] != "`":
                j += 1
                continue
            k = j + 1
            while k < len(window):
                if window[k] == "\\":
                    k += 2
                    continue
                if window[k] == "`":
                    break
                k += 1
            tmpl = window[j + 1 : k]
            idx = 0
            while idx < len(tmpl):
                ch = tmpl[idx]
                if ch == "$" and idx + 1 < len(tmpl) and tmpl[idx + 1] == "{":
                    d = 0
                    e = idx + 2
                    while e < len(tmpl):
                        ec = tmpl[e]
                        if ec == "`":
                            # nested template literal: skip its body wholesale
                            n = e + 1
                            while n < len(tmpl):
                                if tmpl[n] == "\\":
                                    n += 2
                                    continue
                                if tmpl[n] == "`":
                                    break
                                n += 1
                            e = n
                            continue
                        if ec == "{":
                            d += 1
                        elif ec == "}":
                            if d == 0:
                                break
                            d -= 1
                        e += 1
                    expr = tmpl[idx + 2 : e].strip()
                    ok = expr in ALLOWLIST
                    if not ok and expr:
                        # nested template literal truncated the extraction:
                        # accept a prefix of an allowlisted composite expr
                        ok = any("`" in a and a.startswith(expr) for a in ALLOWLIST)
                    if "esc(" not in expr and "escn(" not in expr and not ok:
                        bad.append(expr)
                    idx = e
                idx += 1
            j = k + 1
    assert not bad, f"unescaped template interpolation(s) in innerHTML template: {bad}"


def _extract_fn(script: str, name: str) -> str:
    """Extract a single-line `function name(){...}` panel function."""
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith(f"function {name}(") and stripped.rstrip().endswith("}"):
            return stripped
    # multi-line fall-back: balanced, string-aware brace matcher
    start = script.index(f"function {name}(")
    i = script.index("{", start)
    depth = 0
    j = i
    while j < len(script):
        c = script[j]
        if c in "'\"`":
            q = c
            j += 1
            while j < len(script):
                if script[j] == "\\":
                    j += 2
                    continue
                if script[j] == q:
                    break
                j += 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return script[start : j + 1]
        j += 1
    raise AssertionError(f"function {name}() not terminated in panel script")


def _run_node(program: str) -> None:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "probe.js"
        path.write_text(program)
        proc = subprocess.run(["node", str(path)], capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")
        assert "ESCAPED" in proc.stdout, proc.stdout


MALICIOUS_STATS = {
    "total_requests": "<img src=x onerror=alert(1)>",
    "allowed": "</td><script>alert(2)</script>",
    "denied": 'x"><svg onload=alert(3)>',
    "escalated": "'; alert(4); '",
    "avg_latency_us": "<u>&</u>",
    "tools": {
        "<tr onclick=alert(5)>": {
            "allow": "</td><td onclick=alert(6)>",
            "deny": "<img src=q onerror=alert(7)>",
            "escalate": "'\"",
        }
    },
}


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_malicious_stats_object_is_escaped() -> None:
    """feed loadStats a hostile stats payload: no raw markup may survive."""
    block = _extract_script_blocks(ADMIN_PANEL_HTML)[0]
    program = (
        "const captured={};"
        "global.document={getElementById:(id)=>"
        "{if(!captured[id])captured[id]={innerHTML:''};return captured[id];}};"
        "function api(){return Promise.resolve({json:()=>Promise.resolve("
        + __import__("json").dumps(MALICIOUS_STATS)
        + ")});}"
        + _extract_fn(block, "esc")
        + _extract_fn(block, "escn")
        + "let alert=()=>{};"
        + _extract_fn(block, "loadStats")
        + "\n(async()=>{"
        "loadStats();"
        "await new Promise(r=>setTimeout(r,30));"
        "const g=captured.statsGrid.innerHTML,t=captured.toolTableBody.innerHTML;"
        "const rawBad=/[<](img|script|svg)\\b|[<]u\\b|[<]td onclick/.test(g+t);"
        "const escOk=g.includes('&lt;img')&&t.includes('&lt;img src=q')&&g.includes('&lt;u&gt;');"
        "if(rawBad||!escOk){console.log('RAW:',g,'|',t);process.exit(1);}"
        "console.log('ESCAPED');"
        "})();"
    )
    _run_node(program)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_loadUsers_renders_mfa_states_and_escapes_user_id() -> None:
    """Both users render; the malicious user_id is escaped; Disable only on the
    MFA-enabled row (T-B2 render contract, dynamic state)."""
    block = _extract_script_blocks(ADMIN_PANEL_HTML)[0]
    users = [
        {
            "user_id": '<u id="evil">',
            "api_key_label": "k1",
            "role": "viewer",
            "name": "A",
            "mfa_enabled": True,
        },
        {"user_id": "u2", "api_key_label": "", "role": "admin", "name": "B", "mfa_enabled": False},
    ]
    program = (
        "const captured={};"
        "global.document={getElementById:(id)=>"
        "{if(!captured[id])captured[id]={innerHTML:''};return captured[id];}};"
        "function api(){return Promise.resolve({json:()=>Promise.resolve("
        + __import__("json").dumps({"users": users})
        + ")});}"
        + _extract_fn(block, "esc")
        + _extract_fn(block, "escn")
        + "let alert=()=>{};"
        + _extract_fn(block, "loadUsers")
        + "\n(async()=>{"
        "loadUsers();"
        "await new Promise(r=>setTimeout(r,30));"
        "const h=captured.userTableBody.innerHTML;"
        "const ok=h.includes('Enabled')&&h.includes('Off')"
        "&&h.includes('&lt;u id=&quot;evil&quot;&gt;')"
        "&&!h.includes('<u id=\"evil\">')"
        "&&h.split(\"userMfaAction(event,'disable')\").length===2"
        "&&h.includes(\"userMfaAction(event,'setup')\");"
        "if(!ok){console.log('BAD:',h);process.exit(1);}"
        "console.log('ESCAPED');"
        "})();"
    )
    _run_node(program)


# ---------------------------------------------------------------------------
# T-S6: CSP hardening - no inline event handlers, hash-pinned script-src
# ---------------------------------------------------------------------------


def test_panel_has_no_inline_event_handlers() -> None:
    """Inline handler attributes are gone: dispatch is data-hi + delegation."""
    from raucle.gateway_app import TOPOLOGY_HTML as _topo

    for html in (ADMIN_PANEL_HTML, _topo):
        assert not re.search(
            r'on(?:click|change|input|keydown|submit|load|mouseover|blur\\)="', html
        )
        assert "javascript:" not in html


def test_every_data_hi_value_has_a_dispatcher_entry() -> None:
    """A data-hi attribute with no __HI entry is a dead button (silent)."""
    missing = sorted(
        {m.group(1) for m in re.finditer(r'data-hi="([^"]*)"', ADMIN_PANEL_HTML)}
        - {m.group(1) for m in re.finditer(r'"([^"]*)":\(ev,el\)=>', ADMIN_PANEL_HTML)}
    )
    assert not missing, f"data-hi values without dispatcher entry: {missing}"


def test_csp_script_src_is_hash_pinned() -> None:
    """script-src must be sha256-pinned: no unsafe-inline, stale-hash-safe."""
    from raucle.gateway_app import _panel_csp, _panel_script_hashes

    csp = _panel_csp()
    src = csp.split("script-src ", 1)[1]
    script_src = src.split(";", 1)[0]
    assert "'unsafe-inline'" not in script_src
    assert "'unsafe-eval'" not in script_src
    hashes = _panel_script_hashes()
    assert len(hashes) >= 2, "panel and topology pages each ship a script block"
    for h in hashes:
        assert h in src
    # every shipped inline script block is covered by the CSP
    import base64
    import hashlib

    from raucle.gateway_app import TOPOLOGY_HTML as _topo

    shipped: list[str] = []
    for html in (ADMIN_PANEL_HTML, _topo):
        for b in re.findall(r"<script[^>]*>(.*?)</script>", html, re.S):
            if b.strip():
                shipped.append(
                    "'sha256-"
                    + base64.b64encode(hashlib.sha256(b.encode()).digest()).decode()
                    + "'"
                )
    assert sorted(shipped) == sorted(hashes)


def test_csp_header_on_panel_and_topology() -> None:
    """Smoke: the served pages carry the hardened CSP header."""
    from fastapi.testclient import TestClient

    from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
    from raucle.gateway_app import create_admin_app

    cfg = GatewayConfig(
        policy_file="",
        receipt_store=str(tempfile.mkdtemp() + "/receipts.jsonl"),
        audit_chain=str(tempfile.mkdtemp() + "/audit.jsonl"),
        admin_api_key="admin-key-0123456789abcdef",
        signer_backend="local",
    )
    gateway = RaucleGateway(cfg)
    users = UserManager()
    users.add_user(cfg.admin_api_key, "admin", "Admin")
    client = TestClient(create_admin_app(gateway, users))
    for path in ("/", "/topology"):
        r = client.get(path, headers={"Authorization": "admin-key-0123456789abcdef"})
        assert r.status_code == 200, path
        csp = r.headers["Content-Security-Policy"]
        assert "script-src 'sha256-" in csp
        assert "'unsafe-inline'" not in csp.split("style-src", 1)[0]
        # the served page is the same source the CSP hash pins
        assert "<!DOCTYPE html>" in r.text


# ---------------------------------------------------------------------------
# G7: the guided tour narrative arc
# ---------------------------------------------------------------------------


def _tour_steps() -> list[tuple[str, str, str]]:
    return re.findall(r"\{tab:'([a-z]+)', target:'([^']+)', title:'([^']*)'", ADMIN_PANEL_HTML)


def test_tour_follows_the_narrative_arc() -> None:
    """The arc: live traffic, what the gate caught, the policy behind it,
    the evidence it leaves, then what an auditor takes away."""
    tabs = [t for t, _, _ in _tour_steps()]
    assert tabs == [
        "connections",  # live traffic
        "connections",  # filter
        "dlp",  # caught: sensitive data
        "injection",  # caught: injected instructions
        "shadow",  # caught: unapproved AI
        "policies",  # the policy that did it (with simulate)
        "receipts",  # evidence: signed receipts
        "capdemo",  # evidence: capability tokens
        "receipts",  # auditor takeaway: key model (G5)
        "receipts",  # auditor takeaway: offline verify
        "assure",  # auditor takeaway: assurance packet (G3)
        "assure",  # auditor takeaway: cross-org proof
    ]


def test_tour_has_one_step_per_screen_family_and_is_bounded() -> None:
    steps = _tour_steps()
    # "one step per screen family", not one per tab: the caught family
    # carries three screens, evidence two, auditor takeaway two.
    assert len(steps) <= 12
    targets = [t for _, t, _ in steps]
    assert len(targets) == len(set(targets)), "no duplicate spotlight targets"
    titles = [t for _, _, t in steps]
    assert len(titles) == len(set(titles)), "no duplicate step titles"


def test_tour_no_longer_drops_into_side_quests() -> None:
    """Retired screens stay off the tour; their tabs remain in the panel."""
    tabs = [t for t, _, _ in _tour_steps()]
    for gone in ("dashboard", "mcp", "stop", "learn"):
        assert gone not in tabs
    for kept in ("showTab('dashboard',this)", "showTab('mcp',this)"):
        assert kept in ADMIN_PANEL_HTML
