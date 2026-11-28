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
# D17: the enterprise-buyer tour narrative
# ---------------------------------------------------------------------------


def _tour_steps() -> list[tuple[str, str, str]]:
    return re.findall(r"\{tab:'([a-z]+)', target:'([^']+)', title:'([^']*)'", ADMIN_PANEL_HTML)


def test_tour_follows_the_enterprise_buyer_arc() -> None:
    """The arc: enterprise overview, what the console shows over OSS
    raucle, session monitoring catching a real runaway loop, DLP
    receipts, policy simulation over served traffic, receipt -> offline
    verify -> coverage, capability tokens and PQ, compliance, the MCP
    scanner catching tool poisoning statically, then the honest
    EE-limits close."""
    tabs = [t for t, _, _ in _tour_steps()]
    assert tabs == [
        "dashboard",  # the enterprise overview grid
        "dashboard",  # the stacks: EE console shape over OSS raucle
        "session",  # session monitoring: the runaway loop, real traffic
        "session",  # the catch is receipted, verified offline
        "dlp",  # DLP receipts from the real pattern engine
        "dlp",  # bounded disclosure: digests, never values (D2)
        "simulate",  # policy simulate: test a change before you deploy (K2)
        "simulate",  # the flippable diff, signed
        "receipts",  # every decision leaves a signed receipt
        "receipts",  # offline verify: no operator contact
        "receipts",  # coverage: the receipted-share metric
        "capdemo",  # capability tokens, attenuated live
        "receipts",  # PQ receipts: the signing key family
        "assure",  # compliance: the assurance packet story
        "mcp",  # tool poisoning caught statically by the real scanner
        "dashboard",  # honest close: EE-only surfaces labelled
    ]


def test_tour_targets_are_real_elements_in_the_new_layout() -> None:
    """Every spotlight target must resolve in the shipped panel: an id
    that exists, or the documented left-nav selector shape."""
    import re as _re

    for _tab, target, _title in _tour_steps():
        if target.startswith("#"):
            assert f'id="{target[1:]}"' in ADMIN_PANEL_HTML, target
        else:
            assert _re.fullmatch(r"\[data-tab-id=\"[a-z]+\"\]\.tab", target), target
            assert f'data-tab-id="{target[14:-6]}"' in ADMIN_PANEL_HTML, target


def test_tour_is_bounded_with_unique_targets_and_titles() -> None:
    steps = _tour_steps()
    # 16 after the K2 policy-simulate steps (nav entry + result card) joined
    # the arc, on top of the D2 DLP spotlight + the D5 MCP scanner step
    assert len(steps) <= 16
    targets = [t for _, t, _ in steps]
    assert len(targets) == len(set(targets)), "no duplicate spotlight targets"
    titles = [t for _, _, t in steps]
    assert len(titles) == len(set(titles)), "no duplicate step titles"


def test_tour_retired_screens_stay_off_the_walkthrough() -> None:
    """The walkthrough stays the buyer narrative: the side screens
    (authority stop, learn mode) are reachable tabs the tour
    deliberately does not drop into. The MCP scanner joined the arc
    when D5 made it the tool-poisoning story."""
    tabs = [t for t, _, _ in _tour_steps()]
    for gone in ("stop", "learn"):
        assert gone not in tabs
    for kept in ("showTab('mcp',this)", "showTab('stop',this)", "showTab('learn',this)"):
        assert kept in ADMIN_PANEL_HTML


def test_tour_opens_and_closes_on_the_overview_and_honesty_banner() -> None:
    steps = _tour_steps()
    assert steps[0][2]
    assert "overview" in steps[0][2].lower()
    assert steps[-1][0] == "dashboard"
    assert steps[-1][1] == "#honestyBanner"


def test_tour_spotlights_the_session_catch_with_real_traffic_copy() -> None:
    titles = " | ".join(t for _, _, t in _tour_steps())
    assert "runaway" in titles.lower()
    bodies = " ".join(m.group(1) for m in re.finditer(r"body:'([^']*)'", ADMIN_PANEL_HTML))
    assert "session id" in bodies.lower(), (
        "the tour must say the demo traffic declares a session id (honest about continuity)"
    )


def test_tour_navigation_can_activate_every_tour_tab() -> None:
    """Each tour step must switch to its own panel before spotlighting it."""
    for tab, _, _ in _tour_steps():
        assert f'data-tab-id="{tab}"' in ADMIN_PANEL_HTML, tab


def test_tour_spotlight_tracks_scroll_and_cancels_stale_steps() -> None:
    """Scrolling keeps the cutout aligned; rapid Next/Skip cannot race timers."""
    assert "let tourStep = 0, tourBox = null, tourTimer = null," in ADMIN_PANEL_HTML
    assert "tourRunId = 0, tourTarget = null;" in ADMIN_PANEL_HTML
    assert "const runId = ++tourRunId;" in ADMIN_PANEL_HTML
    assert "if (runId !== tourRunId) return;" in ADMIN_PANEL_HTML
    assert "window.addEventListener('scroll', reposition, true);" in ADMIN_PANEL_HTML
    assert "positionTourCard(tourTarget);" in ADMIN_PANEL_HTML
    assert "clearTimeout(tourTimer);" in ADMIN_PANEL_HTML
    assert "tourTarget = null;" in ADMIN_PANEL_HTML
    assert "if (oldHost) oldHost.replaceChildren();" in ADMIN_PANEL_HTML


def test_tour_can_always_be_dismissed_and_escape_closes_it() -> None:
    assert 'data-hi="tourEnd(false)">×</button>' in ADMIN_PANEL_HTML
    assert 'ev.key === \'Escape\' && document.getElementById(\'tourCard\')' in ADMIN_PANEL_HTML
    assert "localStorage.setItem(TOUR_SEEN_KEY, '1')" in ADMIN_PANEL_HTML


def test_tour_query_is_consumed_after_forced_start() -> None:
    assert "params.delete('tour')" in ADMIN_PANEL_HTML
    assert "history.replaceState(null, '', window.location.pathname" in ADMIN_PANEL_HTML


def test_tour_never_spotlights_an_unrelated_tab_fallback() -> None:
    assert "target = document.getElementById('tab-' + s.tab)" not in ADMIN_PANEL_HTML
    assert "This section is not available in this demo session." in ADMIN_PANEL_HTML
    assert "if (visible) positionTourCard(target);" in ADMIN_PANEL_HTML


def test_tour_reveals_offline_verify_panel_before_spotlighting() -> None:
    assert "s.target === '#rcpt-offline'" in ADMIN_PANEL_HTML
    assert "a[data-hi=\"offlineVerify(event)\"]" in ADMIN_PANEL_HTML
    assert "verifyLink.click();" in ADMIN_PANEL_HTML


def test_tour_card_is_responsive_and_reduced_motion_aware() -> None:
    assert "Math.min(360, Math.max(220, window.innerWidth - 24))" in ADMIN_PANEL_HTML
    assert "prefers-reduced-motion: reduce" in ADMIN_PANEL_HTML
    assert "rgba(9,16,34,.66)" in ADMIN_PANEL_HTML


# ---------------------------------------------------------------------------
# G9: left side navigation
# ---------------------------------------------------------------------------


def test_left_nav_replaces_the_top_tab_strip() -> None:
    """13+ screens moved to a sticky left column; no top strip remains."""
    assert '<div class="tabs">' not in ADMIN_PANEL_HTML
    assert 'class="sidenav"' in ADMIN_PANEL_HTML
    assert 'data-nav-group="trust"' in ADMIN_PANEL_HTML
    assert 'data-nav-group="assurance"' in ADMIN_PANEL_HTML
    assert 'data-nav-group="red"' in ADMIN_PANEL_HTML
    # every screen stays reachable through the left nav dispatcher
    for tab in (
        "dashboard",
        "connections",
        "policies",
        "stop",
        "learn",
        "receipts",
        "assure",
        "mcp",
        "dlp",
        "injection",
        "shadow",
        "capdemo",
        "siem",
        "users",
        "config",
        "simulate",
    ):
        assert f"showTab('{tab}',this)" in ADMIN_PANEL_HTML, tab


def test_left_nav_group_order_matches_the_agent_stacks() -> None:
    """Trust, then Assurance, then Red; Red carries the stop entry only."""
    trust = ADMIN_PANEL_HTML.index('<div class="nav-group" data-nav-group="trust"')
    assurance = ADMIN_PANEL_HTML.index('<div class="nav-group" data-nav-group="assurance"')
    red = ADMIN_PANEL_HTML.index('<div class="nav-group" data-nav-group="red"')
    assert trust < assurance < red
    assert ">Raucle Agent Trust<" in ADMIN_PANEL_HTML
    assert ">Raucle Agent Assurance<" in ADMIN_PANEL_HTML
    assert ">Raucle Agent Red<" in ADMIN_PANEL_HTML
    red_block = ADMIN_PANEL_HTML[red : ADMIN_PANEL_HTML.index("</nav>", red)]
    assert "Emergency authority stop" in red_block
    remainder = red_block.split("Emergency authority stop", 1)[1]
    assert "showTab('" not in remainder, "the red group carries no further entries"


def test_assurance_jump_items_are_dispatcher_backed() -> None:
    """Evidence pack and Key model jump to in-tab sections via the shared map."""
    assert 'data-hi="navEvidencePack()"' in ADMIN_PANEL_HTML
    assert 'data-hi="navKeyModel()"' in ADMIN_PANEL_HTML
    assert '"navEvidencePack()":(ev,el)=>navEvidencePack(el)' in ADMIN_PANEL_HTML
    assert '"navKeyModel()":(ev,el)=>navKeyModel(el)' in ADMIN_PANEL_HTML


def test_demo_group_gating_rules_ship() -> None:
    """Assurance and red nav groups are demo surfaces; live view keeps trust."""
    assert (
        'body:not(.demo) .nav-group[data-nav-group="assurance"], '
        'body:not(.demo) .nav-group[data-nav-group="red"]{display:none}' in ADMIN_PANEL_HTML
    )


def test_left_nav_collapses_to_a_top_strip_under_900px() -> None:
    """The responsive fallback keeps the left nav reachable on small screens."""
    assert "@media (max-width: 900px)" in ADMIN_PANEL_HTML
    assert "flex-direction: row" in ADMIN_PANEL_HTML


def test_tour_spotlights_left_nav_items_for_caught_screens() -> None:
    """G9 carried over: the first DLP step spotlights its left-nav entry;
    the D2 step spotlights the in-tab class card. The D17 steps spotlight
    content sections (scroll-and-spotlight semantics unchanged)."""
    steps = _tour_steps()
    dlp_targets = [target for tab, target, _ in steps if tab == "dlp"]
    assert dlp_targets == ['[data-tab-id="dlp"].tab', "#dlpFindingsCard"]
    for tab in ("dashboard", "session", "receipts", "capdemo", "assure"):
        targets = [target for t, target, _ in steps if t == tab]
        assert all(x.startswith("#") for x in targets), tab


def test_tour_steps_carry_dlp_and_mcp_spotlights() -> None:
    """G9 carried over: the DLP and MCP steps spotlight their left-nav
    entries; the content-spotlight semantics are unchanged."""
    targets = {tab: target for tab, target, _ in _tour_steps()}
    assert targets["dlp"] == "#dlpFindingsCard"
    for tab in ("dashboard", "session", "receipts", "capdemo", "assure", "mcp"):
        assert targets[tab].startswith("#"), tab


def test_tour_steps_carry_the_simulate_spotlight_split() -> None:
    """K2: the policy-simulate steps follow the DLP precedent split: the
    first step spotlights the left-nav entry, the second the in-tab
    result card (always visible, so the spotlight has real extent)."""
    steps = _tour_steps()
    sim_targets = [target for tab, target, _ in steps if tab == "simulate"]
    assert sim_targets == ['[data-tab-id="simulate"].tab', "#simTabResultCard"]


# ---------------------------------------------------------------------------
# K2 (X6 slice 2): the policy-simulate tab renderers and honest states
# ---------------------------------------------------------------------------


def test_simulate_tab_loaders_exist_and_are_wired_into_showtab() -> None:
    for fn in ("loadSimTab", "simTabPick", "simTabRun", "simTabClear", "renderSimTab"):
        assert f"function {fn}(" in ADMIN_PANEL_HTML, fn
    assert "if(t==='simulate')loadSimTab();" in ADMIN_PANEL_HTML


def test_simulate_tab_controls_are_dispatcher_backed() -> None:
    # the run and clear buttons are static HTML; the preset chips gain
    # data-hi in JS (the D10 pattern)
    assert 'data-hi="simTabRun()"' in ADMIN_PANEL_HTML
    assert 'data-hi="simTabClear()"' in ADMIN_PANEL_HTML
    assert "chip.setAttribute('data-hi','simTabPick(event)')" in ADMIN_PANEL_HTML
    for hi in ("simTabRun()", "simTabClear()", "simTabPick(event)", "showTab('simulate',this)"):
        assert f'"{hi}":(ev,el)=>' in ADMIN_PANEL_HTML, hi


def test_simulate_tab_block_is_textcontent_only() -> None:
    """The K2 block builds every row through createElement/textContent."""
    script = "".join(re.findall(r"<script[^>]*>(.*?)</script>", ADMIN_PANEL_HTML, re.S))
    start = script.find("// ================= X6 POLICY SIMULATE TAB")
    assert start != -1, "the K2 simulate tab block marker is missing"
    end = script.find("// ================= EMERGENCY AUTHORITY STOP SCREEN")
    block = script[start:end]
    assert "innerHTML" not in block
    assert "textContent" in block


def test_simulate_run_caps_the_pasted_policy_client_side() -> None:
    """Pasted candidate policies are size-capped in the browser before
    the simulate POST leaves (the MCP manifest precedent)."""
    body = _extract_fn(_extract_script_blocks(ADMIN_PANEL_HTML)[0], "simTabRun")
    cap = body.find("256*1024")
    post = body.find("'/api/policy/simulate'")
    assert cap != -1, "the client-side size cap is missing"
    assert post != -1
    assert cap < post, "the client-side size cap must run before the simulate POST"


def test_simulate_run_is_one_at_a_time() -> None:
    """The run button refuses a second concurrent run: the busy guard is
    checked before the request and cleared when it settles."""
    body = _extract_fn(_extract_script_blocks(ADMIN_PANEL_HTML)[0], "simTabRun")
    assert body.find("if(simTabBusy)") < body.find("api("), "the busy guard must gate the request"
    assert "simTabBusy=true" in body
    assert "simTabBusy=false" in body


def test_simulate_tab_renders_the_honest_unavailable_states() -> None:
    """Named notices for every refusal shape the surfaces can return:
    demo mode off (404), role refusal (403), malformed body (422 rows),
    and the guided empty state before any run."""
    script = _extract_script_blocks(ADMIN_PANEL_HTML)[0]
    body = _extract_fn(script, "simTabRequest")
    assert "r.status===404" in body, "the 404 demo-not-configured notice is missing"
    assert "r.status===403" in body, "the 403 role-refusal notice is missing"
    assert "r.status===422" in body, "the 422 malformed-body notice is missing"
    assert "Array.isArray(detail)" in body, "FastAPI 422 detail rows must render as named text"
    run = _extract_fn(script, "simTabRun")
    assert "Choose a preset policy tweak or paste a candidate policy YAML first" in run


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_renderSimTab_renders_bounded_rows_never_markup() -> None:
    """Hostile tool/agent strings render as text: the changed-decisions
    table holds no markup and never echoes argument values."""
    block = _extract_script_blocks(ADMIN_PANEL_HTML)[0]
    payload = {
        "result": {
            "candidate_policy_hash": "sha256:" + "a" * 64,
            "window_hash": "sha256:" + "b" * 64,
            "gate": {
                "actions_replayed": 2,
                "actions_unreplayable": 0,
                "current": {"allow": 2, "deny": 0},
                "candidate": {"allow": 1, "deny": 1},
                "changed_decisions": [
                    {
                        "receipt_hash": "sha256:" + "c" * 64,
                        "tool": "<img src=x onerror=alert(1)>",
                        "agent_id": "</td><script>alert(2)</script>",
                        "current_decision": "allow",
                        "candidate_decision": "deny",
                        "evidence_depth": 2,
                    }
                ],
                "verdict": "the alternative policy would have prevented 1 of 2 actions",
                "chain_depth": 2,
            },
        },
        "receipt_hash": "sha256:" + "d" * 64,
        "jws": "eyJhbGciOiJFZERTQSJ9...<script>alert(3)</script>",
    }
    program = (
        "const captured={};"
        "function el(tag){return {tag:tag,style:{},children:[],innerHTML:'',textContent:'',"
        "colSpan:null,appendChild(c){this.children.push(c);},setAttribute(){},"
        "classList:{add(){},remove(){},toggle(){}},dataset:{}};}"
        "global.document={getElementById:(id)=>{if(!captured[id])captured[id]=el('div');"
        "return captured[id];},createElement:(tag)=>el(tag)};"
        "const SIM_TAB_MAX_ROWS=200;"
        + _extract_fn(block, "renderSimTab")
        + "renderSimTab("
        + __import__("json").dumps(payload)
        + ");"
        "function textOf(x){let t=x.textContent||'';(x.children||[]).forEach(c=>{t+=textOf(c);});"
        "return t;}"
        "const all=Object.values(captured).map(x=>textOf(x)).join('|');"
        "const inner=Object.values(captured).map(x=>x.innerHTML).join('');"
        "const rawBad=/<img[^>]*onerror|<script/.test(inner);"
        "const rowsOk=all.includes('allow 2 / deny 0')&&all.includes('Decisions that flip: 1')&&"
        "all.includes('the alternative policy would have prevented 1 of 2 actions');"
        "const noArgEcho=!all.includes('account=');"
        "if(rawBad||!rowsOk||!noArgEcho||inner!==''){console.log('BAD:'+all);process.exit(1);}"
        "console.log('ESCAPED');"
    )
    _run_node(program)


# ---------------------------------------------------------------------------
# D5: the MCP scanner tab (real engine, evidence class, no payload echo)
# ---------------------------------------------------------------------------


def test_mcp_findings_render_the_evidence_class_never_the_excerpt() -> None:
    """The findings table shows severity, location and the evidence class
    (the scanner's category). The raw evidence excerpt is manifest payload
    and never reaches a cell."""
    start = ADMIN_PANEL_HTML.find("function renderMcpFindings(")
    assert start != -1
    body = ADMIN_PANEL_HTML[start : ADMIN_PANEL_HTML.find("function mcpScan(")]
    assert "f.category" in body
    assert "f.evidence" not in body


def test_mcp_scan_caps_the_pasted_manifest_client_side() -> None:
    """Pasted manifests are size-capped in the browser before the scan
    POST leaves, matching the server's refusal of oversize bodies."""
    start = ADMIN_PANEL_HTML.find("function mcpScan(")
    assert start != -1
    body = ADMIN_PANEL_HTML[start : start + 3000]
    cap = body.find("256*1024")
    post = body.find("/api/demo/mcp/scan")
    assert cap != -1, "the client-side size cap is missing"
    assert post != -1
    assert cap < post, "the client-side size cap must run before the scan POST"


# ---------------------------------------------------------------------------
# D16: the session behaviour tab renderers (real endpoints, textContent)
# ---------------------------------------------------------------------------


def test_session_loaders_exist_and_are_wired_into_showtab() -> None:
    for fn in ("loadSessionPanel", "loadSessionRules", "loadSessionWindows", "loadSessionFindings"):
        assert f"function {fn}(" in ADMIN_PANEL_HTML, fn
    assert "if(t==='session')loadSessionPanel()" in ADMIN_PANEL_HTML
    # the offline-verify button rides the shared delegated map
    assert "sessionFindingVerify" in ADMIN_PANEL_HTML


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_loadSessionRules_renders_the_real_config_escaped() -> None:
    """Hostile rule ids and config errors render as text, never markup."""
    block = _extract_script_blocks(ADMIN_PANEL_HTML)[0]
    payload = {
        "schema_version": "raucle.demo.session_rules/v1",
        "config_error": "",
        "deny_only": True,
        "session_rules": [
            {
                "id": "<img src=x onerror=alert(1)>",
                "kind": "runaway_tool_loop",
                "threshold": 3,
                "window_seconds": 600,
                "tool_patterns": ["batch_report_export"],
            }
        ],
        "window": {"ttl_seconds": 900, "max_keys": 1024, "max_entries": 10000},
        "limits": ["deny-only v1", "process memory", "gradual_extraction"],
    }
    program = (
        "const captured={};"
        "global.document={getElementById:(id)=>"
        "{if(!captured[id])captured[id]={innerHTML:'',textContent:''};return captured[id];}};"
        "function api(){return Promise.resolve({ok:true,status:200,json:()=>Promise.resolve("
        + __import__("json").dumps(payload)
        + ")});}"
        + _extract_fn(block, "esc")
        + _extract_fn(block, "escn")
        + _extract_fn(block, "loadSessionRules")
        + "\n(async()=>{"
        "loadSessionRules();"
        "await new Promise(r=>setTimeout(r,30));"
        "const all=Object.values(captured).map(x=>(x.innerHTML||'')+(x.textContent||'')).join('|');"
        "const rawBad=/<img[^>]*onerror/.test(all);"
        "const escOk=all.includes('&lt;img src=x onerror=alert(1)&gt;');"
        "if(rawBad||!escOk){console.log('BAD:',all);process.exit(1);}"
        "console.log('ESCAPED');"
        "})();"
    )
    _run_node(program)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_loadSessionFindings_renders_cited_receipts_and_verify_buttons() -> None:
    """Each finding row shows its cited gate receipt and carries a
    dispatcher-backed verify button; hostile text stays text."""
    block = _extract_script_blocks(ADMIN_PANEL_HTML)[0]
    payload = {
        "schema_version": "raucle.demo.session_findings/v1",
        "harness": "session-monitor",
        "count": 1,
        "findings": [
            {
                "finding_id": "finding_<script>",
                "test_id": "demo-runaway-export-loop",
                "verdict": "confirmed",
                "cited_receipt": "rcpt-abc123",
                "tool": "batch_report_export",
                "expected_decision": "deny",
                "actual_decision": "deny",
                "detected_at": 1760000000,
                "note": "session behavioural rule fired",
                "receipt_hash": "sha-xyz<script>alert(2)</script>",
            }
        ],
    }
    program = (
        "const captured={};"
        "global.document={getElementById:(id)=>"
        "{if(!captured[id])captured[id]={innerHTML:'',textContent:''};return captured[id];}};"
        "function api(){return Promise.resolve({ok:true,status:200,json:()=>Promise.resolve("
        + __import__("json").dumps(payload)
        + ")});}"
        + _extract_fn(block, "esc")
        + _extract_fn(block, "escn")
        + _extract_fn(block, "loadSessionFindings")
        + "\n(async()=>{"
        "loadSessionFindings();"
        "await new Promise(r=>setTimeout(r,30));"
        "const all=Object.values(captured).map(x=>(x.innerHTML||'')+(x.textContent||'')).join('|');"
        r"const rawBad=/<script>alert\(2\)<\/script>/.test(all)||/finding_<script>/.test(all);"
        "const ok=all.includes('rcpt-abc123')"
        "&&all.includes('demo-runaway-export-loop')"
        "&&all.includes('sessionFindingVerify(event)');"
        "if(rawBad||!ok){console.log('BAD:',all);process.exit(1);}"
        "console.log('ESCAPED');"
        "})();"
    )
    _run_node(program)


# ---------------------------------------------------------------------------
# G10: brand logo and corporate blue chrome
# ---------------------------------------------------------------------------


def test_brand_logo_asset_is_shipped_and_served() -> None:
    """G10: the engraved mark: package asset, served route, panel img src."""
    from fastapi.testclient import TestClient

    import raucle.gateway_app as ga
    from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
    from raucle.gateway_app import create_admin_app

    png = Path(ga.__file__).with_name("assets") / "logo-mark.png"
    assert png.exists(), png
    assert png.read_bytes().startswith(b"\x89PNG"), png
    assert 'src="/assets/logo-mark.png"' in ADMIN_PANEL_HTML
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
    r = client.get("/assets/logo-mark.png")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/png")
    assert r.content.startswith(b"\x89PNG")
    # the mark is same-origin: the CSP keeps img-src pinned to 'self' data
    assert "img-src 'self'" in ga._panel_csp()


def test_corporate_blue_tokens_are_scoped_to_the_nav_chrome() -> None:
    """G10: engraved blue + hero navy chrome tokens; semantic colours intact."""
    assert "--rc-blue: #7C8FF0" in ADMIN_PANEL_HTML
    assert "--rc-navy: #14143C" in ADMIN_PANEL_HTML
    # green allow / red deny / amber escalate stay literal decision colours
    for colour in ("#22c55e", "#dd6b78", "#e5b85c"):
        assert colour in ADMIN_PANEL_HTML


# ---------------------------------------------------------------------------
# Checker-driven regression: the checker (17 Nov evening) found loadSession-
# Windows reading a client-invented shape and sessionFindingVerify being a
# stub. These probes pin the server shape and the real verify call.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_loadSessionWindows_renders_the_server_shape() -> None:
    """The renderer reads d.sessions with agents/receipts/escalates and
    honours available=false + unavailable_note (unavailable never
    fabricated, client-side too)."""
    block = _extract_script_blocks(ADMIN_PANEL_HTML)[0]
    payload = {
        "schema_version": "raucle.demo.session_windows/v1",
        "available": True,
        "sessions": [
            {
                "session_id": "sess-<script>",
                "receipts": 3,
                "allows": 1,
                "denies": 2,
                "escalates": 0,
                "agents": ["agent:svc<img>"],
                "first_iat": 1760000000,
                "last_iat": 1760000300,
                "recent": [],
            }
        ],
    }
    win_payload = {
        "schema_version": "raucle.demo.session_windows/v1",
        "available": False,
        "sessions": [],
        "unavailable_note": "receipt index unavailable",
    }
    program = (
        "const captured={};"
        "global.document={getElementById:(id)=>"
        "{if(!captured[id])captured[id]={innerHTML:'',textContent:''};"
        "return captured[id];}};"
        "const payloads=["
        + __import__("json").dumps(payload)
        + ","
        + __import__("json").dumps(win_payload)
        + "];let call=0;"
        "function api(){const p=payloads[Math.min(call,1)];call++;"
        "return Promise.resolve({ok:true,status:200,json:()=>Promise.resolve(p)});}"
        + _extract_fn(block, "esc")
        + _extract_fn(block, "escn")
        + _extract_fn(block, "loadSessionWindows")
        + "\n(async()=>{"
        "loadSessionWindows();"
        "await new Promise(r=>setTimeout(r,30));"
        "const first=captured['sessionWindowsBody'].innerHTML;"
        "loadSessionWindows();"
        "await new Promise(r=>setTimeout(r,30));"
        "const second=captured['sessionWindowsBody'].innerHTML;"
        "const rawBad=/<script>|<img>/.test(first+second);"
        "const ok=first.includes('sess-&lt;script&gt;')"
        "&&first.includes('receipts 3')"
        "&&first.includes('agent:svc&lt;img&gt;')"
        "&&second.includes('receipt index unavailable')"
        "&&!second.includes('no active windows');"
        "if(rawBad||!ok){console.log('BAD:',first,'||',second);process.exit(1);}"
        "console.log('ESCAPED');"
        "})();"
    )
    _run_node(program)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_sessionFindingVerify_calls_the_real_endpoint() -> None:
    """The card/row button drives the real POST offline-verify endpoint
    with the finding's receipt hash and renders the verdict - not the
    stub sentence the checker caught."""
    block = _extract_script_blocks(ADMIN_PANEL_HTML)[0]
    program = (
        "const captured={};"
        "let __p='';let __m='';"
        "global.document={getElementById:(id)=>"
        "{if(!captured[id])captured[id]={innerHTML:'',textContent:''};"
        "return captured[id];}};"
        "function api(p,o){__p=p;__m=(o||{}).method||'GET';"
        "return Promise.resolve({status:200,json:()=>Promise.resolve({verdict:'valid',"
        "schema_version:'raucle.demo.chain_verification/v1'})});}"
        + _extract_fn(block, "esc")
        + _extract_fn(block, "escn")
        + _extract_fn(block, "sessionFindingVerify")
        + "\n(async()=>{"
        "const el="
        "{getAttribute:(k)=>k==='data-receipt'?'sha256:deadbeef':"
        "(k==='data-cited'?'sha256:gate':'')};"
        "sessionFindingVerify({},el);"
        "await new Promise(r=>setTimeout(r,30));"
        "const all=Object.values(captured).map(x=>"
        "(x.innerHTML||'')+(x.textContent||'')).join('|');"
        "const called=__p.indexOf("
        '"/api/demo/session-findings/sha256%3Adeadbeef/offline-verify")>-1'
        ' && __m==="POST";'
        "const rawBad=/<script>/.test(all);"
        "const ok=called&&all.includes('VERIFIED OFFLINE');"
        "if(rawBad||!ok){console.log('BAD:',__p,__m,all);process.exit(1);}"
        "console.log('ESCAPED');"
        "})();"
    )
    _run_node(program)


# ---------------------------------------------------------------------------
# D2: the Data Protection tab renderers (real x_dlp plane, digests only)
# ---------------------------------------------------------------------------


def test_dlp_loader_exists_and_is_wired_into_showtab() -> None:
    for fn in ("loadDlpPanel", "loadDlpFindings"):
        assert f"function {fn}(" in ADMIN_PANEL_HTML, fn
    assert "if(t==='dlp')loadDlpPanel()" in ADMIN_PANEL_HTML
    assert "/api/demo/dlp-findings" in ADMIN_PANEL_HTML
    # the simulated DLP renderer is gone: the screen no longer reads the
    # request-time demo findings pack
    assert "function renderDlpScreen(" not in ADMIN_PANEL_HTML


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_loadDlpFindings_renders_digest_pairs_and_absence_states() -> None:
    """Hostile route values stay text; the digest pair renders side by
    side with the collar and the citation; the 404 and unavailable
    states render honestly, never fabricated."""
    block = _extract_script_blocks(ADMIN_PANEL_HTML)[0]
    payload = {
        "schema_version": "raucle.demo.dlp_findings/v1",
        "available": True,
        "count": 1,
        "advisory_findings": 4,
        "by_class": {"pii_email": 2},
        "findings": [
            {
                "scan_id": "scan:<script>alert(1)</script>",
                "action": "redacted",
                "direction": "egress_to_tool",
                "route": {"source": "agent:<img>", "destination": "inbound-screener"},
                "content_sha256": "sha256:" + "a" * 64,
                "redacted_content_sha256": "sha256:" + "b" * 64,
                "matched_classes": ["pii_email"],
                "span_counts": {"pii_email": 2},
                "rule_id": "demo-advisory-redact",
                "cited_receipt": "rcpt-xyz<script>",
                "detected_at": 1760000000,
                "receipt_hash": "sha-abc<script>alert(2)</script>",
            }
        ],
    }
    unavailable = {
        "schema_version": "raucle.demo.dlp_findings/v1",
        "available": False,
        "findings": [],
        "by_class": {},
        "count": 0,
        "advisory_findings": 0,
        "unavailable_note": "receipt store not configured",
    }
    program = (
        "const captured={};"
        "function mkEl(){return {style:{},children:[],innerHTML:'',textContent:'',"
        "appendChild:function(c){this.children.push(c);}};}"
        "global.document={getElementById:(id)=>"
        "{if(!captured[id])captured[id]=mkEl();return captured[id];},"
        "createElement:()=>mkEl()};"
        "function textOf(el){let out=(el.textContent||'')+(el.innerHTML||'');"
        "(el.children||[]).forEach(function(c){out+=textOf(c);});return out;}"
        "const responses=[{status:404},"
        + __import__("json").dumps(payload)
        + ","
        + __import__("json").dumps(unavailable)
        + "];let call=0;"
        "function api(){const r=responses[Math.min(call,2)];call++;"
        "return Promise.resolve({status:r.status||200,json:()=>Promise.resolve(r)});}"
        + _extract_fn(block, "esc")
        + _extract_fn(block, "escn")
        + _extract_fn(block, "findingsRows")
        + _extract_fn(block, "findingsStats")
        + _extract_fn(block, "dshort")
        + _extract_fn(block, "collarSpans")
        + _extract_fn(block, "loadDlpFindings")
        + "\n(async()=>{"
        "loadDlpFindings();"
        "await new Promise(r=>setTimeout(r,30));"
        "const notConfigured=captured['dlpFindingsBody'].innerHTML;"
        "loadDlpFindings();"
        "await new Promise(r=>setTimeout(r,30));"
        "const rowHtml=textOf(captured['dlpTableBody']);"
        "const classHtml=captured['dlpFindingsBody'].innerHTML;"
        "loadDlpFindings();"
        "await new Promise(r=>setTimeout(r,30));"
        "const unavailableHtml=captured['dlpFindingsBody'].innerHTML;"
        "const all=notConfigured+rowHtml+classHtml+unavailableHtml;"
        "const markupSurfaces=notConfigured+classHtml+unavailableHtml;"
        "const tableClean=captured['dlpTableBody'].innerHTML==='';"
        "const rawBad=/<script>|<img>/.test(markupSurfaces)||!tableClean;"
        "const ok=notConfigured.includes('Demo mode is not configured')"
        "&&rowHtml.includes('sha256:aaaa')&&rowHtml.includes('sha256:bbbb')"
        "&&rowHtml.includes('[REDACTED:pii_email] x2')"
        "&&rowHtml.includes('demo-advisory-redact')"
        "&&rowHtml.includes('rcpt-xyz')"
        "&&classHtml.includes('[REDACTED:pii_email] x2')"
        "&&unavailableHtml.includes('receipt store not configured');"
        "if(rawBad||!ok){console.log('BAD:',all);process.exit(1);}"
        "console.log('ESCAPED');"
        "})();"
    )
    _run_node(program)
