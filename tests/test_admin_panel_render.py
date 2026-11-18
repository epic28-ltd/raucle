"""RED-033: the admin panel renders untrusted values safely.

A gate receipt carries caller-influenced text (agent_id, source, destination,
tool, reason). The panel used to interpolate several of those straight into
``innerHTML`` and, worse, into inline handler strings:

    tr.innerHTML = '...' + (r.tool||'') + '...'
    onclick="toggleSource('${esc(n)}')"

``esc()`` is HTML escaping. Inside an ``onclick`` attribute the browser
decodes the entities before parsing the attribute as JavaScript, so a quote
in a source name breaks out of the string literal. The correct pattern, used
once already in this file for receipt ancestry, is a data attribute plus a
shared delegated handler.

These tests are source-level contracts: they read the shipped panel string and
assert the shape of the generated rows, which is the part that matters and the
part a browser test cannot reach without a DOM harness.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import ADMIN_PANEL_HTML, TOPOLOGY_HTML, create_admin_app, create_gateway_app

# Fields the server fills from gate traffic. Any of these reaching HTML must
# go through esc(); any of them reaching a handler must ride a data attribute.
UNTRUSTED_FIELDS = (
    "r.tool",
    "r.agent_id",
    "r.receipt_hash",
    "r.trace_id",
    "r.decision",
    "r.reason",
    "c.source",
    "c.tool",
    "c.destination",
    "c.reason",
    "u.name",
    "u.user_id",
)


def _function_body(html: str, name: str) -> str:
    """Return the source of ``function <name>`` up to the next top-level def."""
    start = html.find(f"function {name}(")
    assert start != -1, f"function {name} not found in the panel"
    rest = html[start:]
    nxt = re.search(r"\nfunction [A-Za-z_]+\(|\n// ===", rest)
    return rest[: nxt.start()] if nxt else rest


class TestEscapingContract:
    @pytest.mark.parametrize("name", ["loadReceipts"])
    def test_receipt_rows_escape_every_untrusted_field(self, name):
        body = _function_body(ADMIN_PANEL_HTML, name)
        for field in ("r.tool", "r.agent_id", "r.receipt_hash", "r.trace_id", "r.decision"):
            bare = re.search(r"\+\s*\(?" + re.escape(field) + r"\b", body)
            assert bare is None, f"{field} is interpolated without esc() in {name}"
            assert f"esc({field}" in body, f"{field} is never escaped in {name}"

    def test_no_untrusted_value_in_an_inline_handler(self):
        """``onclick="fn('${...}')"`` is a JS-string context, not HTML.

        The browser decodes HTML entities in an attribute before parsing it as
        JavaScript, so esc() does not make an interpolated argument safe.
        Values ride data attributes instead.
        """
        assert "('${" not in ADMIN_PANEL_HTML
        for handler in (
            "toggleSource(",
            "toggleDest(",
            "filterByTool(",
            "setupMfa(",
            "disableMfa(",
        ):
            assert f'onclick="{handler}' not in ADMIN_PANEL_HTML, (
                f"{handler} still takes an inline argument"
            )

    def test_flow_and_user_handlers_read_data_attributes(self):
        for token in ('data-name="', 'data-user-id="', "dataset.name", "dataset.userId"):
            assert token in ADMIN_PANEL_HTML, f"{token} missing: values must ride data attributes"
        for delegated in ("function flowItemClick(", "function userMfaAction("):
            assert delegated in ADMIN_PANEL_HTML, f"{delegated} missing"

    def test_topology_view_escapes_dynamic_values(self):
        assert "esc(node.label)" in TOPOLOGY_HTML
        assert "esc(node.subtitle)" in TOPOLOGY_HTML
        # topology wires listeners with addEventListener, never inline handlers
        assert "addEventListener('click'" in TOPOLOGY_HTML


class TestSecurityHeaders:
    @pytest.fixture
    def apps(self, tmp_path):
        cfg = GatewayConfig(
            policy_file="",
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            admin_api_key="admin-key-0123456789abcdef",
            signer_backend="local",
        )
        gateway = RaucleGateway(cfg)
        users = UserManager()
        users.add_user(cfg.admin_api_key, "admin", "Admin")
        return (
            TestClient(create_gateway_app(gateway)),
            TestClient(create_admin_app(gateway, users)),
        )

    @pytest.mark.parametrize("path", ["/", "/health"])
    def test_csp_and_friends_on_admin_app(self, apps, path):
        client = apps[1]
        resp = client.get(path, headers={"Authorization": "admin-key-0123456789abcdef"})
        assert resp.headers["Content-Security-Policy"].startswith("default-src 'none'")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Referrer-Policy"] == "no-referrer"

    def test_csp_on_gateway_app(self, apps):
        client = apps[0]
        resp = client.get("/health")
        assert "Content-Security-Policy" in resp.headers
        assert resp.headers["X-Content-Type-Options"] == "nosniff"


# ---------------------------------------------------------------------------
# D14-D17: the enterprise console reframe (truth classes, overview,
# session behaviour tab, tour)
# ---------------------------------------------------------------------------

#: The D14 truth-class vocabulary. Exactly these labels, no synonyms.
TRUTH_CLASSES = ("OSS LIVE", "OSS MACHINERY + EE VIEW", "EE-ONLY")

#: The persistent honesty banner, verbatim (D14).
HONESTY_BANNER = (
    "This demo shows the Enterprise Edition operator surface. Enforcement, "
    "receipts and verification run on the Apache-2.0 open-source raucle "
    "gateway beneath it. EE-only surfaces are labelled."
)


def _tab_sections(html: str) -> dict[str, str]:
    """Slice the panel into its tab sections, keyed by tab id.

    Walks from each ``<div id="tab-...">`` opening tag to the div that
    closes it (balanced, string-aware), which is the unit D14 calls a
    section: the nav points at exactly these.
    """
    sections: dict[str, str] = {}
    for m in re.finditer(r'<div id="tab-([a-z]+)"', html):
        name = m.group(1)
        i = html.index(">", m.end() - 1) + 1
        depth = 1
        j = i
        while j < len(html) and depth:
            nxt = html.find("<", j)
            if nxt == -1:
                break
            tag_end = html.find(">", nxt)
            if tag_end == -1:
                break
            tag = html[nxt + 1 : tag_end]
            if tag.startswith("div") or tag.startswith("/div"):
                depth += 1 if tag[0] != "/" else -1
            j = tag_end + 1
        sections[name] = html[i:j]
    return sections


def _opening_tag(html: str, tab_id: str) -> str:
    m = re.search(r'<div id="tab-' + tab_id + r'"[^>]*>', html)
    assert m, f"tab-{tab_id} not found"
    return m.group(0)


def _balanced_body(html: str, marker: str, attrs: str = "") -> str:
    """The body of the element whose opening tag starts with *marker*,
    walked to its balanced closing tag (nested divs included)."""
    start = html.find(marker)
    assert start != -1, f"marker not found: {marker}"
    i = html.index(">", start) + 1
    depth = 1
    j = i
    while j < len(html) and depth:
        nxt = html.find("<", j)
        if nxt == -1:
            break
        tag_end = html.find(">", nxt)
        if tag_end == -1:
            break
        tag = html[nxt + 1 : tag_end]
        if tag.startswith("div") or tag.startswith("/div"):
            depth += 1 if tag[0] != "/" else -1
        j = tag_end + 1
    assert depth == 0, f"unbalanced element at {marker}"
    return html[i : j - 6]  # strip the final "</div>"


class TestEnterpriseConsoleFrame:
    """D14: identity, honesty banner, one truth class per section."""

    def test_console_identity_is_the_enterprise_console(self):
        assert "<title>Raucle Enterprise console</title>" in ADMIN_PANEL_HTML
        assert ">Enterprise console<" in ADMIN_PANEL_HTML

    def test_honesty_banner_is_present_and_persistent(self):
        assert HONESTY_BANNER in ADMIN_PANEL_HTML
        # persistent: rendered inside the main layout, never inside a
        # demo-only branch, so both the live and demo views carry it
        assert 'id="honestyBanner"' in ADMIN_PANEL_HTML
        assert 'class="honesty-banner"' in ADMIN_PANEL_HTML

    def test_every_tab_section_declares_exactly_one_truth_class(self):
        sections = _tab_sections(ADMIN_PANEL_HTML)
        assert sections, "the panel must ship tab sections"
        for tab_id, body in sections.items():
            tag = _opening_tag(ADMIN_PANEL_HTML, tab_id)
            marks = re.findall(r'data-truth-class="([^"]*)"', tag)
            assert len(marks) == 1, f"tab-{tab_id} must carry exactly one truth class"
            assert marks[0] in TRUTH_CLASSES, (tab_id, marks[0])
            # the class is also shown: one visible badge in the section,
            # except the overview whose capability cards carry their own
            badges = re.findall(r'class="truth-badge[^"]*"[^>]*>([^<]*)<', body)
            shown = {b for b in badges if b in TRUTH_CLASSES}
            assert marks[0] in shown, f"tab-{tab_id} never shows its truth class"
            if tab_id != "dashboard":
                assert len(badges) == 1, f"tab-{tab_id} shows {len(badges)} badges"

    def test_truth_class_classification_is_honest(self):
        """Machinery-backed demo screens are never labelled OSS LIVE."""
        machinery = ("injection", "shadow", "siem", "users")
        live = (
            "dashboard",
            "connections",
            "policies",
            "capdemo",
            "receipts",
            "learn",
            "config",
            "dlp",
            "session",
            "assure",
            "mcp",
            "stop",
        )
        for tab_id in machinery:
            assert 'data-truth-class="OSS MACHINERY + EE VIEW"' in _opening_tag(
                ADMIN_PANEL_HTML, tab_id
            ), f"tab-{tab_id} must carry the machinery class"
        for tab_id in live:
            assert 'data-truth-class="OSS LIVE"' in _opening_tag(ADMIN_PANEL_HTML, tab_id), (
                f"tab-{tab_id} must carry the OSS LIVE class"
            )


class TestEnterpriseOverview:
    """D15: the landing tab is a capability grid, cards describe only."""

    D15_CARDS = (
        "Decision receipts + offline verify",
        "Coverage: receipted share",
        "Session behavioural rules",
        "Capability tokens + PQ receipts",
        "Data loss prevention",
        "Prompt injection detection",
        "Compliance: EU AI Act pack",
        "Fleet + SIEM targets",
        "AI gateway",
        "Policy editor + simulate",
        "Kill switch: operator stop",
        "MCP tool scanner",
        "Shadow AI discovery",
    )

    def _grid(self) -> str:
        return _balanced_body(ADMIN_PANEL_HTML, '<div class="ov-grid" id="overviewGrid">')

    def _cards(self) -> list[str]:
        grid = self._grid()
        cards: list[str] = []
        for m in re.finditer(r'<div class="ov-card" data-truth-class="[^"]*">', grid):
            body = grid[m.start() :]
            # each card ends where the next card opens, or at the grid end
            nxt = body.find('<div class="ov-card"', m.end())
            cards.append(body[m.end() - m.start() : (nxt if nxt != -1 else len(body))])
        return cards

    def test_overview_grid_renders_the_d15_card_list_with_links(self):
        grid = self._grid()
        for title in self.D15_CARDS:
            assert title in grid, f"overview card missing: {title}"
        cards = self._cards()
        assert len(cards) == 13, f"the D15 card list has 13 cards, found {len(cards)}"
        for card in cards:
            assert re.search(r'class="ov-title"', card), "card must name the capability"
            assert re.search(r'class="ov-desc"', card), "card must describe the capability"
            assert re.search(r'class="truth-badge', card), "card must carry its truth badge"
            assert 'data-hi="' in card, "every overview card links to its tab"

    def test_overview_cards_carry_valid_truth_classes(self):
        grid = self._grid()
        classes = re.findall(r'<div class="ov-card" data-truth-class="([^"]*)"', grid)
        assert len(classes) == 13
        assert all(c in TRUTH_CLASSES for c in classes)
        # the honest EE position is visible on the grid: at least one
        # EE-ONLY card (fleet + SIEM targets) and the machinery classes
        assert "EE-ONLY" in classes
        assert "OSS MACHINERY + EE VIEW" in classes

    def test_enterprise_strip_is_subsumed_by_the_overview(self):
        assert 'id="enterpriseStrip"' not in ADMIN_PANEL_HTML
        assert 'id="enterpriseOverview"' in ADMIN_PANEL_HTML

    def test_overview_carries_no_numbers(self):
        """Cards describe; tabs demonstrate: no fabricated counts."""
        assert not re.search(r"stat-value", self._grid()), "the overview grid must not fake data"


class TestDataProtectionTab:
    """D2: the Data Protection tab ships the real advisory redaction plane.

    The screen reads signed x_dlp receipts minted by the OSS advisory
    redaction engine over live demo traffic, so its truth class is OSS
    LIVE and its copy must state the bounded-disclosure rules.
    """

    def test_tab_declares_oss_live_over_real_machinery(self):
        tag = _opening_tag(ADMIN_PANEL_HTML, "dlp")
        assert 'data-truth-class="OSS LIVE"' in tag
        body = _tab_sections(ADMIN_PANEL_HTML)["dlp"]
        for marker in (
            "advisory redaction engine",
            "x_dlp",
            "[REDACTED:",
            "digest",
            "pci_pan",
            "canned",
        ):
            assert marker in body, marker
        for element_id in ("dlpSummary", "dlpFindingsCard", "dlpFindingsBody", "dlpTableBody"):
            assert f'id="{element_id}"' in body, element_id

    def test_tab_fetches_the_real_dlp_plane(self):
        assert "/api/demo/dlp-findings" in ADMIN_PANEL_HTML

    def test_overview_dlp_card_is_oss_live(self):
        grid = _balanced_body(ADMIN_PANEL_HTML, '<div class="ov-grid" id="overviewGrid">')
        i = grid.index('<div class="ov-title">Data loss prevention</div>')
        start = grid.rindex('<div class="ov-card"', 0, i)
        nxt = grid.find('<div class="ov-card"', i)
        card = grid[start : nxt if nxt != -1 else len(grid)]
        assert 'data-truth-class="OSS LIVE"' in card
        assert "OSS MACHINERY" not in card

    def test_overview_region_carries_no_banned_claim_words(self):
        """The overview cards describe; no overclaim vocabulary ships."""
        grid = _balanced_body(ADMIN_PANEL_HTML, '<div class="ov-grid" id="overviewGrid">')
        for word in (
            "certified",
            "guaranteed",
            "100%",
            "unbreakable",
            "military-grade",
            "bank-grade",
            "industry-leading",
            "state-of-the-art",
            "next-generation",
        ):
            assert word not in grid.lower(), word

    def test_nav_entry_sits_first_in_the_assurance_stack(self):
        nav = ADMIN_PANEL_HTML[ADMIN_PANEL_HTML.index('data-nav-group="assurance"') :]
        nav = nav[: nav.index("</nav>")]
        assert 'data-tab-id="dlp"' in nav
        assert nav.index('data-tab-id="dlp"') < nav.index('data-tab-id="injection"')


class TestSessionBehaviourTab:
    """D16: the session tab ships the real-machinery views."""

    def test_session_tab_exists_in_the_assurance_stack(self):
        assert 'id="tab-session"' in ADMIN_PANEL_HTML
        assert 'data-tab-id="session"' in ADMIN_PANEL_HTML
        # G9 order: after Prompt Injection, before Shadow AI
        nav = ADMIN_PANEL_HTML[ADMIN_PANEL_HTML.index('data-nav-group="assurance"') :]
        nav = nav[: nav.index("</nav>")]
        assert nav.index('data-tab-id="injection"') < nav.index('data-tab-id="session"')
        assert nav.index('data-tab-id="session"') < nav.index('data-tab-id="shadow"')

    def test_session_tab_declares_the_real_views_and_honest_limits(self):
        body = _tab_sections(ADMIN_PANEL_HTML)["session"]
        for marker in (
            'id="sessionRulesCard"',
            'id="sessionWindowsCard"',
            'id="sessionFindingsCard"',
            'id="sessionRulesBody"',
            'id="sessionWindowsBody"',
            'id="sessionFindingsBody"',
        ):
            assert marker in body, marker
        for limit in (
            "deny-only",
            "process memory",
            "gradual_extraction",
        ):
            assert limit in body, f"honest limit missing from the session tab: {limit}"

    def test_session_findings_offline_verify_is_dispatcher_backed(self):
        assert 'data-hi="sessionFindingVerify(event)"' in ADMIN_PANEL_HTML
        assert '"sessionFindingVerify(event)":(ev,el)=>sessionFindingVerify(ev)' in ADMIN_PANEL_HTML

    def test_session_tab_fetches_the_demo_session_plane(self):
        for endpoint in (
            "/api/demo/session-rules",
            "/api/demo/session-windows",
            "/api/demo/session-findings",
        ):
            assert endpoint in ADMIN_PANEL_HTML, endpoint


class TestMcpScannerTab:
    """D5: the MCP scanner tab runs the real engine with honest labels."""

    def test_mcp_tab_exists_in_the_assurance_stack(self):
        assert 'id="tab-mcp"' in ADMIN_PANEL_HTML
        assert 'data-tab-id="mcp"' in ADMIN_PANEL_HTML
        # G9 order: after Shadow AI, before Cross-org proof
        nav = ADMIN_PANEL_HTML[ADMIN_PANEL_HTML.index('data-nav-group="assurance"') :]
        nav = nav[: nav.index("</nav>")]
        assert nav.index('data-tab-id="shadow"') < nav.index('data-tab-id="mcp"')
        assert nav.index('data-tab-id="mcp"') < nav.index('data-tab-id="assure"')

    def test_mcp_tab_declares_two_modes_and_the_scan_route(self):
        body = _tab_sections(ADMIN_PANEL_HTML)["mcp"]
        for marker in (
            'id="mcpManifestList"',
            'id="mcpManifestText"',
            'id="mcpFindingsCard"',
            'id="mcpFindingsBody"',
            'id="mcpSummary"',
            "Evidence class",
        ):
            assert marker in body, marker
        # Two modes: a canned demo manifest to select, a textarea to paste into.
        assert "paste your own" in body.lower()
        assert "/api/demo/mcp/scan" in ADMIN_PANEL_HTML

    def test_mcp_tab_states_the_honest_limits(self):
        body = _tab_sections(ADMIN_PANEL_HTML)["mcp"]
        for limit in (
            "mints no receipt",
            "Stateless one-shot",
            "256 KiB",
            "simulated",
        ):
            assert limit in body, f"honest limit missing from the mcp tab: {limit}"
