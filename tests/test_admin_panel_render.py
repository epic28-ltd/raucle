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
