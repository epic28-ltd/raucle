"""Q15 deployment-artefact contract: auth and rate-limit posture of the
supplied compose, and the packaging honesty of the adapter extras.

Two artifact classes, the same doctrine as test_helm_chart_contract.py:
source-level assertions on the shipped files. Docker compose is not exercised
in CI either, so the compose env is parsed (not grepped) to prove the entries
are real rather than commented; the packaging pins parse pyproject with
tomllib (stdlib on every CI interpreter, 3.11-3.13, so the pin holds in CI).

Supplied-deployment ruling context: the CODE default RAUCLE_GATE_AUTH=off
with its boot banner stays (local dev); the SUPPLIED compose artefact must
require an explicit authentication choice, hence the :? refusal pattern.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.gateway.yml"
PYPROJECT = ROOT / "pyproject.toml"

# Adapter extras whose modules mint signed capability receipts (the audit +
# capability machinery lazily imports cryptography): Finding 85. The extra
# that ships the adapter must ship its signing dependency too.
ADAPTER_EXTRAS = (
    "agent-framework",
    "openai-agents",
    "langchain",
    "autogen",
    "crewai",
    "langgraph",
    "pydantic-ai",
    "google-adk",
)


def _compose_text() -> str:
    return COMPOSE.read_text(encoding="utf-8")


def _compose_gateway_env() -> dict[str, str]:
    import yaml

    doc = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    rows = doc["services"]["raucle-gateway"]["environment"]
    env: dict[str, str] = {}
    for row in rows:
        row = str(row)
        key, _sep, value = row.partition("=")
        env[key] = value
    return env


class TestComposeRequiresAnAuthChoice:
    """The reviewer's Patch A pattern: compose refuses to start without the
    operator choosing an authentication mode."""

    def test_gate_auth_is_refusal_gated(self):
        text = _compose_text()
        assert "RAUCLE_GATE_AUTH=${RAUCLE_GATE_AUTH:?Set to apikey or token}" in text

    def test_gate_auth_is_in_the_parsed_environment(self):
        env = _compose_gateway_env()
        assert env["RAUCLE_GATE_AUTH"] == "${RAUCLE_GATE_AUTH:?Set to apikey or token}"

    def test_comments_point_at_the_provisioning_runbook(self):
        text = _compose_text()
        assert "docs/getting-started/20-production-hardening.md" in text
        assert "issue-key" in text

    def test_demo_service_honestly_discloses_its_auth_gap(self):
        text = _compose_text()
        assert "demo-agents" in text
        assert "receipted DENY" in text


class TestComposeRateLimitPosture:
    """Rate limiting that a public HTTPS listener can rely on."""

    def test_rate_limit_default_is_200_per_minute(self):
        text = _compose_text()
        assert "RAUCLE_GATE_RATE_LIMIT=${RAUCLE_GATE_RATE_LIMIT:-200/minute}" in text
        # The old 60000/minute posture is gone, not just moved.
        assert "60000" not in text
        # Still env-overridable at deploy time.
        env = _compose_gateway_env()
        assert env["RAUCLE_GATE_RATE_LIMIT"] == "${RAUCLE_GATE_RATE_LIMIT:-200/minute}"

    def test_route_limit_is_explicit(self):
        env = _compose_gateway_env()
        assert env["RAUCLE_GATE_ROUTE_LIMIT"] == "${RAUCLE_GATE_ROUTE_LIMIT:-200/minute}"

    def test_trust_proxy_is_set_for_the_supplied_caddy_topology(self):
        text = _compose_text()
        assert "RAUCLE_TRUST_PROXY=${RAUCLE_TRUST_PROXY:-1}" in text
        # The composer must be told WHY: without it every external caller
        # collapses into the proxy's one shared bucket.
        assert "X-Forwarded-For" in text
        assert "shared" in text.lower()
        assert "trust" in text.lower()

    def test_tool_schema_manifest_is_documented_not_forced(self):
        text = _compose_text()
        # Commented-but-real: the entry exists with operator guidance.
        assert "RAUCLE_TOOL_SCHEMA_MANIFEST=/etc/raucle/tools-manifest.json" in text
        assert "tool manifest" in text.lower()
        # ...but it stays inactive: the code default preserves legacy behaviour.
        env = _compose_gateway_env()
        assert "RAUCLE_TOOL_SCHEMA_MANIFEST" not in env


class TestComposeRateLimiterPresence:
    """slowapi rides in the [server] extra the image installs, so the
    serving-mode refusal cannot fire in the supplied artifact."""

    def test_comment_names_the_image_extra_story(self):
        text = _compose_text()
        assert "[server]" in text
        assert "slowapi" in text
        assert "RAUCLE_DISABLE_RATE_LIMIT" in text


def _extras() -> dict[str, list[str]]:
    tomllib = pytest.importorskip("tomllib")  # stdlib from 3.11; CI is 3.11-3.13
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["optional-dependencies"]


class TestAdapterExtrasCarryTheSigningMachinery:
    """Finding 85 (phase-14 review): pip install "raucle[agent-framework]"
    shipped the adapter without the signing/capability machinery its docstring
    and README narrative promise. The adapter emits SIGNED capability receipts;
    the cryptography dependency rides with the extra."""

    @pytest.mark.parametrize("extra", ADAPTER_EXTRAS)
    def test_extra_includes_cryptography(self, extra: str):
        deps = _extras()[extra]
        assert any(dep.startswith("cryptography>=") for dep in deps), deps

    def test_agent_framework_keeps_its_adapter_requirement(self):
        deps = _extras()["agent-framework"]
        assert "agent-framework>=1.0" in deps, deps
        assert "cryptography>=42.0" in deps, deps

    def test_core_dependencies_stay_empty(self):
        """The zero-mandatory-dependency contract is untouched."""
        text = PYPROJECT.read_text(encoding="utf-8")
        row = re.search(r"^dependencies = \[\]$", "\n".join(text.splitlines()), re.M)
        assert row is not None
