"""Chart contract: the values the gateway needs are actually wired.

Two defects lived here and neither had a test:

1. `{{- with .Values.config.demoKey }}` rebinds `.` to the *value*, so the
   `include "raucle-gateway.fullname" .` inside it received a string and
   `helm template` failed with "can't evaluate field Values in type string".
   The demo key path could never render. `healthKey` had the same bug.
2. The chart did not set `RAUCLE_DEMO_MODE` or the per-route rate limit, so a
   Helm install with a demo key served `/api/demo-key` as 404 (RED-035) and
   ran `/gate` without the documented limit (RED-037).

These are source-level assertions on the chart files: helm is not in CI, and a
`with`-scope mistake is visible in the text.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parents[1] / "deploy" / "helm" / "raucle-gateway"
TEMPLATE = CHART / "templates" / "deployment.yaml"
VALUES = CHART / "values.yaml"


def _template() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


def _values() -> dict:
    return yaml.safe_load(VALUES.read_text(encoding="utf-8"))


class TestNoIncludeInsideWith:
    def test_no_include_uses_the_rebound_dot(self):
        """Inside `with`, `.` is the value, not the root context."""
        text = _template()
        for block in re.finditer(r"\{\{-\s*with[^}]*\}\}(.*?)\{\{-\s*end\s*\}\}", text, re.DOTALL):
            body = block.group(1)
            bad = re.findall(r'include\s+"[^"]+"\s+\.\s*[}|]', body)
            assert not bad, f"include with rebound dot inside a with-block: {bad}"


class TestWiring:
    def test_values_carry_the_gateway_knobs(self):
        cfg = _values()["config"]
        for key in ("demoKey", "demoMode", "gateRouteRateLimit", "gateRateLimit", "trustProxy"):
            assert key in cfg, f"values.yaml is missing config.{key}"

    def test_demo_mode_is_conditional_on_its_value(self):
        text = _template()
        assert "RAUCLE_DEMO_MODE" in text
        assert "{{- if .Values.config.demoMode }}" in text

    def test_route_limit_is_wired(self):
        text = _template()
        assert "RAUCLE_GATE_ROUTE_LIMIT" in text
        assert ".Values.config.gateRouteRateLimit" in text

    def test_trust_proxy_is_optional(self):
        text = _template()
        assert "RAUCLE_TRUST_PROXY" in text
        assert "{{- with .Values.config.trustProxy }}" in text

    def test_default_route_limit_matches_the_documented_default(self):
        """The chart default must not quietly disagree with the code default."""
        assert _values()["config"]["gateRouteRateLimit"] == "200/minute"


class TestProdEnvExample:
    def test_example_names_every_variable_the_remediation_added(self):
        path = Path(__file__).resolve().parents[1] / "deploy" / "prod.env.example"
        text = path.read_text(encoding="utf-8")
        for name in (
            "RAUCLE_ADMIN_KEY_FILE",
            "RAUCLE_DEMO_MODE",
            "RAUCLE_GATE_ROUTE_LIMIT",
            "RAUCLE_TRUST_PROXY",
            "RAUCLE_DATA_ROOT",
            "RAUCLE_SIEM_ALLOW_PRIVATE",
        ):
            assert name in text, f"{name} missing from deploy/prod.env.example"

    def test_example_does_not_carry_a_working_secret(self):
        path = Path(__file__).resolve().parents[1] / "deploy" / "prod.env.example"
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "=" not in stripped:
                continue
            _key, _sep, value = stripped.partition("=")
            assert len(value) < 40 or value.startswith("/"), f"looks like a secret: {stripped}"
