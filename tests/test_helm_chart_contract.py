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


SIDECAR_DEPLOYMENT = CHART / "templates" / "sidecar-deployment.yaml"
SIDECAR_SERVICE = CHART / "templates" / "sidecar-service.yaml"
SECRET_TEMPLATE = CHART / "templates" / "secret.yaml"


class TestSidecarWiring:
    """X3 slice 4: the chart actually wires the single-writer sidecar.

    Helm is not in CI, so these are source-level assertions on the chart
    files (the same doctrine as the classes above)."""

    def test_values_carry_the_sidecar_knobs(self):
        sidecar = _values()["sidecar"]
        for key in (
            "enabled",
            "replicaCount",
            "port",
            "maxQueue",
            "receiptStoreDir",
            "receiptSegmentMaxBytes",
            "receiptIndexPath",
            "indexCacheMb",
            "secret",
        ):
            assert key in sidecar, f"values.yaml is missing sidecar.{key}"
        assert sidecar["enabled"] is False
        assert sidecar["replicaCount"] == 1, "the sidecar is THE writer: pinned at 1"
        assert sidecar["maxQueue"] == "4096", "chart default must equal the code default"

    def test_gateway_deployment_wires_url_and_secret_in_sidecar_mode(self):
        text = _template()
        assert "{{- if .Values.sidecar.enabled }}" in text
        assert "RAUCLE_RECEIPT_SIDECAR_URL" in text
        assert "RAUCLE_RECEIPT_SIDECAR_SECRET" in text
        # the URL points at the sidecar service, never a public host
        assert "raucle-gateway.fullname" in text

    def test_store_env_rows_are_gated_on_the_sidecar_being_disabled(self):
        """No local store rows render in sidecar mode: the gateway's
        two-writer guard refuses a sidecar URL plus a local projection,
        so the chart must not pass both."""
        text = _template()
        if_pos = text.index("{{- if .Values.sidecar.enabled }}")
        sidecar_pos = text.index("RAUCLE_RECEIPT_SIDECAR_URL")
        else_pos = text.index("{{- else }}", sidecar_pos)
        store_pos = text.index("RAUCLE_RECEIPT_STORE_DIR", else_pos)
        assert if_pos < sidecar_pos < else_pos < store_pos, (
            "the store rows must sit in the {{- else }} branch, behind the sidecar branch"
        )

    def test_gateway_data_mount_is_read_only_in_sidecar_mode(self):
        text = _template()
        assert "readOnly: {{ .Values.sidecar.enabled }}" in text

    def test_sidecar_deployment_is_the_single_writer(self):
        text = SIDECAR_DEPLOYMENT.read_text(encoding="utf-8")
        assert "replicas: {{ .Values.sidecar.replicaCount }}" in text
        assert "type: Recreate" in text, "one writer: never two sidecar pods at once"
        assert 'command: ["raucle", "sidecar"]' in text
        assert "RAUCLE_RECEIPT_SIDECAR_SECRET" in text
        assert "RAUCLE_RECEIPT_SIDECAR_MAX_QUEUE" in text
        assert "persistentVolumeClaim" in text, "the sidecar owns the data volume"
        assert "readOnly: " not in text, "the sidecar mounts the store read-write"

    def test_sidecar_service_is_clusterip_only(self):
        text = SIDECAR_SERVICE.read_text(encoding="utf-8")
        assert "type: ClusterIP" in text, "the sidecar must never be exposed past the cluster"
        assert "raucle-gateway.fullname" in text

    def test_secret_template_carries_the_sidecar_secret_conditionally(self):
        text = SECRET_TEMPLATE.read_text(encoding="utf-8")
        assert "{{- if .Values.sidecar.enabled }}" in text
        assert "RAUCLE_RECEIPT_SIDECAR_SECRET" in text
        assert "sidecar.secret is REQUIRED" in text

    def test_prod_env_example_documents_the_sidecar_vars(self):
        path = Path(__file__).resolve().parents[1] / "deploy" / "prod.env.example"
        text = path.read_text(encoding="utf-8")
        for name in (
            "RAUCLE_RECEIPT_SIDECAR_URL",
            "RAUCLE_RECEIPT_SIDECAR_SECRET",
            "RAUCLE_RECEIPT_SIDECAR_TIMEOUT",
            "RAUCLE_RECEIPT_SIDECAR_MAX_QUEUE",
        ):
            assert name in text, f"{name} missing from deploy/prod.env.example"

    def test_no_include_uses_the_rebound_dot_in_sidecar_templates(self):
        for path in (SIDECAR_DEPLOYMENT, SIDECAR_SERVICE, SECRET_TEMPLATE):
            text = path.read_text(encoding="utf-8")
            for block in re.finditer(
                r"\{\{-\s*with[^}]*\}\}(.*?)\{\{-\s*end\s*\}\}", text, re.DOTALL
            ):
                bad = re.findall(r'include\s+"[^"]+"\s+\.\s*[}|]', block.group(1))
                assert not bad, f"{path.name}: include with rebound dot: {bad}"
