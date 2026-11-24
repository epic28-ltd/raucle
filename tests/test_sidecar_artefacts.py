"""Config-pin tests for the Foundry MCP sidecar artefacts (Q21, phase-22 review).

These are claim-pins, not deploy tests: they assert that the sidecar
arteffacts (APIM policy XML, Bicep template, README walkthrough) state
exactly what they implement and deployable-what-actually-ships. The
artefacts are XML / Bicep / Markdown, so the assertions are
grep-discipline checks over the artefact text.
"""

from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_SIDE = _REPO / "deploy" / "foundry-mcp-sidecar"

_POLICY = (_SIDE / "apim-policy.xml").read_text(encoding="utf-8")
_BICEP = (_SIDE / "bicep" / "main.bicep").read_text(encoding="utf-8")
_README = (_SIDE / "README.md").read_text(encoding="utf-8")


def test_policy_implements_direct_route_guard():
    """The policy must carry a real direct-route deny (or a truthful comment).

    Q21 close 1 chose the implement variant: inspect the incoming Host
    header against the configured MCP-backend hostname named value and
    return a named 403 denial before the call is routed anywhere.
    """
    assert "{{raucle-mcp-backend-host}}" in _POLICY
    # the guard fires on the inbound Host header inspection
    assert 'GetValueOrDefault("Host"' in _POLICY
    # ... and returns a named denial, not a silent route-through
    assert "return-response" in _POLICY
    assert 'code="403"' in _POLICY
    assert "direct_route_denied" in _POLICY


def test_policy_comment_matches_implemented_behaviour():
    """The opening comment must describe routing + the guard, and must not
    claim the policy itself emits receipts (the phase-22 finding: the old
    comment over-claimed a gate-and-receipt forwarder the XML never
    implemented)."""
    # the guard is described, with its honest limits
    assert "direct-route guard" in _POLICY
    # no receipt-claim from the XML itself
    assert "emits a signed" not in _POLICY
    assert "receipt for each ALLOW / DENY decision" not in _POLICY
    # the header contract is flagged as part of the proposed integration
    assert "proposed integration" in _POLICY.lower()
    # the residual is stated in the artefact: the network rule is primary
    assert "inbound network rules remain the primary no-bypass control" in _POLICY


def test_policy_file_is_wellformed_xml():
    """The artefact is pasted into APIM's policy editor: it must parse as
    XML as shipped (the old file carried raw nested double quotes inside
    attribute values and did not)."""
    import xml.etree.ElementTree as ET

    root = ET.parse(_SIDE / "apim-policy.xml").getroot()
    assert root.tag == "policies"
    for section in ("inbound", "backend", "outbound", "on-error"):
        assert root.find(section) is not None


def test_policy_guard_annotated_with_operator_verification():
    """Deploy-time syntax cannot be validated offline per the APIM
    reference ('policy expressions only have limited verification'), so
    the artefact must name the operator verification steps."""
    assert "limited verification" in _POLICY
    assert "API trace" in _POLICY


def test_readme_carries_numbered_network_rule_enforcement_step():
    """Q21 close 2: the network rule is a numbered deployment-acceptance
    step, not an afterthought sentence - enforcement requires BOTH the
    sidecar route AND the MCP server inbound rules; without the rule the
    boundary is advisory."""
    assert "Deployment acceptance" in _README
    assert "1." in _README and "2." in _README and "3." in _README
    assert "inbound network rules" in _README
    assert "egress IP" in _README
    assert "advisory" in _README
    # the direct-call acceptance row comes from the external review, so
    # named (without links)
    assert "external review" in _README


def test_bicep_startup_command_matches_shipped_cli():
    """The template must deploy the command that actually exists:
    `raucle serve` has --host/--port/--mode choices strict|standard|
    permissive only - `--mode foundry-sidecar` is an unshipped executable
    and must never appear as a deployable command."""
    assert "'--mode'" not in _BICEP or "'foundry-sidecar'" not in _BICEP
    assert "'serve'" in _BICEP
    assert "'0.0.0.0'" in _BICEP  # inbound binding, not 127.0.0.1
    assert "'8080'" in _BICEP
    # probes must hit a route the shipped server answers (GET /health);
    # the old /healthz and /readyz paths never existed server-side
    assert "healthz" not in _BICEP
    assert "readyz" not in _BICEP
    assert "'/health'" in _BICEP


def test_bicep_image_pinned_to_current_release_with_provenance():
    """Q21 close 0(iii): the antique mutable v0.12.0 tag must be gone; the
    default pins the current release tag and records the release tag ->
    source-commit provenance per the PyPI attestations, plus the Q9
    digest-capture discipline."""
    assert "ghcr.io/epic28-ltd/raucle:v0.23.8" in _BICEP
    assert "param raucleImage string = 'ghcr.io/epic28-ltd/raucle:v0.23.8'" in _BICEP
    # the antique tag survives nowhere as a quoted reference (only as the
    # pin comment's history note)
    assert "'ghcr.io/epic28-ltd/raucle:v0.12.0'" not in _BICEP
    # the superseded pin survives nowhere as a quoted reference: the bump
    # (re-check F148) replaces both the tag and its provenance commit
    assert "'ghcr.io/epic28-ltd/raucle:v0.23.7'" not in _BICEP
    # provenance comment: release tag resolves to the release commit
    # (27fce30... per the PEP 740 attestation, verified at pin time)
    assert "27fce30497ad07e6605558c2566ccd0da1b9c658" in _BICEP
    assert "imagetools inspect" in _BICEP  # capture-and-pin command
    assert "PEP 740" in _BICEP


def test_readme_labels_forwarder_unshipped():
    """Q21 close 0(i): the directory is the M2-class PROPOSED integration -
    existing components listed, the Foundry MCP forwarder marked unshipped,
    and the unshipped executable never presented as a deploy command."""
    assert "PROPOSED" in _README
    assert "unshipped" in _README.lower()
    assert "raucle serve" in _README  # existing component named
    assert "/gate" in _README  # existing gateway decision endpoint named
    assert "raucle mcp serve" in _README  # existing MCP detector named
    # the unshipped executable may be NAMED in prose (marked unshipped)
    # but never appears as a runnable command: no code fence carries it
    _fences = _README.split("```")
    code_blocks = _fences[1::2]
    assert len(code_blocks) >= 1
    for block in code_blocks:
        assert "foundry-sidecar" not in block
    # the working startup command is stated where the install is described
    assert "raucle serve --host 0.0.0.0 --port 8080" in _README
