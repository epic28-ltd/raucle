# Framework integration matrix

Status of every adapter under `raucle/integrations/`. This file is pinned
by `tests/test_integration_matrix_honesty.py`: every module in the
package must appear here, and every row marked WIRED must name a test
file that actually exists. Do not upgrade a row without both the code
and the evidence.

## Statuses

- **WIRED** — adapter code exists, is exercised by a test file in
  `tests/`, and has a documented quick start in its module docstring.
- **DOC-ONLY** — adapter code exists against a contract that is not (yet)
  shipped by the host framework, or is exercised only lightly; usable,
  but with the stated caveat.
- **PLANNED** — intended, nothing merged; tracked in docs/proposals.

## Rows

| Adapter | Host framework | Status | Evidence / caveat |
| --- | --- | --- | --- |
| `agent_framework.py` | Microsoft Agent Framework ≥ 1.0 | WIRED | `tests/test_agent_framework_integration.py` (`tests/test_agent_framework_real.py` additionally runs the real SDK and must be requested explicitly). Design: `docs/proposals/agent-framework-middleware.md`. |
| `autogen.py` | AutoGen (`autogen-agentchat`) ≥ 0.4 | WIRED | Wrapping-tool gate, fail-closed on missing token / empty `agent_id` / non-`FunctionTool`. `tests/test_autogen_integration.py` (real-SDK contract mocked along AutoGen 0.4's documented `FunctionTool` shape; a real-SDK tripwire test can follow the `agent_framework` pattern). |
| `crewai.py` | CrewAI ≥ 1.0, < 1.16 | WIRED | Wrapping-tool gate, fail-closed denial; unattributed calls deny (bearer mode closed). `tests/test_crewai_integration.py` + `tests/test_attribution_audit.py`, exercised in CI by the integration-extras job; quick start: `docs/getting-started/05-crewai.md`. |
| `langchain.py` | LangChain (`langchain-core`) ≥ 0.3 | WIRED | Callback-handler gate. `tests/test_langchain_integration.py`. |
| `langgraph.py` | LangGraph (`langgraph`) ≥ 0.2 | WIRED | Tool-node layer gate: `RaucleToolNode` (a drop-in `ToolNode`) and `gate_tool`/`gate_tools` for the `ToolNode` / `tools=` layer — the model node is never wrapped, and denials reach the graph through ToolNode's `handle_tool_errors` contract. Optional extra; contract tests run against a faithful stand-in (no langgraph import at module import time). `tests/test_langgraph_integration.py`; quick start: `docs/getting-started/04-langgraph.md`. |
| `openai_agents.py` | OpenAI Agents SDK (`openai-agents`) ≥ 0.19, < 0.26 | WIRED | Input/output guardrails backed by `Scanner`, receipts in a hash-chain sink, fail-closed on scan failure. P2a adds the capability guard (`guard_tool` / `guard_function`): deny-before-interaction on `FunctionTool`s, acting identity pinned or carried on the run context, unattributed calls deny with an honest null. `tests/test_openai_agents_integration.py` (guardrails + real `Runner.run` tripwire; guard suites run in the base matrix via the dev extra and in the P2a extras job) + `tests/test_attribution_audit.py`; quick start: `docs/getting-started/15-openai-agents.md`. |
| `pydantic_ai.py` | Pydantic AI (`pydantic-ai`) ≥ 1.107, < 3 | WIRED | Wrapping-function gate (P2a): signature-preserving `guard_tool`, deny before the function body runs, acting identity pinned or carried on `RunContext.agent.name`; unattributed calls deny (bearer mode closed). `tests/test_pydantic_ai_integration.py` (real framework, offline `TestModel` end-to-end) + `tests/test_attribution_audit.py` + contract stand-ins in `tests/test_integrations_contract.py`; exercised in CI by the integration-extras P2a job; quick start: `docs/getting-started/16-pydantic-ai.md`. |
| `google_adk.py` | Google ADK (`google-adk`) ≥ 1.39, < 3 | WIRED | Wrapping-function gate (P2a) over ADK's `(args, tool_context)` tool shape, `FunctionTool`-compatible, deny before the function body runs, acting identity pinned or carried on the invocation context (ADK agent names joined into the raucle `agent:` scheme); unattributed calls deny with an honest null. `tests/test_google_adk_integration.py` + `tests/test_attribution_audit.py` + contract stand-ins in `tests/test_integrations_contract.py`; exercised in CI by the integration-extras P2a job; quick start: `docs/getting-started/17-google-adk.md`. |
| `agt.py` | Microsoft Agent Governance Toolkit | DOC-ONLY | `IPolicyProvider` is a *proposal-shape* stub — the upstream PDP plug-in interface does not exist yet (`docs/proposals/agt-pdp-contract.md`). Symbols are documented and stable, but nothing upstream consumes them. |
| `agt_backend.py` | AGT `ExternalPolicyBackend` | DOC-ONLY | Implements the existing AGT backend Protocol, but awaits upstream `microsoft/agent-governance-toolkit#2610`; until then `proof_artefact` / `verification_pointers` are ignored by the AGT evaluator. `tests/test_agt_backend.py`, `tests/test_agt_provider.py` cover the local shape. |
| `qm.py` | QM-class delegation harnesses | WIRED | Task hand-off → gate wiring with bilateral co-signed outcomes. `tests/test_harness_qm.py`; live path in `tests/test_qm_live_integration.py`. |
| `retry_guidance.py` | (cross-adapter) deny→retry guidance | WIRED | O2: deterministic retry guidance derived from the deny's own capability token; honesty rules test-pinned in `tests/test_deny_retry_guidance.py`. |
