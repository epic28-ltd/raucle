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
| `autogen.py` | AutoGen (`autogen-agentchat`) ≥ 0.4 | DOC-ONLY | `gated_tools` is implemented against AutoGen 0.4's tool contract but has no dedicated test file in `tests/` yet — treat as unverified until one lands. |
| `crewai.py` | CrewAI ≥ 1.0 | WIRED | Wrapping-tool gate, fail-closed denial. `tests/test_crewai_integration.py`; quick start: `docs/getting-started/05-crewai.md`. |
| `langchain.py` | LangChain (`langchain-core`) ≥ 0.3 | WIRED | Callback-handler gate. `tests/test_langchain_integration.py`. |
| `openai_agents.py` | OpenAI Agents SDK (`openai-agents`) ≥ 0.1 | WIRED | Input/output guardrails backed by `Scanner`, receipts in a hash-chain sink, fail-closed on scan failure. `tests/test_openai_agents_integration.py` includes a real `Runner.run` tripwire test. |
| `agt.py` | Microsoft Agent Governance Toolkit | DOC-ONLY | `IPolicyProvider` is a *proposal-shape* stub — the upstream PDP plug-in interface does not exist yet (`docs/proposals/agt-pdp-contract.md`). Symbols are documented and stable, but nothing upstream consumes them. |
| `agt_backend.py` | AGT `ExternalPolicyBackend` | DOC-ONLY | Implements the existing AGT backend Protocol, but awaits upstream `microsoft/agent-governance-toolkit#2610`; until then `proof_artefact` / `verification_pointers` are ignored by the AGT evaluator. `tests/test_agt_backend.py`, `tests/test_agt_provider.py` cover the local shape. |
| `qm.py` | QM-class delegation harnesses | WIRED | Task hand-off → gate wiring with bilateral co-signed outcomes. `tests/test_harness_qm.py`; live path in `tests/test_qm_live_integration.py`. |
| `retry_guidance.py` | (cross-adapter) deny→retry guidance | WIRED | O2: deterministic retry guidance derived from the deny's own capability token; honesty rules test-pinned in `tests/test_deny_retry_guidance.py`. |
