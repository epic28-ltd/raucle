"""Framework-specific integration adapters for raucle.

Each integration is optional and lazy-imports its host framework so that
installing ``raucle`` without the integration's extra does not raise
ImportError at top-level import time. Available adapters:

* ``agent_framework.py`` — Microsoft Agent Framework function middleware
* ``autogen.py`` — AutoGen (agentchat) wrapping-tool gate
* ``crewai.py`` — CrewAI wrapping-tool gate
* ``langchain.py`` — LangChain callback-handler gate
* ``langgraph.py`` — LangGraph tool-node layer gate (``ToolNode`` / ``tools=``)
* ``openai_agents.py`` — OpenAI Agents SDK guardrails
* ``agt.py`` / ``agt_backend.py`` — Microsoft Agent Governance Toolkit
* ``qm.py`` — QM-class delegation harnesses
* ``retry_guidance.py`` — cross-adapter deny→retry guidance

See the integration module docstrings and ``docs/proposals/`` for design
notes, and ``docs/integrations/matrix.md`` (pinned by
``tests/test_integration_matrix_honesty.py``) for the honest status of each.
"""
