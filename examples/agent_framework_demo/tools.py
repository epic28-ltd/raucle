"""Two illustrative tools for the Agent Framework demo.

Both tools are deliberately simple — the demo's point is the middleware,
not the tools. A production deployment would call real APIs from these
functions; the raucle gate inspects the call args before the function runs.
"""

from __future__ import annotations


def lookup_customer(customer_id: str) -> dict:
    """Pretend to look up a customer in a CRM.

    In the demo's policy, this tool is *allowed* under the session token —
    the agent's authorised scope includes customer lookups.
    """
    # In a real deployment: HTTPS GET to /v1/customers/{id} on the bank's
    # internal CRM, with the agent's API token in the Authorization header.
    return {
        "customer_id": customer_id,
        "name": "Emma Smith",
        "tier": "premium",
        "kyc_status": "verified",
    }


def transfer_funds(to: str, amount: float) -> dict:
    """Pretend to initiate a fund transfer.

    In the demo's policy, this tool is *NOT* allowed under the session
    token — the agent's authorised scope is customer lookups only. The
    gate refuses any call to this function before it can run.
    """
    # In a real deployment: HTTPS POST to /v1/payments/transfers on the
    # bank's payments API. This function body should never execute in the
    # demo — the gate intercepts.
    return {  # pragma: no cover - never reached when gate is correctly wired
        "to": to,
        "amount": amount,
        "status": "executed",
    }
