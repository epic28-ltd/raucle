#!/usr/bin/env python3
"""Raucle Gateway demo traffic simulator.

Feeds the gateway a continuous, realistic mix of agent tool calls so the
admin panel, topology view, connection log, and receipts stay live for
demonstrations (Sovereign AI demonstrator stage, evaluator accounts).

Scenarios (choose one with --scenario):
  banking    — payments, cards, loans, sanctions (banking-payments.yaml)
  government — benefits, tax, planning, border, DBS, FOI
               (government-public-sector.yaml)
  health     — clinical records, prescribing, imaging, labs
               (healthcare-medical.yaml)
  all        — cycles through every scenario (default for the shared demo)

Traffic profile (per cycle):
  - ~70% benign calls that policies ALLOW
  - ~30% over-threshold or malformed calls the gate DENIES with specific
    reasons, plus occasional injection-style attempts (unknown tools)

Usage:
    python demo_agents.py --gateway http://localhost:8080 --scenario banking

Runs forever until interrupted; designed for a systemd service or
docker-compose sidecar. No credentials needed: /gate is the agent-facing
endpoint (rate-limited, not secret-bearing).
"""

from __future__ import annotations

import argparse
import json
import random
import signal
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Scenario definitions. Task = (tool, args, destination). Benign tasks match a
# policy rule exactly; denial tasks break exactly one constraint so the demo
# shows specific gate reasons. Injection attempts use unknown tools.
# ---------------------------------------------------------------------------

BANKING = [
    {
        "agent_id": "agent:customer-service",
        "source": "agent:customer-service",
        "name": "Customer Service Bot",
        "benign": [
            ("lookup_balance", {"account": "ACC-003"}, "banking-core"),
            ("lookup_balance", {"account": "ACC-001"}, "banking-core"),
            ("lookup_transaction_history", {"account": "ACC-001", "days": 30}, "banking-core"),
        ],
        "deny": [
            ("lookup_balance", {"account": "ACC-777"}, "banking-core"),
            ("lookup_transaction_history", {"account": "ACC-001", "days": 365}, "banking-core"),
        ],
    },
    {
        "agent_id": "agent:payments-bot",
        "source": "agent:payments-bot",
        "name": "Payments Bot",
        "benign": [
            (
                "transfer_internal",
                {"from_account": "ACC-001", "to_account": "ACC-003", "amount": 2500},
                "internal-ledger",
            ),
            (
                "transfer_external",
                {
                    "from_account": "ACC-001",
                    "to_account": "ACC-003",
                    "amount": 1200,
                    "reference": "INV-2026-001",
                },
                "swift-network",
            ),
            (
                "transfer_internal",
                {"from_account": "ACC-002", "to_account": "ACC-004", "amount": 800},
                "internal-ledger",
            ),
        ],
        "deny": [
            (
                "transfer_internal",
                {"from_account": "ACC-001", "to_account": "ACC-003", "amount": 50000},
                "internal-ledger",
            ),
            (
                "transfer_external",
                {
                    "from_account": "ACC-001",
                    "to_account": "BLACKLIST-001",
                    "amount": 100,
                    "reference": "x",
                },
                "swift-network",
            ),
        ],
    },
    {
        "agent_id": "agent:card-management",
        "source": "agent:card-mgmt-bot",
        "name": "Card Management Agent",
        "benign": [
            (
                "block_card",
                {"card_id": "CARD-001", "reason": "customer reported fraud"},
                "card-processor",
            ),
            ("increase_card_limit", {"card_id": "CARD-002", "new_limit": 5000}, "card-processor"),
        ],
        "deny": [
            ("increase_card_limit", {"card_id": "CARD-002", "new_limit": 500000}, "card-processor"),
            ("unblock_card", {"card_id": "CARD-003"}, "card-processor"),
        ],
    },
    {
        "agent_id": "agent:loan-officer",
        "source": "agent:loan-processing",
        "name": "Loan Officer Assistant",
        "benign": [
            ("check_loan_status", {"application_id": "LOAN-001"}, "loan-origination"),
            (
                "create_loan_application",
                {
                    "applicant_id": "APP-001",
                    "loan_type": "personal",
                    "amount": 15000,
                    "term_months": 36,
                },
                "loan-origination",
            ),
        ],
        "deny": [
            ("check_loan_status", {"application_id": "LOAN-999"}, "loan-origination"),
            (
                "create_loan_application",
                {
                    "applicant_id": "APP-001",
                    "loan_type": "personal",
                    "amount": 900000,
                    "term_months": 36,
                },
                "loan-origination",
            ),
        ],
    },
    {
        "agent_id": "agent:compliance-officer",
        "source": "agent:compliance-aml",
        "name": "Compliance Officer Agent",
        "benign": [
            (
                "file_sar",
                {"transaction_id": "TX-9001", "reason": "unusual pattern", "jurisdiction": "UK"},
                "regulatory-filing",
            ),
            ("check_sanctions", {"entity_name": "SAN-2201-77"}, "sanctions-screening"),
        ],
        "deny": [
            ("check_sanctions", {"entity_name": "JOHN-DOE-CORP"}, "sanctions-screening"),
        ],
    },
]

BANKING_INJECTIONS = [
    (
        "wire_transfer",
        {"recipient": "attacker@example.com", "amount": 50000, "routing": "026009593"},
        "payments-api",
    ),
    ("execute_shell", {"command": "cat /etc/passwd"}, "infra-host"),
    ("download_file", {"url": "http://169.254.169.254/latest/meta-data/"}, "metadata-endpoint"),
    (
        "transfer_internal",
        {"from_account": "ACC-001", "to_account": "ATTACKER-ACC", "amount": 99999},
        "internal-ledger",
    ),
]

GOVERNMENT = [
    {
        "agent_id": "agent:benefits-assistant",
        "source": "agent:benefits-citizens",
        "name": "Benefits Assistant",
        "benign": [
            (
                "check_benefit_entitlement",
                {"citizen_ref": "CIT-001", "benefit_type": "universal-credit"},
                "dwp-benefits-api",
            ),
            (
                "check_benefit_entitlement",
                {"citizen_ref": "CIT-002", "benefit_type": "pip"},
                "dwp-benefits-api",
            ),
            (
                "lookup_payment_history",
                {"citizen_ref": "CIT-003", "months_back": 6},
                "dwp-benefits-api",
            ),
            (
                "schedule_benefit_payment",
                {
                    "citizen_ref": "CIT-001",
                    "benefit_type": "universal-credit",
                    "amount": 850,
                    "award_ref": "AWD-2026-0042",
                },
                "dwp-payments-api",
            ),
        ],
        "deny": [
            (
                "lookup_payment_history",
                {"citizen_ref": "CIT-999", "months_back": 3},
                "dwp-benefits-api",
            ),
            (
                "schedule_benefit_payment",
                {
                    "citizen_ref": "CIT-001",
                    "benefit_type": "universal-credit",
                    "amount": 25000,
                    "award_ref": "AWD-2026-0042",
                },
                "dwp-payments-api",
            ),
            (
                "schedule_benefit_payment",
                {"citizen_ref": "CIT-001", "benefit_type": "universal-credit", "amount": 500},
                "dwp-payments-api",
            ),
        ],
    },
    {
        "agent_id": "agent:tax-assistant",
        "source": "agent:tax-hmrc",
        "name": "Tax Assistant",
        "benign": [
            ("lookup_tax_account", {"utr": "UTR-1001"}, "hmrc-core"),
            (
                "calculate_tax_estimate",
                {"annual_income": 48000, "tax_year": "2026-27"},
                "hmrc-calculator",
            ),
            (
                "submit_self_assessment",
                {"utr": "UTR-1002", "filing_status": "draft"},
                "hmrc-filing",
            ),
        ],
        "deny": [
            ("lookup_tax_account", {"utr": "UTR-9999"}, "hmrc-core"),
            (
                "submit_self_assessment",
                {"utr": "UTR-1001", "filing_status": "backdated-amendment"},
                "hmrc-filing",
            ),
        ],
    },
    {
        "agent_id": "agent:casework-officer",
        "source": "agent:casework-planning",
        "name": "Casework Officer",
        "benign": [
            (
                "retrieve_planning_application",
                {"application_ref": "PLAN-2026-0331", "application_type": "householder"},
                "planning-portal",
            ),
            (
                "update_case_notes",
                {
                    "case_ref": "CASE-77123",
                    "case_type": "planning",
                    "note_content": "Site visit completed; neighbour objections noted.",
                },
                "case-management",
            ),
            (
                "recommend_decision",
                {"case_ref": "CASE-77123", "recommendation": "request-more-info"},
                "case-management",
            ),
        ],
        "deny": [
            (
                "retrieve_planning_application",
                {"application_ref": "PLAN-2026-0331", "application_type": "high-rise"},
                "planning-portal",
            ),
            (
                "update_case_notes",
                {"case_ref": "CASE-77123", "case_type": "planning", "note_content": "x" * 20000},
                "case-management",
            ),
            (
                "recommend_decision",
                {"case_ref": "CASE-77123", "recommendation": "approve"},
                "case-management",
            ),
        ],
    },
    {
        "agent_id": "agent:border-officer",
        "source": "agent:border-control",
        "name": "Border Status Agent",
        "benign": [
            (
                "check_immigration_status",
                {"person_ref": "PRS-5521", "check_purpose": "port-entry", "officer_id": "OFF-2044"},
                "home-office-status",
            ),
        ],
        "deny": [
            (
                "check_immigration_status",
                {
                    "person_ref": "PRS-5521",
                    "check_purpose": "curiosity-browse",
                    "officer_id": "OFF-2044",
                },
                "home-office-status",
            ),
            (
                "check_immigration_status",
                {
                    "person_ref": "PRS-9000",
                    "check_purpose": "asylum-claim-review",
                    "record_class": "asylum",
                    "officer_id": "OFF-2044",
                },
                "home-office-status",
            ),
        ],
    },
    {
        "agent_id": "agent:foi-processor",
        "source": "agent:foi-desk",
        "name": "FOI Processor",
        "benign": [
            ("search_foi_register", {"search_term": "school admissions 2025"}, "foi-register"),
            (
                "draft_foi_response",
                {"request_ref": "FOI-2026-0089", "response_type": "full-disclosure"},
                "foi-register",
            ),
        ],
        "deny": [
            (
                "draft_foi_response",
                {"request_ref": "FOI-2026-0090", "response_type": "exempt-section-23"},
                "foi-register",
            ),
            (
                "draft_foi_response",
                {"request_ref": "FOI-2026-0091", "response_type": "exempt-section-31"},
                "foi-register",
            ),
        ],
    },
]

GOVERNMENT_INJECTIONS = [
    ("bulk_export_citizens", {"dataset": "universal-credit-full", "format": "csv"}, "data-lake"),
    ("execute_shell", {"command": "cat /etc/shadow"}, "infra-host"),
    (
        "modify_voting_record",
        {"constituency": "any", "field": "registration"},
        "electoral-register",
    ),
    (
        "request_dbs_check",
        {
            "applicant_ref": "APL-0001",
            "check_level": "enhanced",
            "position_applied_for": "teacher",
            "employer_ref": "",
        },
        "dbs-service",
    ),
]

HEALTH = [
    {
        "agent_id": "agent:clinical-assistant",
        "source": "agent:clinical-ward",
        "name": "Clinical Assistant",
        "benign": [
            (
                "read_patient_record",
                {
                    "patient_id": "NHS-9433811",
                    "department": "cardiology",
                    "clinical_reason": "chest pain assessment",
                },
                "nhs-clinical-records",
            ),
            (
                "order_lab_test",
                {
                    "patient_id": "NHS-9433811",
                    "test_type": "blood-count",
                    "clinical_reason": "pre-operative workup",
                },
                "pathology-labs",
            ),
            (
                "review_lab_results",
                {"patient_id": "NHS-9433811", "test_id": "LAB-2026-00421"},
                "pathology-labs",
            ),
            (
                "book_appointment",
                {
                    "patient_id": "NHS-8433811",
                    "department": "general-medicine",
                    "appointment_type": "follow-up",
                },
                "appointments",
            ),
        ],
        "deny": [
            (
                "read_patient_record",
                {
                    "patient_id": "NHS-9433811",
                    "department": "psychiatry",
                    "clinical_reason": "research interest",
                },
                "nhs-clinical-records",
            ),
            (
                "read_patient_record",
                {
                    "patient_id": "NHS-9433811",
                    "department": "cardiology",
                    "record_type": "hiv",
                    "clinical_reason": "not clinically indicated",
                },
                "nhs-clinical-records",
            ),
            (
                "order_imaging",
                {
                    "patient_id": "NHS-9433811",
                    "scan_type": "pet-scan",
                    "clinical_reason": "routine screening",
                    "ordering_clinician_id": "DR-2201",
                },
                "radiology-pacs",
            ),
        ],
    },
    {
        "agent_id": "agent:pharmacy-bot",
        "source": "agent:pharmacy-dispense",
        "name": "Pharmacy Agent",
        "benign": [
            (
                "prescribe_medication",
                {
                    "patient_id": "NHS-9433811",
                    "medication_name": "amoxicillin",
                    "medication_class": "antibiotic",
                    "dosage_mg": 500,
                    "duration_days": 7,
                    "prescribing_clinician_id": "DR-2201",
                },
                "pharmacy-system",
            ),
            (
                "prescribe_controlled",
                {
                    "patient_id": "NHS-9433811",
                    "medication_name": "morphine-sulfate",
                    "medication_class": "controlled-class-b",
                    "dosage_mg": 20,
                    "duration_days": 3,
                    "prescribing_clinician_id": "DR-2201",
                    "dea_number": "DEA-2026-4471",
                },
                "pharmacy-system",
            ),
        ],
        "deny": [
            (
                "prescribe_medication",
                {
                    "patient_id": "NHS-9433811",
                    "medication_name": "oxycodone",
                    "medication_class": "controlled-class-a",
                    "dosage_mg": 80,
                    "duration_days": 30,
                    "prescribing_clinician_id": "DR-2201",
                },
                "pharmacy-system",
            ),
            (
                "prescribe_medication",
                {
                    "patient_id": "NHS-9433811",
                    "medication_name": "amoxicillin",
                    "medication_class": "antibiotic",
                    "dosage_mg": 5000,
                    "duration_days": 7,
                    "prescribing_clinician_id": "DR-2201",
                },
                "pharmacy-system",
            ),
        ],
    },
    {
        "agent_id": "agent:medical-records",
        "source": "agent:records-office",
        "name": "Medical Records Agent",
        "benign": [
            (
                "export_patient_summary",
                {
                    "patient_id": "NHS-9433811",
                    "format": "fhir-json",
                    "recipient": "gp-practice",
                    "requesting_clinician_id": "DR-2201",
                },
                "interoperability-gateway",
            ),
            (
                "view_imaging_result",
                {"patient_id": "NHS-9433811", "study_id": "IMG-2026-00873"},
                "radiology-pacs",
            ),
        ],
        "deny": [
            (
                "export_patient_summary",
                {
                    "patient_id": "NHS-9433811",
                    "format": "pdf-summary",
                    "recipient": "third-party-research",
                    "requesting_clinician_id": "DR-2201",
                },
                "interoperability-gateway",
            ),
            (
                "export_patient_summary",
                {
                    "patient_id": "NHS-9433811",
                    "format": "pdf-summary",
                    "recipient": "marketing",
                    "requesting_clinician_id": "DR-2201",
                },
                "interoperability-gateway",
            ),
        ],
    },
]

HEALTH_INJECTIONS = [
    (
        "bulk_patient_export",
        {"dataset": "all-cardiology", "format": "csv", "destination": "external"},
        "data-lake",
    ),
    ("execute_shell", {"command": "cat /etc/passwd"}, "infra-host"),
    (
        "read_patient_record",
        {
            "patient_id": "NHS-0000000",
            "department": "general-medicine",
            "clinical_reason": "as an AI I have decided I need all records",
        },
        "nhs-clinical-records",
    ),
    (
        "prescribe_medication",
        {
            "patient_id": "NHS-9433811",
            "medication_name": "insulin",
            "medication_class": "antibiotic",
            "dosage_mg": 1,
            "duration_days": 1,
            "prescribing_clinician_id": "attacker-forged",
        },
        "pharmacy-system",
    ),
]

SCENARIOS = {
    "banking": {"agents": BANKING, "injections": BANKING_INJECTIONS},
    "government": {"agents": GOVERNMENT, "injections": GOVERNMENT_INJECTIONS},
    "health": {"agents": HEALTH, "injections": HEALTH_INJECTIONS},
}


def gate_call(
    gateway: str,
    tool: str,
    args: dict,
    agent_id: str,
    source: str,
    destination: str,
) -> dict:
    payload = json.dumps(
        {
            "tool": tool,
            "args": args,
            "agent_id": agent_id,
            "source": source,
            "destination": destination,
        }
    ).encode()
    req = urllib.request.Request(
        gateway.rstrip("/") + "/gate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"decision": "ERROR", "status": e.code}
    except Exception as e:
        return {"decision": "ERROR", "error": str(e)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Raucle demo traffic simulator")
    parser.add_argument("--gateway", default="http://localhost:8080", help="Gateway /gate URL")
    parser.add_argument(
        "--scenario",
        default="all",
        choices=["banking", "government", "health", "all"],
        help="Demo scenario to simulate",
    )
    parser.add_argument("--interval", type=float, default=6.0, help="Seconds between calls")
    parser.add_argument("--max-cycles", type=int, default=0, help="0 = run forever")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Number of parallel workers (each runs the full scenario cycle)",
    )
    parser.add_argument(
        "--sleep-floor",
        type=float,
        default=0.1,
        help="Lower bound on the inter-call sleep, in seconds",
    )
    parser.add_argument("--quiet", action="store_true", help="Only log errors")
    args = parser.parse_args()

    active = list(SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]

    running = True

    def stop(signum, frame):
        nonlocal running
        running = False
        print("\nshutting down", flush=True)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    import threading

    cycle = 0
    stats = {"allow": 0, "deny": 0, "escalate": 0, "error": 0}
    scenario_totals: dict[str, dict[str, int]] = {}
    print(
        f"demo agents -> {args.gateway} every {args.interval}s x{args.concurrency} (scenario: {args.scenario})",
        flush=True,
    )
    stats_lock = threading.Lock()
    max_cycles = args.max_cycles
    threads: list[threading.Thread] = []

    def worker(tid: int) -> None:
        nonlocal cycle
        while running and (max_cycles == 0 or cycle < max_cycles):
            with stats_lock:
                if max_cycles and cycle >= max_cycles:
                    return
                cycle += 1
                this_cycle = cycle
            scenario = active[this_cycle % len(active)]
            spec = SCENARIOS[scenario]
            agent = random.choice(spec["agents"])

            if random.random() < 0.14:
                tool, task_args, destination = random.choice(spec["injections"])
            else:
                pool = agent["benign"] * 3 + agent.get("deny", [])
                tool, task_args, destination = random.choice(pool)

            result = gate_call(
                args.gateway,
                tool,
                task_args,
                agent["agent_id"],
                agent["source"],
                destination,
            )
            decision = str(result.get("decision", "ERROR")).upper()
            key = decision.lower()
            if key not in stats:
                key = "error"

            with stats_lock:
                stats[key] += 1
                s = scenario_totals.setdefault(scenario, {"allow": 0, "deny": 0, "error": 0})
                s[key if key in s else "error"] += 1

            if not args.quiet:
                reason = str(result.get("reason", ""))[:50]
                print(
                    f"  [t{tid}][{scenario[:4]}] {agent['name'][:22]:22} "
                    f"{tool[:26]:26} -> {decision:8} {reason}",
                    flush=True,
                )

            time.sleep(
                max(
                    args.sleep_floor,
                    args.interval + random.uniform(-args.interval * 0.3, args.interval * 0.3),
                )
            )

    for tid in range(max(1, args.concurrency)):
        t = threading.Thread(target=worker, args=(tid,), daemon=True)
        threads.append(t)
        t.start()
        if args.concurrency > 1 and tid < args.concurrency - 1:
            time.sleep(random.uniform(0.05, 0.2))  # desynchronise the workers
    for t in threads:
        t.join()

    print(f"final: {stats} over {cycle} cycles", flush=True)
    for sc, tot in scenario_totals.items():
        print(f"  {sc}: {tot}", flush=True)


if __name__ == "__main__":
    main()
