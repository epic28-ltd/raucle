"""Offline policy regression runner for consumer-authored scenarios.

The runner loads the exact policy bytes supplied by a consumer, validates
them through the canonical PolicyFile contract, and evaluates explicit
allow/deny/escalate scenarios through RaucleGateway. Reports bind the raw
policy, scenario and suite-manifest bytes by SHA-256 and deliberately omit
argument values and free-text decision reasons.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

REPORT_SCHEMA_VERSION = 1
SUITE_VERSION = "1.0.0"
MAX_INPUT_BYTES = 1_048_576
MAX_SCENARIOS = 500
_ALLOWED_DECISIONS = frozenset({"allow", "deny", "escalate"})
_ALLOWED_SCENARIO_FIELDS = frozenset(
    {"id", "tool", "agent_id", "args", "expected", "source", "destination"}
)
_ENGINE_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class RegressionInputError(ValueError):
    """A named, bounded refusal for malformed consumer input."""


class RegressionEnvironmentError(RuntimeError):
    """A missing runtime dependency or environment prerequisite."""


class RegressionExecutionError(RuntimeError):
    """An engine failure that retains truthful results from completed scenarios."""

    def __init__(
        self,
        results: list[dict[str, Any]],
        *,
        policy_sha256: str,
        scenarios_sha256: str,
        engine_version: str,
        dependency_versions: dict[str, str],
    ) -> None:
        super().__init__("engine_error")
        self.results = results
        self.policy_sha256 = policy_sha256
        self.scenarios_sha256 = scenarios_sha256
        self.engine_version = engine_version
        self.dependency_versions = dependency_versions


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bounded(path: str | Path, label: str) -> bytes:
    """Read at most MAX_INPUT_BYTES + 1, so the bound applies before allocation.

    The path is canonicalised before any read: tilde expansion and traversal
    components collapse onto the physical target, and the read hits exactly
    that canonical file (pythonsecurity:S8707 CLI-input pattern).
    """
    try:
        source = Path(path).expanduser().resolve()
        if not source.is_file():
            raise RegressionInputError(f"{label}_not_a_file")
        with source.open("rb") as handle:
            data = handle.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        raise RegressionInputError(f"{label}_unreadable") from exc
    if len(data) > MAX_INPUT_BYTES:
        raise RegressionInputError(f"{label}_too_large")
    if not data:
        raise RegressionInputError(f"{label}_empty")
    return data


def _load_suite_manifest() -> tuple[dict[str, Any], bytes]:
    path = Path(__file__).with_name("policy_regression_suites.json")
    try:
        raw = path.read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("suite_manifest_unavailable") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 1
        or manifest.get("suite_version") != SUITE_VERSION
        or not isinstance(manifest.get("suites"), list)
        or len(manifest["suites"]) != 1
        or not isinstance(manifest.get("unsupported_suites"), list)
    ):
        raise RuntimeError("suite_manifest_invalid")
    suite = manifest["suites"][0]
    if not isinstance(suite, dict) or not isinstance(suite.get("id"), str):
        raise RuntimeError("suite_manifest_invalid")
    return manifest, raw


def _parse_scenarios(raw: bytes) -> list[dict[str, Any]]:
    def reject_constant(_value: str) -> None:
        raise RegressionInputError("scenarios_invalid_json_constant")

    try:
        document = json.loads(raw.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegressionInputError("scenarios_invalid_json") from exc
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("version"), int)
        or isinstance(document.get("version"), bool)
        or document.get("version") != 1
    ):
        raise RegressionInputError("scenarios_unsupported_version")
    scenarios = document.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise RegressionInputError("scenarios_required")
    if len(scenarios) > MAX_SCENARIOS:
        raise RegressionInputError("scenarios_too_many")

    seen_ids: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, item in enumerate(scenarios):
        if not isinstance(item, dict) or set(item) - _ALLOWED_SCENARIO_FIELDS:
            raise RegressionInputError(f"scenario_{index}_invalid_fields")
        scenario_id = item.get("id")
        tool = item.get("tool")
        agent_id = item.get("agent_id")
        args = item.get("args")
        expected = item.get("expected")
        if not isinstance(scenario_id, str) or not scenario_id.strip():
            raise RegressionInputError(f"scenario_{index}_invalid_id")
        if scenario_id in seen_ids:
            raise RegressionInputError(f"scenario_{index}_duplicate_id")
        seen_ids.add(scenario_id)
        if not isinstance(tool, str) or not tool.strip():
            raise RegressionInputError(f"scenario_{index}_invalid_tool")
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise RegressionInputError(f"scenario_{index}_invalid_agent_id")
        if not isinstance(args, dict):
            raise RegressionInputError(f"scenario_{index}_invalid_args")
        if not isinstance(expected, str) or expected not in _ALLOWED_DECISIONS:
            raise RegressionInputError(f"scenario_{index}_invalid_expected")
        for optional in ("source", "destination"):
            value = item.get(optional, "")
            if not isinstance(value, str):
                raise RegressionInputError(f"scenario_{index}_invalid_{optional}")
        validated.append(
            {
                "id": scenario_id,
                "tool": tool,
                "agent_id": agent_id,
                "args": args,
                "expected": expected,
                "source": item.get("source", ""),
                "destination": item.get("destination", ""),
            }
        )
    return validated


def _validate_policy(raw: bytes) -> None:
    try:
        import yaml

        from raucle.policy import PolicyFile
    except ImportError as exc:
        raise RegressionEnvironmentError("dependency_unavailable") from exc

    try:
        parsed = yaml.safe_load(raw)
        if not isinstance(parsed, dict):
            raise ValueError("policy must be a mapping")
        policy = PolicyFile.from_dict(parsed)
        rules = getattr(policy, "policies", None)
        if rules is not None and not rules:
            raise ValueError("policy must contain at least one rule")
    except Exception as exc:
        raise RegressionInputError("policy_invalid") from exc


def run_regression(
    policy_bytes: bytes,
    scenarios_bytes: bytes,
    *,
    engine_commit: str = "unavailable",
) -> dict[str, Any]:
    """Evaluate consumer scenarios against the exact supplied policy bytes."""
    if not policy_bytes or len(policy_bytes) > MAX_INPUT_BYTES:
        raise RegressionInputError("policy_empty_or_too_large")
    if not scenarios_bytes or len(scenarios_bytes) > MAX_INPUT_BYTES:
        raise RegressionInputError("scenarios_empty_or_too_large")
    if engine_commit != "unavailable" and not _ENGINE_COMMIT_RE.fullmatch(engine_commit):
        raise RegressionInputError("engine_commit_invalid")

    _validate_policy(policy_bytes)
    scenarios = _parse_scenarios(scenarios_bytes)
    manifest, manifest_bytes = _load_suite_manifest()
    engine_version = importlib.metadata.version("raucle")
    dependency_versions = {
        "raucle": engine_version,
        "PyYAML": importlib.metadata.version("PyYAML"),
        "cryptography": importlib.metadata.version("cryptography"),
        "cffi": importlib.metadata.version("cffi"),
        "pycparser": importlib.metadata.version("pycparser"),
    }

    from raucle.gateway import GatewayConfig, RaucleGateway

    suite_id = manifest["suites"][0]["id"]
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="raucle-policy-regression-") as directory:
        root = Path(directory)
        policy_path = root / "consumer-policy.yaml"
        policy_path.write_bytes(policy_bytes)
        config = GatewayConfig(
            policy_file=str(policy_path),
            receipt_store=str(root / "receipts.jsonl"),
            audit_chain=str(root / "audit.jsonl"),
            signer_backend="local",
            gate_auth="off",
            policy_seal_file="",
        )
        # Disable opt-in chaos and policy sealing for this isolated offline
        # test process. The runner never starts a server or makes a network call.
        with patch.dict(
            os.environ,
            {
                "RAUCLE_ENV": "test",
                "RAUCLE_CHAOS": "0",
                "RAUCLE_GATE_AUTH": "off",
                "RAUCLE_POLICY_SEALING": "off",
            },
        ):
            gateway = RaucleGateway(config)
            for scenario in scenarios:
                try:
                    decision = gateway.check_tool_call(
                        scenario["tool"],
                        scenario["args"],
                        agent_id=scenario["agent_id"],
                        source=scenario["source"],
                        destination=scenario["destination"],
                        trace_id=f"policy-regression:{scenario['id']}",
                    )
                except Exception as exc:
                    raise RegressionExecutionError(
                        results,
                        policy_sha256=_sha256(policy_bytes),
                        scenarios_sha256=_sha256(scenarios_bytes),
                        engine_version=engine_version,
                        dependency_versions=dependency_versions,
                    ) from exc
                actual = decision.get("decision")
                if actual not in _ALLOWED_DECISIONS:
                    raise RegressionExecutionError(
                        results,
                        policy_sha256=_sha256(policy_bytes),
                        scenarios_sha256=_sha256(scenarios_bytes),
                        engine_version=engine_version,
                        dependency_versions=dependency_versions,
                    )
                results.append(
                    {
                        "suite_id": suite_id,
                        "scenario_id": scenario["id"],
                        "tool": scenario["tool"],
                        "expected": scenario["expected"],
                        "actual": actual,
                        "passed": actual == scenario["expected"],
                    }
                )

    passed = sum(1 for result in results if result["passed"])
    failed = len(results) - passed
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "suite_version": manifest["suite_version"],
        "suite_manifest_sha256": _sha256(manifest_bytes),
        "engine_version": engine_version,
        "dependency_versions": dependency_versions,
        "engine_commit": engine_commit,
        "policy_sha256": _sha256(policy_bytes),
        "scenarios_sha256": _sha256(scenarios_bytes),
        "status": "passed" if failed == 0 else "failed",
        "summary": {"total": len(results), "passed": passed, "failed": failed},
        "executed": results,
        "skipped": [],
        "unsupported_suites": manifest["unsupported_suites"],
        "limitations": [
            (
                "This run evaluates only the supplied deterministic scenarios "
                "against the supplied policy bytes."
            ),
            (
                "It does not test downstream tool side effects, deployed identity "
                "providers, runtime infrastructure or every possible agent attack."
            ),
            (
                "It is not formal verification, a penetration test or a guarantee "
                "of complete agent security."
            ),
            (
                "Only the minimal pinned regression extra is installed; optional "
                "server and compliance extras are outside this execution profile. "
                "Exact installed versions of the engine and regression dependencies "
                "are recorded in dependency_versions."
            ),
        ],
    }


def _error_report(
    engine_commit: str,
    error_code: str,
    executed: list[dict[str, Any]],
    *,
    policy_sha256: str | None = None,
    scenarios_sha256: str | None = None,
    engine_version: str | None = None,
    dependency_versions: dict[str, str] | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "suite_version": SUITE_VERSION,
        "engine_commit": engine_commit,
        "status": "error",
        "error_code": error_code,
        "executed": executed,
        "skipped": [],
    }
    if policy_sha256 is not None:
        report["policy_sha256"] = policy_sha256
    if scenarios_sha256 is not None:
        report["scenarios_sha256"] = scenarios_sha256
    if engine_version is not None:
        report["engine_version"] = engine_version
    if dependency_versions is not None:
        report["dependency_versions"] = dependency_versions
    try:
        manifest, manifest_bytes = _load_suite_manifest()
    except RuntimeError:
        return report
    report["suite_version"] = manifest["suite_version"]
    report["suite_manifest_sha256"] = _sha256(manifest_bytes)
    report["unsupported_suites"] = manifest["unsupported_suites"]
    return report


def _write_target(path: str | Path) -> Path:
    """Canonicalise the report destination and refuse unusable targets.

    A CLI-supplied write destination resolves (tilde expansion, traversal
    components, symlink aliasing) onto the physical target and is refused
    when that target is the filesystem root or the home directory
    (pythonsecurity:S8707 write-sink hardening).
    """
    destination = Path(path).expanduser().resolve()
    if destination == Path(destination.root) or destination == Path.home():
        raise RegressionInputError("output_forbidden_path")
    return destination


def _write_report(path: str | Path, report: dict[str, Any]) -> None:
    destination = _write_target(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run offline Raucle policy regression scenarios.")
    parser.add_argument("--policy", required=True, help="Consumer policy YAML file")
    parser.add_argument("--scenarios", required=True, help="Version 1 consumer scenario JSON")
    parser.add_argument("--output", required=True, help="Machine-readable JSON report path")
    parser.add_argument(
        "--engine-commit",
        default=os.environ.get("RAUCLE_ENGINE_COMMIT", "unavailable"),
        help="Full immutable Raucle engine commit SHA",
    )
    args = parser.parse_args(argv)

    try:
        report_path = _write_target(args.output)
    except RegressionInputError as exc:
        print(f"Raucle policy regression refused: {exc}", file=sys.stderr)
        return 2

    try:
        policy_bytes = _read_bounded(args.policy, "policy")
        scenarios_bytes = _read_bounded(args.scenarios, "scenarios")
        report = run_regression(
            policy_bytes,
            scenarios_bytes,
            engine_commit=args.engine_commit,
        )
        _write_report(report_path, report)
        print(
            f"Raucle policy regression {report['status']}: "
            f"{report['summary']['passed']}/{report['summary']['total']} scenarios passed "
            f"(policy sha256:{report['policy_sha256']})"
        )
        return 0 if report["status"] == "passed" else 1
    except RegressionInputError as exc:
        report = _error_report(args.engine_commit, str(exc), [])
        _write_report(report_path, report)
        print(f"Raucle policy regression refused: {exc}", file=sys.stderr)
        return 2
    except RegressionEnvironmentError as exc:
        report = _error_report(args.engine_commit, str(exc), [])
        _write_report(report_path, report)
        print("Raucle policy regression failed: dependency_unavailable", file=sys.stderr)
        return 2
    except RegressionExecutionError as exc:
        report = _error_report(
            args.engine_commit,
            "engine_error",
            exc.results,
            policy_sha256=exc.policy_sha256,
            scenarios_sha256=exc.scenarios_sha256,
            engine_version=exc.engine_version,
            dependency_versions=exc.dependency_versions,
        )
        _write_report(report_path, report)
        print("Raucle policy regression failed: engine_error", file=sys.stderr)
        return 2
    except Exception:
        report = _error_report(args.engine_commit, "engine_error", [])
        _write_report(report_path, report)
        print("Raucle policy regression failed: engine_error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
