"""Auditor-facing offline provenance verifier CLI (issue #346, ADR 0011).

A thin front end over the canonical Python verifier
(:class:`raucle.provenance.ProvenanceVerifier`). It contains NO cryptographic
logic of its own: every cryptographic check is performed by the canonical
verifier, exactly as ``raucle provenance verify`` performs it. This module
owns only the auditor-facing surfaces defined by ADR 0011:

- the ``raucle-verify`` console entry point (packaged in ``pyproject.toml``);
- a versioned, deterministic machine report (``raucle.verify.report/v1``);
- a stable exit-code contract documented in
  ``docs/spec/verifier-coverage-inventory.md`` (`--json` on
  ``raucle provenance verify`` shares the same contract).

The command is offline by construction: it reads only the files the caller
names (chain, trust roots, optional ML-DSA-65 key files) and performs no
network I/O, no implicit fetching of trust roots, revocation state,
policies or transparency checkpoints.

Classification is fail-closed: a failure reason the classifier does not
recognise is reported verbatim with an ``unclassified`` label and the
verdict falls back to ``invalid``. The versioned verdict is never
``verified`` when a required check was skipped, when the bundle is empty,
or when any check could not be performed.

Known limitation, named rather than hidden: the canonical verifier reports
a missing trust root exactly like a failed signature (one generic error
string), so this front end additionally scans the chain's JWS headers
(read-only, no trust placed in them) to name every key the chain
references that has no supplied trust root. Distinguishing the two cases
inside the canonical verifier's own error stream would require a
lower-layer change and is Reported, not edited, in this slice.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

#: Versioned report schema. Additive-only evolution: new keys may appear,
#: existing keys never change meaning and are never removed or reordered.
REPORT_SCHEMA_VERSION = "raucle.verify.report/v1"

#: Verdict vocabulary (machine values, stable).
VERIFIED = "verified"
INVALID = "invalid"
UNSUPPORTED_PROFILE = "unsupported_profile"
MISSING_TRUST_MATERIAL = "missing_trust_material"
POLICY_REQUIREMENT_UNMET = "policy_requirement_unmet"
PQ_RUNTIME_UNAVAILABLE = "pq_runtime_unavailable"
OPERATIONAL_ERROR = "operational_error"

#: Stable exit-code table (documented in the coverage inventory spec).
EXIT_VERIFIED = 0
EXIT_OPERATIONAL_ERROR = 1
EXIT_INVALID = 2
EXIT_UNSUPPORTED_PROFILE = 3
EXIT_MISSING_TRUST_MATERIAL = 4
EXIT_POLICY_REQUIREMENT_UNMET = 5
EXIT_PQ_RUNTIME_UNAVAILABLE = 6

_VERDICT_EXITS: dict[str, int] = {
    VERIFIED: EXIT_VERIFIED,
    OPERATIONAL_ERROR: EXIT_OPERATIONAL_ERROR,
    INVALID: EXIT_INVALID,
    UNSUPPORTED_PROFILE: EXIT_UNSUPPORTED_PROFILE,
    MISSING_TRUST_MATERIAL: EXIT_MISSING_TRUST_MATERIAL,
    POLICY_REQUIREMENT_UNMET: EXIT_POLICY_REQUIREMENT_UNMET,
    PQ_RUNTIME_UNAVAILABLE: EXIT_PQ_RUNTIME_UNAVAILABLE,
}

#: Nonverdict-driving reason classes, first matching substring wins. The
#: list is ordered: specific profile refusals are checked before the
#: generic ``malformed record`` wrapper so an unknown algorithm or version
#: keeps its specific class. Anything unmatched is reported verbatim as
#: ``unclassified`` and fails the chain closed (verdict ``invalid``).
_REASON_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "missing_trust_material",
        ("no capability statement supplied for",),
    ),
    (
        "unsupported_profile",
        (
            "unexpected JWS alg",
            "unexpected JOSE typ",
            "payload typ",
            "unexpected JOSE header key",
            "unknown critical header parameter",
            "unknown envelope field",
            "'raucle/v1' must be 'provenance'",
            "is not canonical JSON (JCS)",
            "pq1 receipts must pin a 16-hex-char 'pqk'",
        ),
    ),
    (
        "policy_requirement_unmet",
        ("--require-pq failed: ", "require_pq: "),
    ),
    ("verifier_bounds", ("ProvenanceVerifierBoundsExceeded",)),
    ("tamper", ("record tampered",)),
    ("signature", ("signature verification failed for",)),
    ("parent_link", ("not found in chain",)),
    ("sanitisation", ("sanitisation",)),
    ("taint", ("taint",)),
    ("capability", ("capability",)),
    ("malformed_record", ("malformed record",)),
    (
        "extension",
        (
            "x_bilateral",
            "x_dlp",
            "x_state",
            "x_timestamp",
            "x_lease",
            "lease",
            "delegation",
            "counterfactual",
            "tool_definition",
            "finding",
            "revocation",
        ),
    ),
)

#: Verdict precedence: the first class present decides the verdict. Fixed
#: order so the same input always yields the same verdict and exit code.
_VERDICT_PRECEDENCE: tuple[tuple[str, str], ...] = (
    ("unsupported_profile", UNSUPPORTED_PROFILE),
    ("missing_trust_material", MISSING_TRUST_MATERIAL),
    ("policy_requirement_unmet", POLICY_REQUIREMENT_UNMET),
)


def _b64url_decode(segment: str) -> bytes:
    """Decode an unpadded base64url segment (observation only, not crypto)."""
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _digest_file(path: str) -> dict[str, Any]:
    """Best-possible artifact digest row; missing files raise OSError."""
    data = Path(path).read_bytes()
    return {
        "path": path,
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _digest_artifacts(artifacts: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Build checked-artifact digest rows, in the caller's order."""
    rows = []
    for kind, path in artifacts:
        row = _digest_file(path)
        rows.append({"kind": kind, **row})
    return rows


def _split_line_prefix(message: str) -> tuple[int | None, str]:
    """Split a canonical report error into (line, remainder)."""
    if message.startswith("line ") and ": " in message:
        head, rest = message.split(": ", 1)
        tail = head[len("line ") :]
        if tail.isdigit():
            return int(tail), rest
    return None, message


def _classify(message: str) -> str:
    for cls, needles in _REASON_PATTERNS:
        if any(needle in message for needle in needles):
            return cls
    return "unclassified"


def _classify_reasons(errors: list[str]) -> list[dict[str, Any]]:
    reasons: list[dict[str, Any]] = []
    for error in errors:
        line, rest = _split_line_prefix(error)
        reasons.append({"line": line, "class": _classify(rest), "message": rest})
    return reasons


def _decode_receipt_header(line: str) -> dict[str, Any]:
    """Decode one JSONL line's chain envelope JWS header.

    Moved verbatim from the former in-loop block of ``_observe_chain``
    (python:S3776); behaviour is unchanged.
    """
    raw = json.loads(line)
    jws = raw["jws"]
    header = json.loads(_b64url_decode(jws.split(".", 1)[0]))
    if not isinstance(header, dict):
        raise ValueError("header is not an object")
    return header


def _observe_profiles_and_kids(
    header: dict[str, Any],
    line_no: int,
    profiles: dict[str, int],
    supplied_key_ids: set[str],
    supplied_pq_key_ids: set[str],
    missing_ed25519: list[tuple[int, str]],
    missing_pq: list[tuple[int, str]],
) -> None:
    """Classify one receipt header and record its unreferenced key ids.

    Moved verbatim from the former in-loop block of ``_observe_chain``
    (python:S3776); behaviour is unchanged.
    """
    from raucle.pq import header_is_pq1

    if header_is_pq1(header):
        profiles["pq1"] += 1
    elif header.get("crit") == ["raucle/v1"] and header.get("typ") == (_expected_receipt_typ()):
        profiles["v1"] += 1
    else:
        profiles["other"] += 1
    kid = header.get("kid")
    if isinstance(kid, str) and kid not in supplied_key_ids:
        missing_ed25519.append((line_no, kid))
    if header_is_pq1(header):
        pqk = header.get("pqk")
        if isinstance(pqk, str) and pqk not in supplied_pq_key_ids:
            missing_pq.append((line_no, pqk))


def _unobserved_chain_scan(profiles: dict[str, int]) -> dict[str, Any]:
    """Best-effort empty observation: nothing scanned, nothing named."""
    return {"profiles": profiles, "missing_ed25519": [], "missing_pq": []}


def _observe_chain(
    chain_path: str | Path,
    supplied_key_ids: set[str],
    supplied_pq_key_ids: set[str],
) -> dict[str, Any]:
    """Scan the chain for header-declared profiles and untrusted key ids.

    Read-only, best-effort, offline; the canonical verifier owns every
    decision. Returns the observed profile counters plus the (line, key id)
    pairs with no supplied trust root.
    """
    profiles = {"v1": 0, "pq1": 0, "other": 0, "unparseable": 0}
    missing_ed25519: list[tuple[int, str]] = []
    missing_pq: list[tuple[int, str]] = []
    try:
        # pythonsecurity:S8707 CLI-input pattern (the engine-proven recipe
        # from raucle/policy_regression): canonicalise the operator-supplied
        # chain path before any read and refuse an unobservable chain; the
        # scan stays best-effort and the canonical verifier reports the
        # underlying problem.
        source = Path(chain_path).expanduser().resolve()
        if not source.is_file():
            return _unobserved_chain_scan(profiles)
        with source.open(encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    header = _decode_receipt_header(line)
                except Exception:
                    # Unparseable here is only an observation failure; the
                    # canonical verifier classifies the underlying problem.
                    profiles["unparseable"] += 1
                    continue
                _observe_profiles_and_kids(
                    header,
                    line_no,
                    profiles,
                    supplied_key_ids,
                    supplied_pq_key_ids,
                    missing_ed25519,
                    missing_pq,
                )
    except OSError:
        # The canonical verifier reports unreadable chains; the scan has
        # nothing to add.
        return _unobserved_chain_scan(profiles)
    return {"profiles": profiles, "missing_ed25519": missing_ed25519, "missing_pq": missing_pq}


def _expected_receipt_typ() -> str:
    """The understood receipt ``typ`` literal, read from the canonical module."""
    from raucle.provenance import _EXPECTED_TYP

    return _EXPECTED_TYP


def _enforce_require_pq(canonical_report: Any, chain_path: str | Path) -> None:
    """Apply the canonical --require-pq enforcement (reused, not reimplemented)."""
    from raucle.cli import _enforce_require_pq

    _enforce_require_pq(str(chain_path), canonical_report)


def _coverage_section(
    receipts: int,
    capabilities_supplied: bool,
    require_pq: bool,
    pq_available: bool,
) -> dict[str, Any]:
    """Honest coverage rows: what ran, and what this command never performs."""
    performed: list[str] = [
        "signature_classical_and_hybrid",
        "tamper_evidence",
        "parent_links",
        "taint_monotonicity",
        "structural_rules",
    ]
    skipped: list[dict[str, str]] = [
        {
            "check": "transparency_anchor",
            "reason": "not wired into this command; transparency tooling "
            "(SCITT anchor, log inclusion/consistency) is invoked separately",
        },
        {
            "check": "segment_seal_meta",
            "reason": "segment seal sidecars are verified by receipt-store "
            "tooling, not by chain verification",
        },
        {
            "check": "policy_proof_artifacts",
            "reason": "Lean/SMT policy proofs and policy seal sidecars are "
            "verified out of band; receipts carry ruleset-hash digests only",
        },
    ]
    if receipts == 0:
        performed.clear()
    if capabilities_supplied:
        performed.append("capability_conformance")
    else:
        skipped.append(
            {
                "check": "capability_conformance",
                "reason": "no capability statements supplied: model/tool "
                "allowlist conformance was not performed",
            }
        )
    if require_pq:
        performed.append("require_pq_chain_profile")
    if not pq_available:
        skipped.append(
            {
                "check": "hybrid_pq1_signatures",
                "reason": "ML-DSA-65 unavailable in this runtime: pq1 receipts "
                "fail closed (PQUnavailable), they are never verified classically",
            }
        )
    if os.environ.get("RAUCLE_VERIFY_BOUNDS") == "off":
        skipped.append(
            {
                "check": "resource_bounds",
                "reason": "disabled by RAUCLE_VERIFY_BOUNDS=off (legacy unbounded mode)",
            }
        )
    else:
        performed.append("resource_bounds")
    return {"performed": performed, "skipped": skipped}


def _verdict_for(reasons: list[dict[str, Any]], invalid: bool) -> str:
    """Deterministic verdict from the classified reasons (fail-closed)."""
    classes = {r["class"] for r in reasons}
    for cls, verdict in _VERDICT_PRECEDENCE:
        if cls in classes:
            return verdict
    if invalid or classes:
        return INVALID
    return VERIFIED


def _body(
    verdict: str,
    reasons: list[dict[str, Any]],
    *,
    report: Any | None,
    receipts: int,
    profiles: dict[str, int],
    coverage: dict[str, Any] | None,
    checked_artifacts: list[dict[str, Any]],
    require_pq: bool,
    pq_available: bool,
    pq_keys_supplied: int,
    trust_roots_supplied: int,
    offline: bool = True,
) -> dict[str, Any]:
    invalid = verdict != VERIFIED
    body: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "verdict": verdict,
        "invalid": invalid,
        "exit_code": _VERDICT_EXITS[verdict],
        "receipt_count": receipts,
        "failure_reasons": reasons,
        "profiles_observed": profiles,
        "require_pq": require_pq,
        "pq": {"available": pq_available, "keys_supplied": pq_keys_supplied},
        "trust_roots_supplied": trust_roots_supplied,
        "checked_artifacts": checked_artifacts,
        "coverage": coverage if coverage is not None else {"performed": [], "skipped": []},
        "offline": offline,
    }
    if report is not None:
        body["counts"] = {
            "signature_failures": report.signature_failures,
            "parent_link_failures": report.parent_link_failures,
            "taint_monotonicity_failures": report.taint_monotonicity_failures,
            "capability_violations": report.capability_violations,
            "unauthorised_sanitisations": report.unauthorised_sanitisations,
        }
        body["tampered_receipts"] = report.tampered_receipts
        if report.counterfactual_evidence:
            body["counterfactual_evidence"] = report.counterfactual_evidence
        if report.capability_trust_modes:
            body["capability_trust_modes"] = dict(report.capability_trust_modes)
    return body


def _operational_body(
    message: str,
    *,
    checked_artifacts: list[dict[str, Any]],
    require_pq: bool,
    pq_available: bool,
    pq_keys_supplied: int,
    trust_roots_supplied: int,
) -> tuple[dict[str, Any], int]:
    body = _body(
        OPERATIONAL_ERROR,
        [{"line": None, "class": "operational_error", "message": message}],
        report=None,
        receipts=0,
        profiles={"v1": 0, "pq1": 0, "other": 0, "unparseable": 0},
        coverage={"performed": [], "skipped": []},
        checked_artifacts=checked_artifacts,
        require_pq=require_pq,
        pq_available=pq_available,
        pq_keys_supplied=pq_keys_supplied,
        trust_roots_supplied=trust_roots_supplied,
    )
    return body, EXIT_OPERATIONAL_ERROR


def run_offline_verify(
    chain_path: str | Path,
    *,
    public_keys: dict[str, Any],
    capabilities: dict[str, Any] | None,
    pq_public_keys: dict[str, Any] | None,
    require_pq: bool,
    artifacts: list[tuple[str, str]],
) -> tuple[dict[str, Any], int]:
    """Run the canonical verifier and build a versioned report.

    Returns ``(body, exit_code)``; ``body`` is JSON-serialisable in its
    construction order. Any unreadable chain or artifact is an
    ``operational_error`` (exit 1); anything the canonical verifier raises
    that is genuinely unexpected still propagates so a stack trace
    surfaces for debugging (BUGS in the verifier are not verdicts).
    """
    from raucle.pq import pq_available as pq_runtime_available
    from raucle.provenance import ProvenanceVerifier

    trust_roots_supplied = len(public_keys)
    pq_keys_supplied = len(pq_public_keys or {})
    pq_ok = pq_runtime_available()
    try:
        checked = _digest_artifacts(artifacts)
    except OSError as exc:
        return _operational_body(
            f"cannot read verification artifact: {exc}",
            checked_artifacts=[],
            require_pq=require_pq,
            pq_available=pq_ok,
            pq_keys_supplied=pq_keys_supplied,
            trust_roots_supplied=trust_roots_supplied,
        )

    report: Any
    try:
        report = ProvenanceVerifier(
            public_keys=dict(public_keys),
            capabilities=dict(capabilities) if capabilities else None,
            pq_public_keys=dict(pq_public_keys) if pq_public_keys else None,
        ).verify_chain(chain_path)
    except Exception as exc:  # classified below - re-raised for real bugs
        from raucle.pq import PQUnavailable

        if isinstance(exc, PQUnavailable):
            return _pq_unavailable_body(
                exc,
                capabilities=capabilities,
                require_pq=require_pq,
                pq_ok=pq_ok,
                checked_artifacts=checked,
                pq_keys_supplied=pq_keys_supplied,
                trust_roots_supplied=trust_roots_supplied,
            )
        raise

    return _assemble_verified_body(
        report,
        chain_path=chain_path,
        public_keys=public_keys,
        capabilities=capabilities,
        pq_public_keys=pq_public_keys,
        require_pq=require_pq,
        pq_ok=pq_ok,
        checked_artifacts=checked,
        pq_keys_supplied=pq_keys_supplied,
        trust_roots_supplied=trust_roots_supplied,
    )


def _pq_unavailable_body(
    exc: Exception,
    *,
    capabilities: dict[str, Any] | None,
    require_pq: bool,
    pq_ok: bool,
    checked_artifacts: list[dict[str, Any]],
    pq_keys_supplied: int,
    trust_roots_supplied: int,
) -> tuple[dict[str, Any], int]:
    """Versioned body for a chained receipt stream the PQ runtime cannot do.

    Moved verbatim from the former in-line block of ``run_offline_verify``
    (python:S3776); behaviour is unchanged.
    """
    body = _body(
        PQ_RUNTIME_UNAVAILABLE,
        [
            {
                "line": None,
                "class": "pq_runtime_unavailable",
                "message": str(exc),
            }
        ],
        report=None,
        receipts=0,
        profiles={"v1": 0, "pq1": 0, "other": 0, "unparseable": 0},
        coverage=_coverage_section(0, bool(capabilities), require_pq, pq_ok),
        checked_artifacts=checked_artifacts,
        require_pq=require_pq,
        pq_available=False,
        pq_keys_supplied=pq_keys_supplied,
        trust_roots_supplied=trust_roots_supplied,
    )
    return body, EXIT_PQ_RUNTIME_UNAVAILABLE


def _assemble_verified_body(
    report: Any,
    *,
    chain_path: str | Path,
    public_keys: dict[str, Any],
    capabilities: dict[str, Any] | None,
    pq_public_keys: dict[str, Any] | None,
    require_pq: bool,
    pq_ok: bool,
    checked_artifacts: list[dict[str, Any]],
    pq_keys_supplied: int,
    trust_roots_supplied: int,
) -> tuple[dict[str, Any], int]:
    """Assemble the post-verification section of the versioned report.

    Moved verbatim from the former tail of ``run_offline_verify``
    (python:S3776); behaviour is unchanged.
    """
    # Policy requirement: reuse the canonical --require-pq enforcement so
    # the versioned report carries the exact same named errors.
    if require_pq:
        _enforce_require_pq(report, chain_path)

    # CLI-layer trust-material scan: name every referenced key with no
    # supplied trust root (the canonical verifier reports missing keys as
    # generic signature failures).
    supplied_key_ids = set(public_keys) | set(capabilities or {})
    supplied_pq_key_ids = set(pq_public_keys or {})
    scan = _observe_chain(chain_path, supplied_key_ids, supplied_pq_key_ids)
    scan_reasons: list[dict[str, Any]] = []
    for line_no, kid in scan["missing_ed25519"]:
        scan_reasons.append(
            {
                "line": line_no,
                "class": "missing_trust_material",
                "message": f"no supplied trust root matches the referenced agent_key_id {kid!r}",
            }
        )
    for line_no, pqk in scan["missing_pq"]:
        scan_reasons.append(
            {
                "line": line_no,
                "class": "missing_trust_material",
                "message": f"no supplied ML-DSA-65 key matches the referenced pqk {pqk!r}",
            }
        )
    reasons = _classify_reasons(report.errors) + scan_reasons

    receipts = report.receipt_count
    if receipts == 0:
        invalid = True
        reasons.append(
            {
                "line": None,
                "class": "empty_chain",
                "message": "the chain contains no receipts; nothing was verified",
            }
        )
    else:
        invalid = not report.valid
    coverage = _coverage_section(
        receipts,
        bool(capabilities),
        require_pq,
        pq_ok,
    )
    if invalid and not reasons:
        # Fail closed: never claim verified, never pass silently.
        reasons.append(
            {
                "line": None,
                "class": "unclassified",
                "message": "verification failed without a named reason",
            }
        )
    verdict = _verdict_for(reasons, invalid)
    body = _body(
        verdict,
        reasons,
        report=report,
        receipts=receipts,
        profiles=scan["profiles"],
        coverage=coverage,
        checked_artifacts=checked_artifacts,
        require_pq=require_pq,
        pq_available=pq_ok,
        pq_keys_supplied=pq_keys_supplied,
        trust_roots_supplied=trust_roots_supplied,
    )
    return body, _VERDICT_EXITS[verdict]


def emit_versioned_report(
    chain_path: str | Path,
    *,
    public_keys: dict[str, Any],
    capabilities: dict[str, Any] | None,
    pq_public_keys: dict[str, Any] | None,
    require_pq: bool,
    artifacts: list[tuple[str, str]],
) -> tuple[dict[str, Any], int]:
    """Entry point shared by `raucle provenance verify --json` and the console script."""

    return run_offline_verify(
        chain_path,
        public_keys=public_keys,
        capabilities=capabilities,
        pq_public_keys=pq_public_keys,
        require_pq=require_pq,
        artifacts=artifacts,
    )


def _print_human(body: dict[str, Any]) -> None:
    """Deterministic, plain-text auditor summary (no colours, no timestamps)."""
    print(f"raucle-verify:        {body['verdict']}")
    print(f"  schema:             {body['schema_version']}")
    print(f"  exit code:          {body['exit_code']}")
    counts = body.get("counts") or {}
    print(f"  receipts:           {body['receipt_count']}")
    if counts:
        print(
            f"  signature failures: {counts['signature_failures']}, "
            f"parent-link failures: {counts['parent_link_failures']}, "
            f"capability violations: {counts['capability_violations']}"
        )
    tampered = body.get("tampered_receipts") or []
    print(f"  tampered receipts:  {len(tampered)}")
    profiles = body["profiles_observed"]
    print(
        f"  profiles observed:  v1={profiles['v1']} pq1={profiles['pq1']} "
        f"other={profiles['other']} unparseable={profiles['unparseable']}"
    )
    pq = body["pq"]
    print(
        f"  pq:                 available={str(pq['available']).lower()} "
        f"keys_supplied={pq['keys_supplied']}"
    )
    print(f"  require-pq:         {'yes' if body['require_pq'] else 'no'}")
    print(f"  verified offline:   {'yes' if body['offline'] else 'no'}")
    for row in body["checked_artifacts"]:
        print(f"  artifact:           {row['kind']} {row['path']} {row['sha256']}")
    coverage = body["coverage"]
    print(f"  performed:          {', '.join(coverage['performed']) or 'none'}")
    for row in coverage["skipped"]:
        print(f"  skipped:            {row['check']}: {row['reason']}")
    for reason in body["failure_reasons"]:
        line = reason["line"]
        prefix = f"line {line}" if line is not None else "bundle"
        print(f"  failure:            {prefix} [{reason['class']}]: {reason['message']}")
    if not body["failure_reasons"]:
        print("  failures:           none")


def _load_pubkeys(paths: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load the trust roots with the canonical CLI loader (one implementation)."""
    from raucle.cli import _load_provenance_pubkeys

    return _load_provenance_pubkeys(paths)


def _load_pq_keys(paths: list[str]) -> dict[str, Any]:
    """Load ML-DSA-65 key PEMs keyed by their pqk id (same as the canonical CLI)."""
    if not paths:
        return {}
    from raucle.pq import pq_key_id_from_public_key, pq_public_key_from_pem

    keys: dict[str, Any] = {}
    for pem_path in paths:
        # pythonsecurity:S8707 CLI-input pattern (the engine-proven recipe
        # from raucle/policy_regression): canonicalise the operator-supplied
        # key path before any read and refuse anything that is not a regular
        # file, fail closed with the CLI's named FileNotFoundError.
        source = Path(pem_path).expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(source))
        text = source.read_text(encoding="ascii")
        keys[pq_key_id_from_public_key(pq_public_key_from_pem(text))] = text
    return keys


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raucle-verify",
        description=(
            "Offline auditor-facing provenance verifier front end over the "
            "canonical raucle verifier (ADR 0011). No network I/O. Trust "
            "roots must be supplied; keys embedded in the evidence are "
            "never trust anchors."
        ),
    )
    parser.add_argument("chain", help="Path to the provenance chain JSONL")
    parser.add_argument(
        "--trust-roots",
        "--pubkeys",
        dest="trust_roots",
        nargs="+",
        required=True,
        metavar="FILE",
        help="Capability-statement JSON files and/or public-key PEM files",
    )
    parser.add_argument(
        "--pq-keys",
        "--pq-pubkeys",
        dest="pq_keys",
        nargs="*",
        metavar="PEM",
        help="ML-DSA-65 public key PEM files for raucle/pq1 hybrid receipts",
    )
    parser.add_argument(
        "--require-pq",
        action="store_true",
        help="Fail unless every receipt carries a valid raucle/pq1 hybrid signature",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help=f"Emit the versioned machine report ({REPORT_SCHEMA_VERSION})",
    )
    return parser


def _auditor_main(argv: list[str] | None = None) -> int:
    """Console-script body: identical contract, auditor-facing framing."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    pq_paths = args.pq_keys or []
    artifacts: list[tuple[str, str]] = [("chain", args.chain)]
    artifacts += [("trust_root", p) for p in args.trust_roots]
    artifacts += [("pq_key", p) for p in pq_paths]
    require_pq = bool(args.require_pq)
    try:
        public_keys, capabilities = _load_pubkeys(args.trust_roots)
        pq_public_keys = _load_pq_keys(pq_paths)
    except (OSError, ValueError, KeyError) as exc:
        if args.json:
            body, code = _operational_body(
                str(exc),
                checked_artifacts=[],
                require_pq=require_pq,
                pq_available=False,
                pq_keys_supplied=len(pq_paths),
                trust_roots_supplied=len(args.trust_roots),
            )
            print(json.dumps(body, indent=2))
        else:
            print(f"error: {exc}", file=sys.stderr)
            code = EXIT_OPERATIONAL_ERROR
        return code
    body, code = emit_versioned_report(
        args.chain,
        public_keys=public_keys,
        capabilities=capabilities,
        pq_public_keys=pq_public_keys,
        require_pq=require_pq,
        artifacts=artifacts,
    )
    if args.json:
        print(json.dumps(body, indent=2))
    else:
        _print_human(body)
    return code


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``raucle-verify`` console script."""
    return _auditor_main(argv)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
