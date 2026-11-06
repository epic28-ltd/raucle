"""NFR operability guard (P5.NFR / operability-v1).

Keeps ``docs/nfr/cli-contract.md`` honest against the implementation:

1. every subcommand the parser defines is documented in the contract's
   command table (no undocumented command surface),
2. every documented subcommand is a real parser choice (no fantasy rows),
3. every exit code documented in the contract's exit-code table is
   literally returned somewhere in the CLI implementation (a documented
   code that the code never emits is a broken contract),
4. the four documented codes cover the codes the implementation actually
   returns (no undocumented exit vocabulary).
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
CLI = (_REPO / "raucle" / "cli.py").read_text(encoding="utf-8")
CONTRACT = (_REPO / "docs" / "nfr" / "cli-contract.md").read_text(encoding="utf-8")


def _documented_exit_codes() -> list[int]:
    codes = re.findall(r"^\| (\d+) \|", CONTRACT, flags=re.MULTILINE)
    return sorted(int(c) for c in codes)


def _documented_commands() -> set[str]:
    rows = re.findall(r"^\| ([a-z][a-z0-9-]+) \|", CONTRACT, flags=re.MULTILINE)
    return set(rows) - {"code", "command"}


def _parser_commands() -> set[str]:
    from raucle.cli import _build_parser

    parser = _build_parser()
    for action in parser._actions:  # noqa: SLF001 - contract guard, by design
        if action.dest == "command" and action.choices:
            return set(action.choices)
    raise AssertionError("parser exposes no command choices")


def test_every_parser_command_is_documented():
    missing = _parser_commands() - _documented_commands()
    assert not missing, f"commands missing from docs/nfr/cli-contract.md: {sorted(missing)}"


def test_every_documented_command_is_real():
    phantom = _documented_commands() - _parser_commands()
    assert not phantom, f"documented commands not in the parser: {sorted(phantom)}"


def test_every_documented_exit_code_appears_in_the_implementation():
    for code in _documented_exit_codes():
        emitted = (
            re.search(rf"return {code}\b", CLI)
            or re.search(rf"sys\.exit\({code}\)", CLI)
            or re.search(rf"exit_code={code}", CLI)
        )
        assert emitted, (
            f"exit code {code} documented in cli-contract.md but never returned in raucle/cli.py"
        )


def test_implementation_does_not_return_undocumented_exit_codes():
    documented = set(_documented_exit_codes())
    returned = [int(s) for s in re.findall(r"^\s*return (\d{1,3})\b", CLI, flags=re.MULTILINE)]
    stray = {c for c in returned if c not in documented and c not in {0, 1, 2, 130}}
    assert not stray, f"CLI returns codes undocumented in cli-contract.md: {sorted(stray)}"
