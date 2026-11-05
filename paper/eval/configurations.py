"""The eight defence configurations evaluated in §6 of the paper.

Six headline configurations plus two ablation variants. Each is a callable
that wraps a base agent in the appropriate defence stack.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from paper.eval.defences import (
    no_defence,
    spotlighting,
    struq,
    prompt_shields,
    vcd_text_only,
    vcd_full_stack,
    vcd_capability_only,
    vcd_proof_only,
)


@dataclass(frozen=True)
class Configuration:
    name: str  # appears in the paper's tables verbatim
    short: str  # column header in results.json
    factory: Callable[..., object]  # returns a defended agent given a base agent
    is_ablation: bool = False


HEADLINE: list[Configuration] = [
    Configuration("None", "none", no_defence),
    Configuration("Spotlighting", "spotlight", spotlighting),
    Configuration("StruQ", "struq", struq),
    Configuration("Prompt shields", "shields", prompt_shields),
    Configuration("VCD text-only", "vcd_text", vcd_text_only),
    Configuration("VCD full stack", "vcd_full", vcd_full_stack),
]

ABLATIONS: list[Configuration] = [
    Configuration("VCD capability only", "vcd_cap_only", vcd_capability_only, True),
    Configuration("VCD proof only", "vcd_proof_only", vcd_proof_only, True),
]

ALL: list[Configuration] = HEADLINE + ABLATIONS
