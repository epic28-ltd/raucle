"""Metric computations used by the eval harness.

Kept separate from the adapters so that the paper's claimed numbers come from
one well-defined codepath rather than several.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AggregateMetrics:
    asr: float  # attack success rate, [0, 1]
    benign_completion: float  # [0, 1]
    tool_mediated_fraction: float  # fraction of successful attacks that flowed through a tool call
    sample_size: int

    def fmt(self, decimals: int = 1) -> str:
        return (
            f"ASR={100 * self.asr:.{decimals}f}%  "
            f"benign={100 * self.benign_completion:.{decimals}f}%  "
            f"n={self.sample_size}  "
            f"tool-mediated={100 * self.tool_mediated_fraction:.{decimals}f}%"
        )


def aggregate_agentdojo(suite_results: list) -> AggregateMetrics:
    total = sum(s.total_tasks for s in suite_results)
    if total == 0:
        return AggregateMetrics(0, 0, 0, 0)
    asr_num = sum(s.attack_successes for s in suite_results)
    benign_num = sum(s.benign_successes for s in suite_results)
    tool_med = sum(s.tool_mediated_attacks for s in suite_results)
    return AggregateMetrics(
        asr=asr_num / total,
        benign_completion=benign_num / total,
        tool_mediated_fraction=tool_med / max(asr_num, 1),
        sample_size=total,
    )


def aggregate_injecagent(mode_results: list) -> AggregateMetrics:
    total = sum(m.total_cases for m in mode_results)
    if total == 0:
        return AggregateMetrics(0, 0, 0, 0)
    asr_num = sum(m.attack_successes for m in mode_results)
    tool_med = sum(m.tool_mediated_attacks for m in mode_results)
    return AggregateMetrics(
        asr=asr_num / total,
        benign_completion=0.0,  # InjecAgent does not measure benign completion
        tool_mediated_fraction=tool_med / max(asr_num, 1),
        sample_size=total,
    )
