"""Deterministic fusion of AI probabilities and generated-rule matches."""

from __future__ import annotations

from vtguard.rule_induction.tree import HEADS, Rule


def rule_scores(matches: dict[str, int], rules: list[Rule]) -> dict[str, float]:
    return {head: float(any(matches.get(rule.rule_id, 0) for rule in rules
                            if rule.head == head)) for head in HEADS}


def fuse_scores(ai_scores: dict[str, float], matched_rules: dict[str, int],
                rules: list[Rule], weights: dict[str, float]) -> dict[str, float]:
    rule = rule_scores(matched_rules, rules)
    if set(ai_scores) != set(HEADS) or set(weights) != set(HEADS):
        raise ValueError("Fusion needs all six AI scores and head weights")
    if any(not 0 <= value <= 1 for value in weights.values()):
        raise ValueError("Fusion weights must be in [0, 1]")
    return {head: (1 - weights[head]) * ai_scores[head] + weights[head] * rule[head]
            for head in HEADS}
