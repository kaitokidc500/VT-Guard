"""Small CPU rule + AI baseline, selected only on validation runs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vtguard.data.schema import TARGET_TTPS
from vtguard.evaluation.metrics import binary_metrics, choose_threshold
from vtguard.features.event import event_tokens
from vtguard.fusion.scores import fuse_scores, rule_scores
from vtguard.inference.baseline import BaselineBundle
from vtguard.inference.hybrid import HybridBundle
from vtguard.rule_induction.tree import HEADS, induce_rules, match_vector
from vtguard.training.baseline import train_baseline
from vtguard.training.reviewed import load_reviewed


def _target(row, head: str) -> int:
    return int(row.event.labels.activity == "attack" if head == "attack"
               else head in row.event.labels.ttps)


def train_hybrid(manifest_path: Path, output_dir: Path, *,
                 allow_synthetic: bool = False, min_rule_support: int = 3,
                 min_validation_matches: int = 2) -> dict:
    train_baseline(manifest_path, output_dir, allow_synthetic=allow_synthetic)
    rows, _ = load_reviewed(manifest_path, allow_synthetic=allow_synthetic)
    train = [row for row in rows if row.split == "train"]
    validation = [row for row in rows if row.split == "validation"]
    test = [row for row in rows if row.split == "test"]
    rules = induce_rules(train, validation, min_support=min_rule_support,
                         min_validation_matches=min_validation_matches)
    base = BaselineBundle.load(output_dir)
    val_ai = [base.predict(row.event) for row in validation]
    val_matches = [match_vector(row.event, rules) for row in validation]
    test_ai = [base.predict(row.event) for row in test]
    test_matches = [match_vector(row.event, rules) for row in test]
    weights = {}
    thresholds = {}
    comparisons = {}
    for head in HEADS:
        val_y = [_target(row, head) for row in validation]
        test_y = [_target(row, head) for row in test]
        has_rules = any(rule.head == head for rule in rules)
        candidates = (0.0, 0.25, 0.5, 0.75, 1.0) if has_rules else (0.0,)
        best = None
        for weight in candidates:
            scores = [(1 - weight) * ai[head] + weight * rule_scores(match, rules)[head]
                      for ai, match in zip(val_ai, val_matches)]
            threshold = choose_threshold(val_y, scores)
            f1 = binary_metrics(val_y, scores, threshold)["f1"]
            candidate = (f1, -weight, weight, threshold)
            if best is None or candidate > best:
                best = candidate
        weights[head] = best[2]
        thresholds[head] = best[3]
        rule_test = [rule_scores(match, rules)[head] for match in test_matches]
        hybrid_test = [(1 - weights[head]) * ai[head] + weights[head] * rule
                       for ai, rule in zip(test_ai, rule_test)]
        comparisons[head] = {
            "rule_only": binary_metrics(test_y, rule_test, 0.5),
            "ai_only": binary_metrics(test_y, [score[head] for score in test_ai],
                                      base.content["thresholds"][head]),
            "hybrid": binary_metrics(test_y, hybrid_test, thresholds[head]),
        }
    content = base.content | {
        "bundle_kind": "cpu_hybrid_baseline", "rules": [rule.to_dict() for rule in rules],
        "fusion": {"method": "validation_selected_convex_rule_ai_v1",
                   "weights": weights, "thresholds": thresholds},
        "comparisons": comparisons,
        "rule_induction": {"method": "binary_cart_positive_leaves_v1",
                           "min_support": min_rule_support,
                           "min_validation_matches": min_validation_matches,
                           "candidate_count": len(rules)},
    }
    references = []
    for row in validation[:3]:
        event = row.event
        ai = base.predict(event)
        matches = match_vector(event, rules)
        references.append({"tokens": sorted(event_tokens(event)), "matches": matches,
                           "scores": fuse_scores(ai, matches, rules, weights)})
    content["hybrid_reference_inference"] = references
    output_dir = Path(output_dir)
    encoded = json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    (output_dir / "bundle.json").write_bytes(encoded)
    (output_dir / "bundle.sha256").write_text(hashlib.sha256(encoded).hexdigest() + "\n",
                                               encoding="ascii")
    HybridBundle.load(output_dir)
    return {"status": content["detector_status"], "rules": len(rules),
            "comparisons": comparisons, "bundle_dir": str(output_dir)}
