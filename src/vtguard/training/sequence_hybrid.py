"""Fit validated rule fusion around an already trained GRU bundle."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from vtguard import SCHEMA_VERSION
from vtguard.evaluation.metrics import binary_metrics, choose_threshold
from vtguard.features.event import event_tokens
from vtguard.features.sequence import offline_windows
from vtguard.features.sequence_encoding import encode_window
from vtguard.fusion.scores import fuse_scores, rule_scores
from vtguard.inference.sequence import SequenceBundle
from vtguard.inference.sequence_hybrid import SequenceHybridBundle
from vtguard.rule_induction.tree import HEADS, induce_rules, match_vector
from vtguard.training.reviewed import load_reviewed


def _target(row, head: str) -> int:
    return int(row.event.labels.activity == "attack" if head == "attack"
               else head in row.event.labels.ttps)


def _split_windows(rows, split, config):
    ordered = sorted((row for row in rows if row.split == split),
                     key=lambda row: (row.event.event_time_utc, row.event.event_uid))
    windows = offline_windows([row.event for row in ordered], config)
    return list(zip(ordered, windows))


def fit_sequence_hybrid(manifest_path: Path, sequence_bundle_dir: Path, output_dir: Path, *,
                        allow_synthetic: bool = False, min_rule_support: int = 3,
                        min_validation_matches: int = 2) -> dict:
    manifest_path = Path(manifest_path)
    source_bundle = SequenceBundle.load(sequence_bundle_dir)
    if source_bundle.content["reviewed_manifest_sha256"] != hashlib.sha256(manifest_path.read_bytes()).hexdigest():
        raise ValueError("GRU bundle and reviewed manifest differ")
    rows, report = load_reviewed(manifest_path, allow_synthetic=allow_synthetic)
    if report["synthetic"] != (source_bundle.content["detector_status"] == "synthetic_smoke"):
        raise ValueError("Synthetic status differs between manifest and GRU bundle")
    train = [row for row in rows if row.split == "train"]
    validation = [row for row in rows if row.split == "validation"]
    rules = induce_rules(train, validation, min_support=min_rule_support,
                         min_validation_matches=min_validation_matches)
    val_pairs = _split_windows(rows, "validation", source_bundle.config)
    test_pairs = _split_windows(rows, "test", source_bundle.config)
    val_ai = [source_bundle.predict(window) for _, window in val_pairs]
    test_ai = [source_bundle.predict(window) for _, window in test_pairs]
    val_matches = [match_vector(row.event, rules) for row, _ in val_pairs]
    test_matches = [match_vector(row.event, rules) for row, _ in test_pairs]
    weights = {}
    thresholds = {}
    comparisons = {}
    for head in HEADS:
        val_y = [_target(row, head) for row, _ in val_pairs]
        test_y = [_target(row, head) for row, _ in test_pairs]
        has_rule = any(rule.head == head for rule in rules)
        candidates = (0.0, 0.25, 0.5, 0.75, 1.0) if has_rule else (0.0,)
        best = None
        for weight in candidates:
            scores = [(1 - weight) * ai[head] + weight * rule_scores(match, rules)[head]
                      for ai, match in zip(val_ai, val_matches)]
            threshold = choose_threshold(val_y, scores)
            candidate = (binary_metrics(val_y, scores, threshold)["f1"], -weight,
                         weight, threshold)
            if best is None or candidate > best:
                best = candidate
        weights[head], thresholds[head] = best[2], best[3]
        rule_test = [rule_scores(match, rules)[head] for match in test_matches]
        hybrid_test = [(1 - weights[head]) * ai[head] + weights[head] * rule
                       for ai, rule in zip(test_ai, rule_test)]
        comparisons[head] = {
            "rule_only": binary_metrics(test_y, rule_test, 0.5),
            "ai_only": binary_metrics(test_y, [score[head] for score in test_ai],
                                      source_bundle.content["thresholds"][head]),
            "hybrid": binary_metrics(test_y, hybrid_test, thresholds[head]),
        }
    output_dir = Path(output_dir)
    sequence_dir = output_dir / "sequence"
    sequence_dir.mkdir(parents=True, exist_ok=True)
    for name in ("bundle.json", "bundle.sha256", "weights.pt"):
        shutil.copy2(Path(sequence_bundle_dir) / name, sequence_dir / name)
    references = []
    for row, window in val_pairs[:3]:
        ai = source_bundle.predict(window)
        matches = match_vector(row.event, rules)
        references.append({"encoded": encode_window(window, source_bundle.vocabulary, source_bundle.config),
                           "target_tokens": sorted(event_tokens(row.event)),
                           "scores": fuse_scores(ai, matches, rules, weights)})
    content = {
        "bundle_kind": "gru_rule_hybrid", "bundle_version": "0.1",
        "schema_version": SCHEMA_VERSION, "attack_version": "19.2",
        "detector_status": source_bundle.content["detector_status"],
        "deployable": False, "model_kind": source_bundle.content["model_config"]["kind"],
        "rules": [rule.to_dict() for rule in rules],
        "fusion": {"method": "validation_selected_convex_rule_ai_v1",
                   "weights": weights, "thresholds": thresholds},
        "comparisons": comparisons, "reference_inference": references,
        "rule_induction": {"method": "binary_cart_positive_leaves_v1",
                           "min_support": min_rule_support,
                           "min_validation_matches": min_validation_matches},
        "reviewed_manifest_sha256": source_bundle.content["reviewed_manifest_sha256"],
        "code_commit": source_bundle.content["code_commit"],
    }
    raw = json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    (output_dir / "hybrid.json").write_bytes(raw)
    (output_dir / "hybrid.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n", encoding="ascii")
    SequenceHybridBundle.load(output_dir)
    return {"status": content["detector_status"], "rules": len(rules),
            "bundle_dir": str(output_dir), "comparisons": comparisons}
