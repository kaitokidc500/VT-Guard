from __future__ import annotations

import hashlib
import json
import os
import platform
from collections import Counter
from pathlib import Path

from vtguard import SCHEMA_VERSION
from vtguard.data.schema import TARGET_TTPS
from vtguard.evaluation.metrics import binary_metrics, choose_threshold
from vtguard.features.event import event_tokens, fit_vocabulary, vectorize
from vtguard.inference.baseline import BaselineBundle
from vtguard.models.logistic import train_logistic
from vtguard.training.reviewed import SPLITS, ReviewedExample, load_reviewed


HEADS = ("attack",) + TARGET_TTPS


def _target(example: ReviewedExample, head: str) -> int:
    if head == "attack":
        return int(example.event.labels.activity == "attack")
    return int(head in example.event.labels.ttps)


def train_baseline(manifest_path: Path, output_dir: Path, *, allow_synthetic: bool = False,
                   epochs: int = 80, learning_rate: float = 0.08) -> dict:
    examples, data_report = load_reviewed(manifest_path, allow_synthetic=allow_synthetic)
    splits = {split: [row for row in examples if row.split == split] for split in SPLITS}
    if any(not rows for rows in splits.values()):
        raise ValueError("Every split needs reviewed examples")
    vocabulary = fit_vocabulary([row.event for row in splits["train"]])
    if not vocabulary:
        raise ValueError("No train features after leakage-safe filtering")
    vectors = {split: [vectorize(row.event, vocabulary) for row in rows]
               for split, rows in splits.items()}
    heads = {}
    thresholds = {}
    metrics = {}
    for head_name in HEADS:
        train_y = [_target(row, head_name) for row in splits["train"]]
        val_y = [_target(row, head_name) for row in splits["validation"]]
        test_y = [_target(row, head_name) for row in splits["test"]]
        if not 0 < sum(train_y) < len(train_y):
            raise ValueError(f"Train split lacks both classes for {head_name}")
        if not 0 < sum(val_y) < len(val_y):
            raise ValueError(f"Validation split lacks both classes for {head_name}")
        model = train_logistic(vectors["train"], train_y, len(vocabulary),
                               epochs=epochs, learning_rate=learning_rate)
        val_scores = [model.predict(vector) for vector in vectors["validation"]]
        threshold = choose_threshold(val_y, val_scores)
        test_scores = [model.predict(vector) for vector in vectors["test"]]
        heads[head_name] = model.to_dict()
        thresholds[head_name] = threshold
        metrics[head_name] = {
            "validation": binary_metrics(val_y, val_scores, threshold),
            "test": binary_metrics(test_y, test_scores, threshold),
        }
    reference_bundle = BaselineBundle({
        "schema_version": SCHEMA_VERSION, "bundle_kind": "cpu_event_baseline",
        "vocabulary": vocabulary, "heads": heads,
    })
    references = []
    for row in splits["validation"][:3]:
        tokens = sorted(event_tokens(row.event))
        references.append({"tokens": tokens, "scores": reference_bundle.predict_tokens(tokens)})
    counts = {split: {
        "events": len(rows),
        "runs": len({row.event.provenance.run_id for row in rows}),
        "families": len({row.event.provenance.scenario_family for row in rows}),
        "activities": dict(Counter(row.event.labels.activity for row in rows)),
        "ttp_positives": {ttp: sum(ttp in row.event.labels.ttps for row in rows)
                          for ttp in TARGET_TTPS},
    } for split, rows in splits.items()}
    test_ttp = [metrics[name]["test"] for name in TARGET_TTPS]
    macro_ttp = {
        key: sum(row[key] for row in test_ttp) / len(test_ttp)
        for key in ("precision", "recall", "f1")
    }
    defined_ap = [row["average_precision"] for row in test_ttp
                  if row["average_precision"] is not None]
    macro_ttp["average_precision"] = (sum(defined_ap) / len(defined_ap)
                                      if len(defined_ap) == len(test_ttp) else None)
    manifest_digest = hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest()
    content = {
        "bundle_kind": "cpu_event_baseline", "bundle_version": "0.1",
        "schema_version": SCHEMA_VERSION, "attack_version": "19.2",
        "detector_status": "synthetic_smoke" if data_report["synthetic"] else "experimental_baseline",
        "deployable": False, "model_type": "one_vs_rest_logistic_sgd",
        "feature_version": "event_allowlist_v1", "sequence_config": {"mode": "single_event"},
        "labels": list(HEADS), "vocabulary": vocabulary, "heads": heads,
        "thresholds": thresholds, "reference_inference": references,
        "training_config": {"epochs": epochs, "learning_rate": learning_rate, "seed": 17},
        "data_provenance": data_report,
        "reviewed_manifest_sha256": manifest_digest,
        "code_commit": os.environ.get("VTGUARD_CODE_COMMIT"),
        "dependency_versions": {"python": platform.python_version(), "third_party": "none"},
        "metrics": {"by_head": metrics, "macro_ttp_test": macro_ttp,
                    "benign_admin_false_positives_test": metrics["attack"]["test"]["fp"],
                    "counts": counts,
                    "evaluation_unit": "reviewed_event",
                    "session_detection": None, "end_to_end_latency": None,
                    "alerts_per_benign_hour": None},
    }
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    (output_dir / "bundle.json").write_bytes(encoded)
    (output_dir / "bundle.sha256").write_text(hashlib.sha256(encoded).hexdigest() + "\n", encoding="ascii")
    BaselineBundle.load(output_dir)
    return {"detector_status": content["detector_status"],
            "counts": counts, "test_metrics": {name: metrics[name]["test"] for name in HEADS},
            "bundle_dir": str(output_dir)}
