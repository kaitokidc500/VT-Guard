"""Comparable event-level summaries from verified model bundles."""

from __future__ import annotations

import json
from pathlib import Path

from vtguard.data.schema import TARGET_TTPS
from vtguard.inference.baseline import BaselineBundle
from vtguard.inference.hybrid import HybridBundle
from vtguard.inference.sequence import SequenceBundle
from vtguard.inference.sequence_hybrid import SequenceHybridBundle


def _summary(metrics: dict[str, dict]) -> dict:
    attack = metrics["attack"]
    ttp = [metrics[name] for name in TARGET_TTPS]
    return {"attack_precision": attack["precision"], "attack_recall": attack["recall"],
            "attack_f1": attack["f1"], "attack_average_precision": attack["average_precision"],
            "benign_admin_false_positives": attack["fp"],
            "macro_ttp_precision": sum(row["precision"] for row in ttp) / len(ttp),
            "macro_ttp_recall": sum(row["recall"] for row in ttp) / len(ttp),
            "macro_ttp_f1": sum(row["f1"] for row in ttp) / len(ttp),
            "macro_ttp_average_precision": (sum(row["average_precision"] for row in ttp) / len(ttp)
                                            if all(row["average_precision"] is not None for row in ttp)
                                            else None)}


def compare_experiments(root: Path) -> dict:
    root = Path(root)
    logistic = BaselineBundle.load(root / "logistic").content
    hybrid = HybridBundle.load(root / "hybrid_logistic").content
    gru = SequenceBundle.load(root / "gru").content
    attention = SequenceBundle.load(root / "gru_attention").content
    combined = SequenceHybridBundle.load(root / "hybrid_gru_attention").content
    bundles = (logistic, hybrid, gru, attention, combined)
    if len({bundle["reviewed_manifest_sha256"] for bundle in bundles}) != 1:
        raise ValueError("Experiment bundles use different reviewed manifests")
    if len({bundle["detector_status"] for bundle in bundles}) != 1:
        raise ValueError("Experiment bundles mix synthetic and real status")
    results = {
        "logistic": _summary({head: value["test"] for head, value in logistic["metrics"]["by_head"].items()}),
        "hybrid_logistic": _summary({head: value["hybrid"] for head, value in hybrid["comparisons"].items()}),
        "gru": _summary({head: value["test"] for head, value in gru["metrics"]["by_head"].items()}),
        "gru_attention": _summary({head: value["test"] for head, value in attention["metrics"]["by_head"].items()}),
        "hybrid_gru_attention": _summary({head: value["hybrid"] for head, value in combined["comparisons"].items()}),
        "generated_rules_only": _summary({head: value["rule_only"] for head, value in combined["comparisons"].items()}),
    }
    return {"detector_status": logistic["detector_status"],
            "reviewed_manifest_sha256": logistic["reviewed_manifest_sha256"],
            "evaluation_unit": "reviewed_event_or_window_end",
            "results": results,
            "limitations": ["No session detection, alerts per benign hour, or SIEM latency in local training",
                            "Synthetic metrics are pipeline checks only"] if logistic["detector_status"] == "synthetic_smoke"
                           else ["Session detection, benign hours, and SIEM latency require held-out lab runs"]}


def write_comparison(root: Path, output_path: Path) -> dict:
    report = compare_experiments(root)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report
