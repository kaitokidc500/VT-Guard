"""Summarize reviewed corpus before committing Colab compute."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from vtguard.data.schema import TARGET_TTPS
from vtguard.features.sequence import SequenceConfig, offline_windows
from vtguard.training.reviewed import SPLITS, load_reviewed


def inspect_reviewed(manifest_path: Path, *, allow_synthetic: bool = False,
                     sequence_config: SequenceConfig = SequenceConfig()) -> dict:
    rows, gate = load_reviewed(manifest_path, allow_synthetic=allow_synthetic)
    by_split = {}
    warnings = []
    for split in SPLITS:
        subset = [row for row in rows if row.split == split]
        activities = Counter(row.event.labels.activity for row in subset)
        source_activity = defaultdict(Counter)
        for row in subset:
            source_activity[row.event.provenance.source_dataset][row.event.labels.activity] += 1
        ordered = sorted(subset, key=lambda row: (row.event.event_time_utc, row.event.event_uid))
        windows = offline_windows([row.event for row in ordered], sequence_config)
        by_split[split] = {
            "events": len(subset), "runs": gate["run_counts"][split],
            "families": gate["scenario_family_counts"][split],
            "activities": dict(activities),
            "ttp_positives": {ttp: sum(ttp in row.event.labels.ttps for row in subset)
                              for ttp in TARGET_TTPS},
            "source_activity": {name: dict(counts) for name, counts in source_activity.items()},
            "multi_event_windows": sum(len(window) > 1 for window in windows),
            "missing_host": sum(not row.event.host for row in subset),
            "missing_logon_or_user": sum(not (row.event.logon_id or row.event.user) for row in subset),
        }
        if any(len(counts) == 1 for counts in source_activity.values()):
            warnings.append(f"{split}: some sources contain only one activity class; audit source leakage")
    if gate["unreviewed_events_excluded"]:
        warnings.append("Some raw events have no reviewed label and are excluded from training context")
    if not by_split["train"]["multi_event_windows"]:
        warnings.append("Train has no multi-event windows; sequence model cannot be assessed")
    if gate["synthetic"]:
        warnings.append("Synthetic fixture only; not a real training corpus")
    return {"schema_version": "1.0", "manifest": str(Path(manifest_path).resolve()),
            "gate": gate, "by_split": by_split, "warnings": warnings,
            "sequence_ready": bool(by_split["train"]["multi_event_windows"] or gate["synthetic"]),
            "sequence_window_present": bool(by_split["train"]["multi_event_windows"])}


def write_readiness(manifest_path: Path, output_path: Path, *,
                    allow_synthetic: bool = False) -> dict:
    report = inspect_reviewed(manifest_path, allow_synthetic=allow_synthetic)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report
