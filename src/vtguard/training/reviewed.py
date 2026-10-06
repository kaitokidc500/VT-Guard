from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from vtguard import SCHEMA_VERSION
from vtguard.data.adapters import ParseIssue, read_events
from vtguard.data.schema import Labels, NormalizedEvent, TARGET_TTPS


SPLITS = ("train", "validation", "test")


@dataclass
class ReviewedExample:
    event: NormalizedEvent
    split: str


def _checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validated_annotation(annotation: dict) -> Labels:
    if annotation.get("activity") not in ("attack", "benign-admin"):
        raise ValueError("Baseline needs independently reviewed attack or benign-admin activity")
    if set(annotation.get("reviewed_techniques", [])) != set(TARGET_TTPS):
        raise ValueError("Each annotation must explicitly review all five TTPs")
    if not annotation.get("reviewed_by") or not annotation.get("evidence"):
        raise ValueError("Annotation needs reviewer and evidence")
    confidence = annotation.get("confidence")
    if confidence is None:
        raise ValueError("Annotation confidence is required")
    return Labels(annotation["activity"], list(annotation.get("ttps", [])),
                  float(confidence), list(annotation["evidence"]))


def load_reviewed(manifest_path: Path, *, allow_synthetic: bool = False
                  ) -> tuple[list[ReviewedExample], dict]:
    """Load only reviewed event annotations and enforce split leakage checks."""
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported reviewed manifest schema")
    if manifest.get("attack_version") != "19.2":
        raise ValueError("Reviewed manifest must pin Enterprise ATT&CK v19.2")
    examples: list[ReviewedExample] = []
    families: dict[str, str] = {}
    file_hash_splits: dict[str, str] = {}
    observations: dict[tuple, str] = {}
    run_ids: set[str] = set()
    run_counts = {split: 0 for split in SPLITS}
    unreviewed = 0
    for run in manifest.get("runs", []):
        run_id = run.get("run_id")
        family = run.get("scenario_family")
        split = run.get("split")
        if not run_id or not family or split not in SPLITS or run_id in run_ids:
            raise ValueError("Each run needs unique ID, scenario family, and explicit split")
        run_ids.add(run_id)
        if family in families and families[family] != split:
            raise ValueError("Scenario family crosses splits")
        families[family] = split
        is_synthetic = bool(run.get("is_synthetic", False))
        if is_synthetic and not allow_synthetic:
            raise ValueError("Synthetic data forbidden for real baseline training")
        source_path = Path(run["file_path"])
        if not source_path.is_absolute():
            source_path = manifest_path.parent / source_path
        if not source_path.is_file() or _checksum(source_path) != run.get("sha256"):
            raise ValueError(f"Source checksum mismatch: {run_id}")
        file_hash = run["sha256"]
        if file_hash in file_hash_splits and file_hash_splits[file_hash] != split:
            raise ValueError("Same raw file content crosses splits")
        file_hash_splits[file_hash] = split
        annotations = {}
        for annotation in run.get("annotations", []):
            line = annotation.get("line")
            if not isinstance(line, int) or line < 1 or line in annotations:
                raise ValueError("Annotation line must be a unique positive integer")
            annotations[line] = _validated_annotation(annotation)
        if not annotations:
            raise ValueError(f"Run has no reviewed annotations: {run_id}")
        observed_lines: set[int] = set()
        for event in read_events(source_path, run["input_format"], run["source_dataset"],
                                 run.get("source_version"), synthetic=is_synthetic):
            if isinstance(event, ParseIssue):
                raise ValueError(f"Parse issue in reviewed run: {event.raw_ref}: {event.reason}")
            locator = event.provenance.raw_ref.rsplit("#", 1)[-1]
            line = int(locator[1:]) if locator.startswith("L") else 1
            if line not in annotations:
                unreviewed += 1
                continue
            if not event.event_time_utc:
                raise ValueError("Reviewed event lacks a usable UTC event time")
            event.provenance.run_id = run_id
            event.provenance.scenario_family = family
            event.labels = annotations[line]
            observed_lines.add(line)
            if event.record_id is not None:
                key = (event.host, event.channel, event.event_id,
                       event.record_id, event.event_time_utc)
                prior_split = observations.get(key)
                if prior_split is not None:
                    raise ValueError(f"Repeated observation in reviewed corpus: {prior_split}/{split}")
                observations[key] = split
            examples.append(ReviewedExample(event, split))
        if observed_lines != set(annotations):
            raise ValueError(f"Annotations reference absent event lines in {run_id}")
        run_counts[split] += 1
    if not examples or any(count == 0 for count in run_counts.values()):
        raise ValueError("Reviewed corpus needs runs in train, validation, and test")
    examples.sort(key=lambda row: (row.event.provenance.run_id or "", row.event.event_time_utc or "", row.event.record_id or ""))
    return examples, {
        "run_counts": run_counts,
        "scenario_family_counts": {split: sum(value == split for value in families.values()) for split in SPLITS},
        "unreviewed_events_excluded": unreviewed,
        "source_hashes": sorted(file_hash_splits),
        "synthetic": any(row.event.provenance.is_synthetic for row in examples),
    }
