"""Tiny synthetic data solely for exercising the reviewed-data training path."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

from vtguard.data.schema import TARGET_TTPS


CASES = (
    ("benign_notepad", "benign-admin", (), "notepad.exe", "notepad.exe"),
    ("benign_ipconfig", "benign-admin", ("T1016",), "ipconfig.exe", "ipconfig /all"),
    ("attack_t1016", "attack", ("T1016",), "ipconfig.exe", "ipconfig /all"),
    ("attack_t1049", "attack", ("T1049",), "netstat.exe", "netstat -ano"),
    ("attack_t1018", "attack", ("T1018",), "dsquery.exe", "dsquery computer"),
    ("attack_t1087", "attack", ("T1087.002",), "net.exe", "net user /domain"),
    ("attack_t1654", "attack", ("T1654",), "wevtutil.exe", "wevtutil qe System"),
)


def make_fixture(root: Path, *, events_per_run: int = 1) -> Path:
    if not 1 <= events_per_run <= 4:
        raise ValueError("Synthetic fixture supports one to four events per run")
    root = Path(root)
    runs_dir = root / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    runs = []
    for split_index, split in enumerate(("train", "validation", "test")):
        for case_index, (name, activity, ttps, image, command) in enumerate(CASES):
            run_id = f"fixture_{split}_{name}"
            timestamp = f"2026-10-06T{10 + split_index:02d}:{case_index:02d}:00Z"
            payloads = []
            annotations = []
            for event_index in range(events_per_run):
                event_time = (datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                              + timedelta(seconds=event_index * 5)).isoformat().replace("+00:00", "Z")
                payloads.append({
                    "timestamp": event_time,
                    "data": {"win": {
                        "system": {"eventID": "1",
                                   "eventRecordID": str(10000 + split_index * 1000 + case_index * 10 + event_index),
                                   "channel": "Microsoft-Windows-Sysmon/Operational",
                                   "computer": f"fixture-{split_index}-{case_index}", "systemTime": event_time},
                        "eventdata": {"utcTime": event_time, "image": f"C:\\Windows\\System32\\{image}",
                                      "commandLine": command},
                    }},
                })
                annotations.append({
                    "line": event_index + 1, "activity": activity, "ttps": list(ttps),
                    "reviewed_techniques": list(TARGET_TTPS), "confidence": 1.0,
                    "reviewed_by": "synthetic-fixture",
                    "evidence": ["Synthetic fixture; no real detection evidence"],
                })
            relative = Path("runs") / (run_id + ".jsonl")
            content = ("\n".join(json.dumps(payload) for payload in payloads) + "\n").encode("utf-8")
            (root / relative).write_bytes(content)
            runs.append({
                "run_id": run_id, "scenario_family": run_id, "split": split,
                "run_start_utc": timestamp,
                "run_end_utc": timestamp.replace(":00Z", ":30Z"),
                "boundary_tolerance_seconds": 1.0,
                "file_path": relative.as_posix(), "sha256": hashlib.sha256(content).hexdigest(),
                "input_format": "wazuh-jsonl", "source_dataset": "synthetic-baseline-fixture",
                "source_version": "fixture-v1", "is_synthetic": True,
                "annotations": annotations,
            })
    manifest = {"schema_version": "1.0", "attack_version": "19.2", "runs": runs}
    manifest_path = root / "reviewed_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path
