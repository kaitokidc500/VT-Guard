"""Tiny synthetic data solely for exercising the reviewed-data training path."""
from __future__ import annotations

import hashlib
import json
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


def make_fixture(root: Path) -> Path:
    root = Path(root)
    runs_dir = root / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    runs = []
    for split_index, split in enumerate(("train", "validation", "test")):
        for case_index, (name, activity, ttps, image, command) in enumerate(CASES):
            run_id = f"fixture_{split}_{name}"
            timestamp = f"2026-10-06T{10 + split_index:02d}:{case_index:02d}:00Z"
            payload = {
                "timestamp": timestamp,
                "data": {"win": {
                    "system": {"eventID": "1", "eventRecordID": str(1000 + split_index * 100 + case_index),
                               "channel": "Microsoft-Windows-Sysmon/Operational",
                               "computer": f"fixture-{split_index}-{case_index}", "systemTime": timestamp},
                    "eventdata": {"utcTime": timestamp, "image": f"C:\\Windows\\System32\\{image}",
                                  "commandLine": command},
                }},
            }
            relative = Path("runs") / (run_id + ".jsonl")
            content = (json.dumps(payload) + "\n").encode("utf-8")
            (root / relative).write_bytes(content)
            runs.append({
                "run_id": run_id, "scenario_family": run_id, "split": split,
                "file_path": relative.as_posix(), "sha256": hashlib.sha256(content).hexdigest(),
                "input_format": "wazuh-jsonl", "source_dataset": "synthetic-baseline-fixture",
                "source_version": "fixture-v1", "is_synthetic": True,
                "annotations": [{
                    "line": 1, "activity": activity, "ttps": list(ttps),
                    "reviewed_techniques": list(TARGET_TTPS), "confidence": 1.0,
                    "reviewed_by": "synthetic-fixture",
                    "evidence": ["Synthetic fixture; no real detection evidence"],
                }],
            })
    manifest = {"schema_version": "1.0", "attack_version": "19.2", "runs": runs}
    manifest_path = root / "reviewed_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path
