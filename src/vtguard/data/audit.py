from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

from vtguard.data.adapters import ParseIssue, read_events
from vtguard.data.public_sources import local_path, verify
from vtguard.data.schema import OBSERVED_FIELDS


def _time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def audit_public(manifest: dict, root: Path) -> dict:
    """Audit pinned files without inferring per-event labels from path metadata."""
    sources: list[dict] = []
    seen_observations: dict[tuple, str] = {}
    overlaps: Counter = Counter()
    for item in manifest["items"]:
        path = local_path(root, item)
        if not verify(path, item):
            raise ValueError(f"Missing or checksum mismatch: {item['id']}")
        summary = {
            "id": item["id"], "technique_context": item["technique_context"],
            "dataset_id": item["dataset_id"], "sha256": item["sha256"],
            "size": item["size"], "events": 0, "parse_issues": 0,
            "event_ids": Counter(), "channels": Counter(), "hosts": Counter(),
            "missing": Counter(), "activity_labels": Counter(),
            "run_ids": Counter(), "images": Counter(),
            "event_time_min": None, "event_time_max": None,
            "file_order_time_inversions": 0, "five_minute_gaps_in_file_order": 0,
            "same_file_duplicate_observations": 0,
            "script_fragments": 0, "commands_present": 0,
            "examples": [], "issues": [],
        }
        previous_time = None
        own_keys: set[tuple] = set()
        for record in read_events(path, "windows-event-xml", item["id"], manifest["commit"]):
            if isinstance(record, ParseIssue):
                summary["parse_issues"] += 1
                if len(summary["issues"]) < 5:
                    summary["issues"].append({"ref": record.raw_ref, "reason": record.reason})
                continue
            event = record
            summary["events"] += 1
            summary["event_ids"][str(event.event_id)] += 1
            summary["channels"][event.channel or "<missing>"] += 1
            summary["hosts"][event.host or "<missing>"] += 1
            summary["activity_labels"][event.labels.activity] += 1
            if event.provenance.run_id:
                summary["run_ids"][event.provenance.run_id] += 1
            for field in OBSERVED_FIELDS:
                summary["missing"][field] += event.missing[field]
            if event.image:
                summary["images"][event.image.replace("\\", "/").rsplit("/", 1)[-1].lower()] += 1
            if event.command_line:
                summary["commands_present"] += 1
            if event.fragment_number is not None or event.fragment_total is not None:
                summary["script_fragments"] += 1
            if len(summary["examples"]) < 5 and (event.command_line or event.script_block_text):
                # Example references identify evidence without copying sensitive command text.
                summary["examples"].append(event.provenance.raw_ref)
            event_time = _time(event.event_time_utc)
            if event_time:
                text_time = event.event_time_utc
                if summary["event_time_min"] is None or text_time < summary["event_time_min"]:
                    summary["event_time_min"] = text_time
                if summary["event_time_max"] is None or text_time > summary["event_time_max"]:
                    summary["event_time_max"] = text_time
                if previous_time is not None:
                    summary["file_order_time_inversions"] += event_time < previous_time
                    summary["five_minute_gaps_in_file_order"] += abs((event_time - previous_time).total_seconds()) > 300
                previous_time = event_time
            if event.record_id is not None:
                key = (event.host, event.channel, event.event_id, event.record_id, event.event_time_utc)
                summary["same_file_duplicate_observations"] += key in own_keys
                own_keys.add(key)
                other = seen_observations.get(key)
                if other and other != item["id"]:
                    overlaps[f"{other}|{item['id']}"] += 1
                else:
                    seen_observations[key] = item["id"]
        for key in ("event_ids", "channels", "hosts", "missing", "activity_labels", "run_ids", "images"):
            summary[key] = dict(summary[key])
        summary["independent_run_boundaries_verified"] = False
        sources.append(summary)
    return {
        "repository": manifest["repository"], "commit": manifest["commit"],
        "license": manifest["license"], "sources": sources,
        "cross_file_duplicate_observations": dict(overlaps),
        "label_policy": "All event labels remain unknown until independent evidence review",
        "session_policy": "File/time-gap groups are not verified independent runs",
    }
