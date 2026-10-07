from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from pathlib import Path

from vtguard.data.adapters import ParseIssue, read_events
from vtguard.training.reviewed import load_reviewed


REVIEW_COLUMNS = (
    "line", "event_uid", "event_time_utc", "host", "channel", "event_id",
    "record_id", "image", "command_line", "script_block_text",
    "activity", "ttps", "reviewed_techniques", "confidence", "reviewed_by", "evidence",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_path(base: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    return (path if path.is_absolute() else base / path).resolve()


def _line(raw_ref: str) -> int:
    locator = raw_ref.rsplit("#", 1)[-1]
    return int(locator[1:]) if locator.startswith("L") else 1


def prepare_review_sheets(spec_path: Path, output_dir: Path) -> Path:
    """Generate blank local review CSVs; never infer labels from telemetry."""
    spec_path = Path(spec_path)
    output_dir = Path(output_dir)
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    if spec.get("schema_version") != "1.0" or spec.get("attack_version") != "19.2":
        raise ValueError("Run spec needs schema 1.0 and ATT&CK 19.2")
    output_dir.mkdir(parents=True, exist_ok=True)
    plan = {"schema_version": "1.0", "attack_version": "19.2", "runs": []}
    used_ids: set[str] = set()
    for run in spec.get("runs", []):
        run_id = run.get("run_id", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id) or run_id in used_ids:
            raise ValueError("Run IDs must be unique filename-safe strings")
        used_ids.add(run_id)
        source_path = _source_path(spec_path.parent, run["file_path"])
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
        digest = _sha256(source_path)
        if run.get("sha256") and run["sha256"] != digest:
            raise ValueError(f"Raw checksum mismatch for {run_id}")
        sheet_name = f"review_{run_id}.csv"
        with (output_dir / sheet_name).open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=REVIEW_COLUMNS)
            writer.writeheader()
            for event in read_events(source_path, run["input_format"], run["source_dataset"],
                                     run.get("source_version"), synthetic=bool(run.get("is_synthetic"))):
                if isinstance(event, ParseIssue):
                    raise ValueError(f"Parse issue in {run_id}: {event.raw_ref}: {event.reason}")
                writer.writerow({
                    "line": _line(event.provenance.raw_ref), "event_uid": event.event_uid,
                    "event_time_utc": event.event_time_utc, "host": event.host,
                    "channel": event.channel, "event_id": event.event_id,
                    "record_id": event.record_id, "image": event.image,
                    "command_line": event.command_line,
                    "script_block_text": event.script_block_text,
                })
        try:
            portable_path = os.path.relpath(source_path, output_dir)
        except ValueError:
            portable_path = str(source_path)
        plan["runs"].append({
            key: value for key, value in run.items()
            if key not in ("annotations", "file_path", "sha256", "review_sheet")
        } | {"file_path": portable_path, "sha256": digest, "review_sheet": sheet_name})
    plan_path = output_dir / "review_plan.json"
    plan_path.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    return plan_path


def compile_reviewed_manifest(plan_path: Path, output_path: Path, *,
                              allow_synthetic: bool = False) -> Path:
    """Compile only manually filled rows, then run all training-data gates."""
    plan_path = Path(plan_path)
    output_path = Path(output_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    compiled = {"schema_version": plan["schema_version"],
                "attack_version": plan["attack_version"], "runs": []}
    for run in plan["runs"]:
        sheet = plan_path.parent / run["review_sheet"]
        source = _source_path(plan_path.parent, run["file_path"])
        if _sha256(source) != run["sha256"]:
            raise ValueError(f"Raw checksum changed for {run['run_id']}")
        event_uids = {}
        for event in read_events(source, run["input_format"], run["source_dataset"],
                                 run.get("source_version"), synthetic=bool(run.get("is_synthetic"))):
            if isinstance(event, ParseIssue):
                raise ValueError(f"Parse issue in {run['run_id']}")
            event_uids[_line(event.provenance.raw_ref)] = event.event_uid
        annotations = []
        seen_lines: set[int] = set()
        with sheet.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not set(REVIEW_COLUMNS).issubset(reader.fieldnames or []):
                raise ValueError(f"Review sheet columns missing: {sheet}")
            for row in reader:
                line = int(row["line"])
                if line in seen_lines or event_uids.get(line) != row["event_uid"]:
                    raise ValueError(f"Review row mismatch or duplicate line: {run['run_id']}:{line}")
                seen_lines.add(line)
                if not row["activity"].strip():
                    continue
                annotations.append({
                    "line": line, "activity": row["activity"].strip(),
                    "ttps": [value.strip() for value in row["ttps"].split("|") if value.strip()],
                    "reviewed_techniques": [value.strip() for value in row["reviewed_techniques"].split("|") if value.strip()],
                    "confidence": float(row["confidence"]),
                    "reviewed_by": row["reviewed_by"].strip(),
                    "evidence": [row["evidence"].strip()] if row["evidence"].strip() else [],
                })
        if seen_lines != set(event_uids):
            missing = sorted(set(event_uids) - seen_lines)
            raise ValueError(f"Review sheet missing raw event rows for {run['run_id']}: {missing[:5]}")
        if annotations:
            try:
                portable_path = os.path.relpath(source, output_path.parent)
            except ValueError:
                portable_path = str(source)
            compiled["runs"].append({key: value for key, value in run.items()
                                     if key not in ("review_sheet", "file_path")}
                                    | {"file_path": portable_path, "annotations": annotations})
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Validation happens against the same parent directory as the final manifest.
    temporary = output_path.with_suffix(output_path.suffix + ".partial")
    temporary.write_text(json.dumps(compiled, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        load_reviewed(temporary, allow_synthetic=allow_synthetic)
        temporary.replace(output_path)
    finally:
        temporary.unlink(missing_ok=True)
    return output_path
