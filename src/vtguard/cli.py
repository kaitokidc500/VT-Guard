from __future__ import annotations

import argparse
import json
from hashlib import sha256
from pathlib import Path

from vtguard import SCHEMA_VERSION
from vtguard.data.adapters import read_events
from vtguard.data.quality import assess
from vtguard.data.schema import model_input


def _checksum(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(config_path: Path) -> dict:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"Config schema must be {SCHEMA_VERSION}")
    input_path = Path(config["input_path"])
    output_dir = Path(config["output_dir"])
    if not input_path.is_absolute():
        input_path = config_path.parent.parent / input_path
    if not output_dir.is_absolute():
        output_dir = config_path.parent.parent / output_dir
    if not input_path.is_file():
        raise FileNotFoundError(input_path)
    events, report = assess(read_events(
        input_path, config["input_format"], config["source_dataset"],
        config.get("source_version"), synthetic=config.get("synthetic", False)))
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "normalized.jsonl").open("w", encoding="utf-8") as normalized, \
         (output_dir / "model_inputs.jsonl").open("w", encoding="utf-8") as features:
        for event in events:
            normalized.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
            features.write(json.dumps({"event_uid": event.event_uid, "features": model_input(event)},
                                      ensure_ascii=False) + "\n")
    result = report.to_dict() | {
        "schema_version": SCHEMA_VERSION,
        "input_format": config["input_format"],
        "input_sha256": _checksum(input_path),
        "source_version": config.get("source_version"),
        "source_dataset": config["source_dataset"],
        "synthetic_fixture": bool(config.get("synthetic", False)),
        "detector_status": "not_trained",
    }
    (output_dir / "quality.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize telemetry and audit data quality")
    parser.add_argument("config", type=Path, help="JSON config path")
    args = parser.parse_args()
    result = run(args.config)
    print(json.dumps({"parsed_events": result["parsed_events"],
                      "rejected_records": result["rejected_records"],
                      "warnings": result["warnings"],
                      "detector_status": result["detector_status"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
