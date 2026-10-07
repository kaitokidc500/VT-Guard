"""Stage a checksum-verified reviewed corpus into disposable Colab scratch space."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

from vtguard.training.reviewed import load_reviewed


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stage_reviewed(manifest_path: Path, output_dir: Path, *,
                   allow_synthetic: bool = False) -> Path:
    """Copy only manifest-listed raw files and rewrite portable relative paths."""
    manifest_path = Path(manifest_path).resolve()
    output_dir = Path(output_dir).resolve()
    load_reviewed(manifest_path, allow_synthetic=allow_synthetic)
    source = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for run in source["runs"]:
        run_id = run["run_id"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id):
            raise ValueError("Run ID is not safe for staged filename")
        input_path = Path(run["file_path"])
        if not input_path.is_absolute():
            input_path = manifest_path.parent / input_path
        input_path = input_path.resolve()
        suffix = input_path.suffix or ".raw"
        relative = Path("raw") / f"{run_id}{suffix}"
        destination = output_dir / relative
        if input_path == destination:
            raise ValueError("Stage directory must differ from source corpus")
        shutil.copyfile(input_path, destination)
        if _sha256(destination) != run["sha256"]:
            destination.unlink(missing_ok=True)
            raise ValueError(f"Staged checksum mismatch for {run_id}")
        run["file_path"] = relative.as_posix()
    staged = output_dir / "reviewed_manifest.json"
    staged.write_text(json.dumps(source, indent=2, ensure_ascii=False), encoding="utf-8")
    load_reviewed(staged, allow_synthetic=allow_synthetic)
    return staged
