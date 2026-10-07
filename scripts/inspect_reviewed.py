from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.training.readiness import write_readiness


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit reviewed run/class/source readiness")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-synthetic", action="store_true", help="Fixture smoke only")
    args = parser.parse_args()
    report = write_readiness(args.manifest, args.output, allow_synthetic=args.allow_synthetic)
    print(json.dumps({"sequence_window_present": report["sequence_window_present"],
                      "by_split": report["by_split"], "warnings": report["warnings"]},
                     ensure_ascii=False))
    if not report["sequence_ready"]:
        raise SystemExit("Reviewed corpus has no train multi-event windows")


if __name__ == "__main__":
    main()
