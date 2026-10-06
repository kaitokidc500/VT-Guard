from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.training.baseline import train_baseline


def main() -> None:
    parser = argparse.ArgumentParser(description="Train reviewed, single-event CPU baseline")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-synthetic", action="store_true", help="For pipeline smoke tests only")
    args = parser.parse_args()
    result = train_baseline(args.manifest, args.output, allow_synthetic=args.allow_synthetic)
    print(json.dumps({"status": result["detector_status"],
                      "counts": result["counts"], "bundle_dir": result["bundle_dir"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
