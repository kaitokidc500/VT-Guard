from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.evaluation.experiment import write_comparison


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare verified baseline, GRU and hybrid bundles")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = write_comparison(args.root, args.output)
    print(json.dumps({"status": report["detector_status"],
                      "models": list(report["results"]), "output": str(args.output)},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
