from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.data.stage import stage_reviewed


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify and stage selected reviewed data")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--allow-synthetic", action="store_true", help="Fixture smoke only")
    args = parser.parse_args()
    print(stage_reviewed(args.manifest, args.output_dir,
                         allow_synthetic=args.allow_synthetic))


if __name__ == "__main__":
    main()
