from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.data.review_sheet import compile_reviewed_manifest, prepare_review_sheets


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare or compile local reviewed run sheets")
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--spec", required=True, type=Path)
    prepare.add_argument("--output-dir", required=True, type=Path)
    compile_cmd = sub.add_parser("compile")
    compile_cmd.add_argument("--plan", required=True, type=Path)
    compile_cmd.add_argument("--output", required=True, type=Path)
    compile_cmd.add_argument("--allow-synthetic", action="store_true", help="Fixture smoke only")
    args = parser.parse_args()
    if args.command == "prepare":
        print(prepare_review_sheets(args.spec, args.output_dir))
    else:
        print(compile_reviewed_manifest(args.plan, args.output,
                                        allow_synthetic=args.allow_synthetic))


if __name__ == "__main__":
    main()
