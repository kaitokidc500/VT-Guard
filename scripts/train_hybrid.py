from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.training.hybrid import train_hybrid


def main() -> None:
    parser = argparse.ArgumentParser(description="Train reviewed CPU rule + AI baseline")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-synthetic", action="store_true", help="Fixture smoke only")
    parser.add_argument("--min-rule-support", type=int, default=3)
    parser.add_argument("--min-validation-matches", type=int, default=2)
    args = parser.parse_args()
    result = train_hybrid(args.manifest, args.output,
                          allow_synthetic=args.allow_synthetic,
                          min_rule_support=args.min_rule_support,
                          min_validation_matches=args.min_validation_matches)
    print(json.dumps({key: value for key, value in result.items() if key != "comparisons"},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
