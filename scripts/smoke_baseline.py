from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.training.baseline import train_baseline
from vtguard.training.synthetic_fixture import make_fixture


def main() -> None:
    manifest = make_fixture(ROOT / "artifacts/baseline_smoke_input")
    result = train_baseline(manifest, ROOT / "artifacts/baseline_smoke_bundle",
                            allow_synthetic=True)
    print(json.dumps({"status": result["detector_status"], "counts": result["counts"],
                      "bundle_dir": result["bundle_dir"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
