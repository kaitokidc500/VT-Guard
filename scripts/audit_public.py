from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.data.audit import audit_public
from vtguard.data.public_sources import load_manifest


def main() -> None:
    manifest = load_manifest(ROOT / "configs/public_sources.json")
    result = audit_public(manifest, ROOT / "data/public/splunk/pinned")
    output = ROOT / "artifacts/public_audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    for source in result["sources"]:
        print(f"{source['id']}: {source['events']} events, {source['parse_issues']} parse issues, "
              f"{len(source['hosts'])} hosts, {len(source['run_ids'])} verified runs")
    print(f"Cross-file repeated observations: {result['cross_file_duplicate_observations']}")
    print(f"Full audit: {output}")


if __name__ == "__main__":
    main()
