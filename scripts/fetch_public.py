from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.data.public_sources import fetch, fetch_metadata, load_manifest, local_path, verify, verify_metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch selected pinned Splunk attack_data files")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    manifest = load_manifest(ROOT / "configs/public_sources.json")
    data_root = ROOT / "data/public/splunk/pinned"
    for item in manifest["items"]:
        path = local_path(data_root, item)
        if args.verify_only:
            if not verify(path, item):
                raise SystemExit(f"Missing or checksum mismatch: {item['id']}")
        else:
            path = fetch(manifest, item, data_root)
        print(f"{item['id']}: {path.stat().st_size} bytes; SHA-256 OK")
    if not args.verify_only:
        for key, digest in fetch_metadata(manifest, ROOT / "data/public/splunk/metadata").items():
            print(f"metadata {key}: SHA-256 {digest}")
    elif not verify_metadata(manifest, ROOT / "data/public/splunk/metadata"):
        raise SystemExit("Missing or checksum mismatch in scenario metadata/license")


if __name__ == "__main__":
    main()
