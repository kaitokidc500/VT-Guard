from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path


def load_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("repository") != "splunk/attack_data":
        raise ValueError("Unexpected public repository")
    commit = manifest.get("commit", "")
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise ValueError("Public source commit must be a full SHA-1")
    ids = [item["id"] for item in manifest["items"]]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate source IDs")
    for item in manifest["items"] + manifest.get("metadata", []):
        parts = Path(item["path"]).parts
        if not parts or ".." in parts or Path(item["path"]).is_absolute():
            raise ValueError("Unsafe source path")
    for item in manifest["items"]:
        if len(item["sha256"]) != 64 or not 0 < item["size"] <= 20_000_000:
            raise ValueError("Invalid source checksum/size")
    for item in manifest.get("metadata", []):
        if len(item.get("sha256", "")) != 64:
            raise ValueError("Missing metadata checksum")
    if len(manifest.get("license_sha256", "")) != 64:
        raise ValueError("Missing license checksum")
    return manifest


def fetch_metadata(manifest: dict, root: Path) -> dict[str, str]:
    """Fetch small pinned scenario descriptions and license for provenance audit."""
    result = {}
    entries = list(manifest.get("metadata", [])) + [
        {"id": "LICENSE", "path": "LICENSE", "sha256": manifest["license_sha256"]}]
    for entry in entries:
        url = ("https://raw.githubusercontent.com/"
               f"splunk/attack_data/{manifest['commit']}/{entry['path']}")
        destination = root / (entry["id"] + Path(entry["path"]).suffix)
        if not destination.exists() or hashlib.sha256(destination.read_bytes()).hexdigest() != entry["sha256"]:
            with urllib.request.urlopen(url, timeout=30) as response:
                content = response.read(100_001)
            if len(content) > 100_000:
                raise ValueError("Metadata file exceeds 100 KB")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            raise ValueError(f"Metadata checksum mismatch: {entry['id']}")
        result[entry["id"]] = digest
    return result


def verify_metadata(manifest: dict, root: Path) -> bool:
    entries = list(manifest.get("metadata", [])) + [
        {"id": "LICENSE", "path": "LICENSE", "sha256": manifest["license_sha256"]}]
    for entry in entries:
        destination = root / (entry["id"] + Path(entry["path"]).suffix)
        if not destination.is_file():
            return False
        if hashlib.sha256(destination.read_bytes()).hexdigest() != entry["sha256"]:
            return False
    return True


def local_path(root: Path, item: dict) -> Path:
    return root / item["id"] / Path(item["path"]).name


def verify(path: Path, item: dict) -> bool:
    if not path.is_file() or path.stat().st_size != item["size"]:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest() == item["sha256"]


def fetch(manifest: dict, item: dict, root: Path) -> Path:
    """Fetch one pinned LFS object with size cap, checksum and atomic placement."""
    destination = local_path(root, item)
    if verify(destination, item):
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    url = ("https://media.githubusercontent.com/media/"
           f"splunk/attack_data/{manifest['commit']}/{item['path']}")
    temporary = destination.with_suffix(destination.suffix + ".partial")
    digest = hashlib.sha256()
    count = 0
    try:
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as target:
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > item["size"]:
                    raise ValueError("Download exceeds pinned size")
                digest.update(chunk)
                target.write(chunk)
        if count != item["size"] or digest.hexdigest() != item["sha256"]:
            raise ValueError("Downloaded file does not match pinned size/SHA-256")
        temporary.replace(destination)
        return destination
    finally:
        temporary.unlink(missing_ok=True)
