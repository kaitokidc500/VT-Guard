"""Print a bounded evidence review; this script never assigns labels."""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.data.adapters import ParseIssue, read_events
from vtguard.data.public_sources import load_manifest, local_path


def main() -> None:
    manifest = load_manifest(ROOT / "configs/public_sources.json")
    root = ROOT / "data/public/splunk/pinned"
    for item in manifest["items"]:
        path = local_path(root, item)
        commands: Counter = Counter()
        scripts: Counter = Counter()
        old_or_new: Counter = Counter()
        technique_like: list[tuple[str, str]] = []
        query_terms = {
            "t1016_sysmon": ("ipconfig", "route print", "arp.exe", "arp -a"),
            "t1049_sysmon": ("netstat", "get-nettcpconnection", "get-netudpendpoint"),
            "t1018_sysmon": ("net view", "dsquery", "nltest", "get-adcomputer", "get-netcomputer"),
            "t1654_sysmon": ("wevtutil", "get-winevent", "get-eventlog", "win32_ntlogevent", "psloglist"),
        }.get(item["id"], ())
        for record in read_events(path, "windows-event-xml", item["id"], manifest["commit"]):
            if isinstance(record, ParseIssue):
                continue
            if record.command_line:
                commands[record.command_line] += 1
                if any(term in record.command_line.lower() for term in query_terms):
                    technique_like.append((record.provenance.raw_ref.rsplit("#", 1)[-1], record.command_line))
            if record.script_block_text:
                scripts[record.script_block_text] += 1
            if record.event_time_utc:
                old_or_new[record.event_time_utc[:10]] += 1
        print(f"\n--- {item['id']} dates: {old_or_new.most_common(8)}")
        for value, count in commands.most_common(12):
            print(f"command x{count}: {value[:220]}")
        for value, count in scripts.most_common(6):
            print(f"script x{count}: {value[:400]}")
        print(f"technique-like command events: {len(technique_like)}")
        for ref, value in technique_like[:12]:
            print(f"candidate {ref}: {value[:220]}")


if __name__ == "__main__":
    main()
