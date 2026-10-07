from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from vtguard.data.normalize import normalize
from vtguard.data.schema import NormalizedEvent, Provenance


@dataclass
class ParseIssue:
    raw_ref: str
    reason: str


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_payload(root: ET.Element) -> dict:
    if _local(root.tag) != "Event":
        raise ValueError("XML root is not a Windows Event")
    system: dict = {}
    eventdata: dict = {}
    for child in root:
        section = _local(child.tag)
        if section == "System":
            for item in child:
                key = _local(item.tag)
                system[key] = dict(item.attrib) if item.attrib else item.text
        elif section in ("EventData", "UserData"):
            for item in child.iter():
                if item is child:
                    continue
                name = item.attrib.get("Name") or _local(item.tag)
                if item.text and item.text.strip():
                    eventdata[name] = item.text
    return {"System": system, "EventData": eventdata}


def read_events(path: Path, input_format: str, source_dataset: str,
                source_version: str | None = None, *, synthetic: bool = False
                ) -> Iterator[NormalizedEvent | ParseIssue]:
    """Stream JSONL; accept a single complete Windows Event XML document.

    Any malformed line becomes an issue. Input is bounded by line except single XML.
    The caller must supply provenance; filename/TTP paths are never used as labels.
    """
    if input_format not in ("wazuh-jsonl", "splunk-jsonl", "windows-event-xml"):
        raise ValueError(f"Unsupported input format: {input_format}")
    path = Path(path)
    if input_format == "windows-event-xml":
        try:
            with path.open("r", encoding="utf-8-sig") as handle:
                first = next((line for line in handle if line.strip()), "")
            if first.strip().endswith("</Event>"):
                # Splunk attack_data .log files store one complete Event XML per line.
                with path.open("r", encoding="utf-8-sig") as handle:
                    for number, line in enumerate(handle, 1):
                        if not line.strip():
                            continue
                        raw_ref = f"{path}#L{number}"
                        try:
                            payload = _xml_payload(ET.fromstring(line))
                            provenance = Provenance(source_dataset, source_version, str(path), raw_ref,
                                                    is_synthetic=synthetic)
                            yield normalize(payload, provenance, number)
                        except (ET.ParseError, ValueError) as exc:
                            yield ParseIssue(raw_ref, f"{type(exc).__name__}: {exc}")
            else:
                root = ET.parse(path).getroot()
                payload = _xml_payload(root)
                provenance = Provenance(source_dataset, source_version, str(path), f"{path}#event-1",
                                        is_synthetic=synthetic)
                yield normalize(payload, provenance, 1)
        except (ET.ParseError, ValueError, OSError) as exc:
            yield ParseIssue(str(path), f"{type(exc).__name__}: {exc}")
        return
    with path.open("r", encoding="utf-8-sig") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            raw_ref = f"{path}#L{number}"
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise ValueError("Expected one JSON object per line")
                provenance = Provenance(source_dataset, source_version, str(path), raw_ref,
                                        is_synthetic=synthetic)
                yield normalize(payload, provenance, number)
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                yield ParseIssue(raw_ref, f"{type(exc).__name__}: {exc}")
