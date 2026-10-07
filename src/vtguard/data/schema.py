from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from vtguard import SCHEMA_VERSION


OBSERVED_FIELDS = (
    "host", "host_role", "channel", "event_id", "record_id", "event_time_utc",
    "ingest_time_utc", "system_time_utc", "sysmon_utc_time", "user", "logon_id",
    "process_guid", "parent_process_guid", "pid", "image", "parent_image",
    "command_line", "script_block_text", "script_block_id", "fragment_number",
    "fragment_total", "destination_ip", "destination_port", "dns_query",
)
TARGET_TTPS = ("T1016", "T1049", "T1018", "T1087.002", "T1654")
ACTIVITY_LABELS = ("unknown", "ambiguous", "background", "automation-control", "benign-admin", "attack")


@dataclass
class Labels:
    activity: str = "unknown"
    ttps: list[str] = field(default_factory=list)
    confidence: float | None = None
    evidence: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.activity not in ACTIVITY_LABELS:
            raise ValueError(f"Unsupported activity label: {self.activity}")
        if any(ttp not in TARGET_TTPS for ttp in self.ttps):
            raise ValueError("TTP label outside the five target techniques")
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("Label confidence must be in [0, 1]")


@dataclass
class Provenance:
    source_dataset: str
    source_version: str | None
    source_file: str
    raw_ref: str
    run_id: str | None = None
    scenario_id: str | None = None
    scenario_family: str | None = None
    is_synthetic: bool = False


@dataclass
class NormalizedEvent:
    event_uid: str
    provenance: Provenance
    labels: Labels = field(default_factory=Labels)
    schema_version: str = SCHEMA_VERSION
    host: str | None = None
    host_role: str | None = None
    channel: str | None = None
    event_id: int | None = None
    record_id: str | None = None
    event_time_utc: str | None = None
    ingest_time_utc: str | None = None
    system_time_utc: str | None = None
    sysmon_utc_time: str | None = None
    user: str | None = None
    logon_id: str | None = None
    process_guid: str | None = None
    parent_process_guid: str | None = None
    pid: int | None = None
    image: str | None = None
    parent_image: str | None = None
    command_line: str | None = None
    script_block_text: str | None = None
    script_block_id: str | None = None
    fragment_number: int | None = None
    fragment_total: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    dns_query: str | None = None
    missing: dict[str, bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"Unsupported schema version: {self.schema_version}")
        self.missing = {name: getattr(self, name) is None for name in OBSERVED_FIELDS}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def model_input(event: NormalizedEvent) -> dict[str, Any]:
    """Only approved observable fields; no source, identity shortcut, or label metadata."""
    allowed = ("channel", "event_id", "event_time_utc", "image", "parent_image",
               "command_line", "script_block_text", "destination_ip", "destination_port",
               "dns_query")
    return {name: getattr(event, name) for name in allowed} | {
        "missing": {name: event.missing[name] for name in allowed}
    }
