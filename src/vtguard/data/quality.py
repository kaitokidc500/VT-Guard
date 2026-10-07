from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from vtguard.data.adapters import ParseIssue
from vtguard.data.schema import NormalizedEvent, OBSERVED_FIELDS


@dataclass
class QualityReport:
    input_records: int = 0
    parsed_events: int = 0
    rejected_records: int = 0
    duplicate_event_uids: int = 0
    duplicate_observations: int = 0
    missing: Counter = field(default_factory=Counter)
    by_channel_event_id: Counter = field(default_factory=Counter)
    by_activity: Counter = field(default_factory=Counter)
    by_ttp: Counter = field(default_factory=Counter)
    by_source: Counter = field(default_factory=Counter)
    host_count: int = 0
    run_count: int = 0
    events_without_run: int = 0
    ingest_before_event: int = 0
    issues: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "input_records": self.input_records, "parsed_events": self.parsed_events,
            "rejected_records": self.rejected_records,
            "duplicate_event_uids": self.duplicate_event_uids,
            "duplicate_observations": self.duplicate_observations,
            "missing": dict(self.missing),
            "by_channel_event_id": dict(self.by_channel_event_id),
            "by_activity": dict(self.by_activity), "by_ttp": dict(self.by_ttp),
            "by_source": dict(self.by_source), "host_count": self.host_count,
            "run_count": self.run_count, "events_without_run": self.events_without_run,
            "ingest_before_event": self.ingest_before_event, "issues": self.issues,
            "warnings": self.warnings(),
        }

    def warnings(self) -> list[str]:
        warnings = []
        if self.rejected_records:
            warnings.append("Input contains rejected records")
        if self.duplicate_observations:
            warnings.append("Repeated same-channel observations need review")
        if self.events_without_run:
            warnings.append("Run/session boundaries absent; sequence training is unsafe")
        if self.by_activity.get("unknown", 0) == self.parsed_events:
            warnings.append("All labels unknown; no supervised training claim")
        if self.ingest_before_event:
            warnings.append("Ingestion precedes event time; inspect clock/time mapping")
        return warnings


def assess(items: Iterable[NormalizedEvent | ParseIssue]) -> tuple[list[NormalizedEvent], QualityReport]:
    report = QualityReport()
    events: list[NormalizedEvent] = []
    uids: set[str] = set()
    observations: set[tuple] = set()
    hosts: set[str] = set()
    runs: set[str] = set()
    for item in items:
        report.input_records += 1
        if isinstance(item, ParseIssue):
            report.rejected_records += 1
            if len(report.issues) < 20:
                report.issues.append({"raw_ref": item.raw_ref, "reason": item.reason})
            continue
        event = item
        events.append(event)
        report.parsed_events += 1
        report.duplicate_event_uids += event.event_uid in uids
        uids.add(event.event_uid)
        # Keep Sysmon 1 and Security 4688 separate even when they describe one process.
        key = (event.provenance.source_dataset, event.host, event.channel,
               event.record_id, event.event_id, event.event_time_utc)
        if event.record_id is not None and key in observations:
            report.duplicate_observations += 1
        observations.add(key)
        for name in OBSERVED_FIELDS:
            report.missing[name] += event.missing[name]
        report.by_channel_event_id[f"{event.channel or '<missing>'}:{event.event_id if event.event_id is not None else '<missing>'}"] += 1
        report.by_activity[event.labels.activity] += 1
        for ttp in event.labels.ttps:
            report.by_ttp[ttp] += 1
        report.by_source[event.provenance.source_dataset] += 1
        if event.host:
            hosts.add(event.host)
        if event.provenance.run_id:
            runs.add(event.provenance.run_id)
        else:
            report.events_without_run += 1
        if event.event_time_utc and event.ingest_time_utc:
            if datetime.fromisoformat(event.ingest_time_utc.replace("Z", "+00:00")) < datetime.fromisoformat(event.event_time_utc.replace("Z", "+00:00")):
                report.ingest_before_event += 1
    report.host_count = len(hosts)
    report.run_count = len(runs)
    return events, report
