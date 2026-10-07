from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from vtguard.data.schema import NormalizedEvent, Provenance


def _get(obj: Any, *names: str) -> Any:
    if not isinstance(obj, dict):
        return None
    lowered = {str(k).lower(): v for k, v in obj.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value is not None:
            return value
    return None


def _text(value: Any) -> str | None:
    if isinstance(value, dict):
        value = _get(value, "#text", "text", "value")
    if value is None:
        return None
    result = str(value).strip()
    return result or None


def _integer(value: Any) -> int | None:
    value = _text(value)
    if value is None:
        return None
    try:
        return int(value, 0) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _utc(value: Any, *, declared_utc: bool = False) -> str | None:
    value = _text(value)
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            if not declared_utc:
                return None  # A timezone-free timestamp cannot safely order events.
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except ValueError:
        return None


def _event_data(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        items = _get(value, "Data")
        if isinstance(items, list):
            return {str(_get(item, "@Name", "Name")): _get(item, "#text", "text", "value")
                    for item in items if isinstance(item, dict) and _get(item, "@Name", "Name")}
        if isinstance(items, dict) and _get(items, "@Name", "Name"):
            return {str(_get(items, "@Name", "Name")): _get(items, "#text", "text", "value")}
        return value
    return {}


def normalize(payload: dict[str, Any], provenance: Provenance, ordinal: int) -> NormalizedEvent:
    """One shared, causal conversion for offline files and future online records.

    Wazuh alert metadata is deliberately ignored. Labels are never inferred from paths,
    commands, rule IDs, or ATT&CK tags.
    """
    data = _get(payload, "data") or {}
    win = _get(data, "win") or _get(payload, "win") or {}
    source = win if isinstance(win, dict) and win else payload
    event = _get(source, "Event") or source
    system = _get(event, "system", "System") or {}
    event_data = _event_data(_get(event, "eventdata", "EventData") or {})
    time_created = _get(system, "TimeCreated")
    system_time = _utc(_get(time_created, "@SystemTime", "SystemTime") if isinstance(time_created, dict) else time_created)
    system_time = system_time or _utc(_get(system, "SystemTime"))
    sysmon_time = _utc(_get(event_data, "UtcTime"), declared_utc=True)
    # Sysmon UtcTime is the event's own timestamp; retain the XML system timestamp too.
    event_time = sysmon_time or system_time or _utc(_get(payload, "event_time", "EventTime"))
    ingest_time = _utc(_get(payload, "timestamp", "@timestamp", "ingest_time"))
    provider = _get(system, "Provider") or {}
    channel = _text(_get(system, "Channel")) or _text(_get(payload, "channel"))
    if channel is None:
        channel = _text(_get(provider, "@Name", "Name"))
    raw_key = f"{provenance.source_dataset}|{provenance.source_version}|{provenance.source_file}|{ordinal}"
    uid = sha256(raw_key.encode("utf-8")).hexdigest()
    return NormalizedEvent(
        event_uid=uid, provenance=provenance,
        host=_text(_get(system, "Computer")) or _text(_get(payload, "host", "hostname", "Computer"))
             or _text(_get(_get(payload, "agent") or {}, "name")),
        channel=channel,
        event_id=_integer(_get(system, "EventID") or _get(payload, "event_id", "EventID")),
        record_id=_text(_get(system, "EventRecordID") or _get(payload, "record_id")),
        event_time_utc=event_time, ingest_time_utc=ingest_time,
        system_time_utc=system_time, sysmon_utc_time=sysmon_time,
        user=_text(_get(event_data, "User", "UserName", "SubjectUserName", "TargetUserName")),
        logon_id=_text(_get(event_data, "LogonId", "SubjectLogonId", "TargetLogonId")),
        process_guid=_text(_get(event_data, "ProcessGuid")),
        parent_process_guid=_text(_get(event_data, "ParentProcessGuid")),
        pid=_integer(_get(event_data, "ProcessId", "NewProcessId")),
        image=_text(_get(event_data, "Image", "NewProcessName")),
        parent_image=_text(_get(event_data, "ParentImage")),
        command_line=_text(_get(event_data, "CommandLine", "ProcessCommandLine")),
        script_block_text=_text(_get(event_data, "ScriptBlockText")),
        script_block_id=_text(_get(event_data, "ScriptBlockId")),
        fragment_number=_integer(_get(event_data, "MessageNumber")),
        fragment_total=_integer(_get(event_data, "MessageTotal")),
        destination_ip=_text(_get(event_data, "DestinationIp")),
        destination_port=_integer(_get(event_data, "DestinationPort")),
        dns_query=_text(_get(event_data, "QueryName")),
    )
