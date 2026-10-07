"""Causal event windows shared by offline training and online inference."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from vtguard.data.schema import NormalizedEvent


@dataclass(frozen=True)
class SequenceConfig:
    max_events: int = 64
    horizon_seconds: int = 300
    max_groups: int = 1024

    def __post_init__(self) -> None:
        if min(self.max_events, self.horizon_seconds, self.max_groups) < 1:
            raise ValueError("Sequence limits must be positive")


def _time(event: NormalizedEvent) -> datetime:
    if not event.event_time_utc:
        raise ValueError("Sequence event has no canonical UTC time")
    value = datetime.fromisoformat(event.event_time_utc.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("Sequence event time needs timezone")
    return value


def _key(event: NormalizedEvent) -> tuple[str | None, str, str]:
    run = event.provenance.run_id
    host = event.host
    if not host:
        raise ValueError("Sequence needs host")
    # Keep distinct logon contexts apart. A missing identity remains its own group.
    identity = event.logon_id or event.user or "<unknown>"
    return run, host.casefold(), identity.casefold()


class CausalSequenceBuilder:
    def __init__(self, config: SequenceConfig = SequenceConfig()) -> None:
        self.config = config
        self._windows: dict[tuple[str | None, str, str], deque[NormalizedEvent]] = {}
        self._last: dict[tuple[str | None, str, str], datetime] = {}

    def push(self, event: NormalizedEvent) -> tuple[NormalizedEvent, ...]:
        key = _key(event)
        timestamp = _time(event)
        if key in self._last and timestamp < self._last[key]:
            raise ValueError("Out-of-order event needs collector late-data handling")
        if key not in self._windows and len(self._windows) >= self.config.max_groups:
            oldest = min(self._last, key=self._last.get)
            del self._windows[oldest]
            del self._last[oldest]
        self._last[key] = timestamp
        history = self._windows.setdefault(key, deque())
        cutoff = timestamp - timedelta(seconds=self.config.horizon_seconds)
        while history and _time(history[0]) < cutoff:
            history.popleft()
        history.append(event)
        while len(history) > self.config.max_events:
            history.popleft()
        return tuple(history)


def offline_windows(events: list[NormalizedEvent],
                    config: SequenceConfig = SequenceConfig()
                    ) -> list[tuple[NormalizedEvent, ...]]:
    """Replay in event-time order; output aligns with sorted events."""
    ordered = sorted(events, key=lambda event: (_time(event), event.event_uid))
    builder = CausalSequenceBuilder(config)
    return [builder.push(event) for event in ordered]
