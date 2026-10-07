"""Shared causal encoding for GRU training and CPU inference."""

from __future__ import annotations

import math

from vtguard.data.schema import NormalizedEvent
from vtguard.features.event import event_tokens
from vtguard.features.sequence import SequenceConfig, _key, _time


def encode_window(window: tuple[NormalizedEvent, ...], vocabulary: dict[str, int],
                  config: SequenceConfig) -> list[list[float]]:
    if not window or len(window) > config.max_events:
        raise ValueError("Invalid sequence window length")
    output: list[list[float]] = []
    previous = None
    first = None
    group = _key(window[-1])
    for event in window:
        if _key(event) != group:
            raise ValueError("Sequence window crosses run/host/identity")
        timestamp = _time(event)
        if previous is not None and timestamp < previous:
            raise ValueError("Sequence window is not ordered in UTC")
        if first is None:
            first = timestamp
        if (timestamp - first).total_seconds() > config.horizon_seconds:
            raise ValueError("Sequence window exceeds horizon")
        vector = [0.0] * (len(vocabulary) + 1)
        for token in event_tokens(event):
            if token in vocabulary:
                vector[vocabulary[token]] = 1.0
        delta = 0.0 if previous is None else (timestamp - previous).total_seconds()
        vector[-1] = math.log1p(min(delta, config.horizon_seconds)) / math.log1p(config.horizon_seconds)
        output.append(vector)
        previous = timestamp
    return output
