from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vtguard import SCHEMA_VERSION
from vtguard.data.schema import NormalizedEvent
from vtguard.features.event import event_tokens, vectorize
from vtguard.models.logistic import LogisticHead


class BaselineBundle:
    def __init__(self, content: dict):
        if content.get("schema_version") != SCHEMA_VERSION or content.get("bundle_kind") != "cpu_event_baseline":
            raise ValueError("Incompatible baseline bundle/schema")
        self.content = content
        self.vocabulary = {key: int(value) for key, value in content["vocabulary"].items()}
        self.heads = {key: LogisticHead.from_dict(value) for key, value in content["heads"].items()}
        if any(len(head.weights) != len(self.vocabulary) for head in self.heads.values()):
            raise ValueError("Bundle head/vocabulary size mismatch")

    @classmethod
    def load(cls, directory: Path) -> "BaselineBundle":
        directory = Path(directory)
        raw = (directory / "bundle.json").read_bytes()
        expected = (directory / "bundle.sha256").read_text(encoding="ascii").strip()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("Baseline bundle checksum mismatch")
        bundle = cls(json.loads(raw))
        for reference in bundle.content["reference_inference"]:
            actual = bundle.predict_tokens(reference["tokens"])
            if any(abs(actual[label] - value) > 1e-10 for label, value in reference["scores"].items()):
                raise ValueError("Baseline reference inference mismatch")
        return bundle

    def predict_tokens(self, tokens: list[str] | frozenset[str]) -> dict[str, float]:
        features = {self.vocabulary[token]: 1.0 for token in tokens if token in self.vocabulary}
        return {label: head.predict(features) for label, head in self.heads.items()}

    def predict(self, event: NormalizedEvent) -> dict[str, float]:
        if event.schema_version != SCHEMA_VERSION:
            raise ValueError("Input schema version mismatch")
        return self.predict_tokens(event_tokens(event))
