"""Versioned CPU GRU bundle loader and reference inference."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import torch

from vtguard import SCHEMA_VERSION
from vtguard.data.schema import NormalizedEvent
from vtguard.features.sequence import SequenceConfig
from vtguard.features.sequence_encoding import encode_window
from vtguard.models.gru import GRUDetector


class SequenceBundle:
    def __init__(self, content: dict, model: GRUDetector) -> None:
        if content.get("bundle_kind") != "cpu_gru_sequence" or content.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("Incompatible GRU bundle/schema")
        self.content = content
        self.model = model.cpu().eval()
        self.vocabulary = {key: int(value) for key, value in content["vocabulary"].items()}
        self.config = SequenceConfig(**content["sequence_config"])

    @classmethod
    def load(cls, directory: Path) -> "SequenceBundle":
        directory = Path(directory)
        raw = (directory / "bundle.json").read_bytes()
        expected = (directory / "bundle.sha256").read_text(encoding="ascii").strip()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("GRU bundle checksum mismatch")
        content = json.loads(raw)
        weights = (directory / "weights.pt").read_bytes()
        if hashlib.sha256(weights).hexdigest() != content["weights_sha256"]:
            raise ValueError("GRU weights checksum mismatch")
        model = GRUDetector(len(content["vocabulary"]) + 1,
                            content["model_config"]["hidden_size"],
                            attention=content["model_config"]["attention"])
        model.load_state_dict(torch.load(directory / "weights.pt", map_location="cpu",
                                         weights_only=True))
        bundle = cls(content, model)
        for reference in content["reference_inference"]:
            actual = bundle.predict_encoded(reference["encoded"])
            if any(abs(actual[head] - score) > 1e-5
                   for head, score in reference["scores"].items()):
                raise ValueError("GRU reference inference mismatch")
        return bundle

    def predict_encoded(self, encoded: list[list[float]]) -> dict[str, float]:
        values = torch.tensor([encoded], dtype=torch.float32)
        lengths = torch.tensor([len(encoded)], dtype=torch.long)
        with torch.no_grad():
            scores = torch.sigmoid(self.model(values, lengths))[0].tolist()
        return dict(zip(self.content["labels"], scores))

    def predict(self, window: tuple[NormalizedEvent, ...]) -> dict[str, float]:
        if any(event.schema_version != SCHEMA_VERSION for event in window):
            raise ValueError("Input schema version mismatch")
        return self.predict_encoded(encode_window(window, self.vocabulary, self.config))
