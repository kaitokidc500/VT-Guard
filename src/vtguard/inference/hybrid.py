"""CPU reference inference for rule + logistic baseline bundles."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vtguard.data.schema import NormalizedEvent
from vtguard.features.event import event_tokens
from vtguard.fusion.scores import fuse_scores, rule_scores
from vtguard.inference.baseline import BaselineBundle
from vtguard.rule_induction.tree import HEADS, Rule, match_vector


class HybridBundle:
    def __init__(self, content: dict) -> None:
        if content.get("bundle_kind") != "cpu_hybrid_baseline":
            raise ValueError("Incompatible hybrid bundle")
        self.content = content
        self.baseline = BaselineBundle(content | {"bundle_kind": "cpu_event_baseline"})
        self.rules = [Rule.from_dict(value) for value in content["rules"]]
        self.weights = content["fusion"]["weights"]
        self.thresholds = content["fusion"]["thresholds"]
        if set(self.weights) != set(HEADS) or set(self.thresholds) != set(HEADS):
            raise ValueError("Hybrid head contract mismatch")

    @classmethod
    def load(cls, directory: Path) -> "HybridBundle":
        directory = Path(directory)
        raw = (directory / "bundle.json").read_bytes()
        expected = (directory / "bundle.sha256").read_text(encoding="ascii").strip()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("Hybrid bundle checksum mismatch")
        bundle = cls(json.loads(raw))
        for reference in bundle.content["hybrid_reference_inference"]:
            tokens = reference["tokens"]
            ai = bundle.baseline.predict_tokens(tokens)
            actual = fuse_scores(ai, reference["matches"], bundle.rules, bundle.weights)
            if any(abs(actual[head] - score) > 1e-10
                   for head, score in reference["scores"].items()):
                raise ValueError("Hybrid reference inference mismatch")
        return bundle

    def predict(self, event: NormalizedEvent) -> dict:
        ai = self.baseline.predict(event)
        matches = match_vector(event, self.rules)
        fused = fuse_scores(ai, matches, self.rules, self.weights)
        return {"ai_scores": ai, "rule_scores": rule_scores(matches, self.rules),
                "matched_rules": [rule_id for rule_id, value in matches.items() if value],
                "hybrid_scores": fused,
                "decisions": {head: fused[head] >= self.thresholds[head] for head in HEADS},
                "detector_version": self.content["bundle_version"]}
