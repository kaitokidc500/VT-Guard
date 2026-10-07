"""Self-contained GRU attention + generated rules + fusion bundle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vtguard.data.schema import NormalizedEvent
from vtguard.features.event import event_tokens
from vtguard.fusion.scores import fuse_scores, rule_scores
from vtguard.inference.sequence import SequenceBundle
from vtguard.rule_induction.tree import HEADS, Rule, match_vector


class SequenceHybridBundle:
    def __init__(self, content: dict, sequence: SequenceBundle) -> None:
        if content.get("bundle_kind") != "gru_rule_hybrid":
            raise ValueError("Incompatible GRU hybrid bundle")
        if content.get("schema_version") != sequence.content["schema_version"]:
            raise ValueError("Hybrid and GRU schema mismatch")
        self.content = content
        self.sequence = sequence
        self.rules = [Rule.from_dict(value) for value in content["rules"]]
        self.weights = content["fusion"]["weights"]
        self.thresholds = content["fusion"]["thresholds"]
        if set(self.weights) != set(HEADS) or set(self.thresholds) != set(HEADS):
            raise ValueError("GRU hybrid head contract mismatch")

    @classmethod
    def load(cls, directory: Path) -> "SequenceHybridBundle":
        directory = Path(directory)
        raw = (directory / "hybrid.json").read_bytes()
        expected = (directory / "hybrid.sha256").read_text(encoding="ascii").strip()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("GRU hybrid checksum mismatch")
        sequence = SequenceBundle.load(directory / "sequence")
        bundle = cls(json.loads(raw), sequence)
        for reference in bundle.content["reference_inference"]:
            ai = sequence.predict_encoded(reference["encoded"])
            tokens = frozenset(reference["target_tokens"])
            matches = {rule.rule_id: int(rule.matches_tokens(tokens)) for rule in bundle.rules}
            actual = fuse_scores(ai, matches, bundle.rules, bundle.weights)
            if any(abs(actual[head] - value) > 1e-5
                   for head, value in reference["scores"].items()):
                raise ValueError("GRU hybrid reference inference mismatch")
        return bundle

    def predict(self, window: tuple[NormalizedEvent, ...]) -> dict:
        if not window:
            raise ValueError("Hybrid inference needs a nonempty window")
        ai = self.sequence.predict(window)
        matches = match_vector(window[-1], self.rules)
        fused = fuse_scores(ai, matches, self.rules, self.weights)
        return {"ai_scores": ai, "rule_scores": rule_scores(matches, self.rules),
                "matched_rules": [rule_id for rule_id, value in matches.items() if value],
                "hybrid_scores": fused,
                "decisions": {head: fused[head] >= self.thresholds[head] for head in HEADS},
                "detector_version": self.content["bundle_version"]}
