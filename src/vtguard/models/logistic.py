from __future__ import annotations

import math
import random
from dataclasses import dataclass


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1 / (1 + z)
    z = math.exp(value)
    return z / (1 + z)


@dataclass
class LogisticHead:
    weights: list[float]
    bias: float

    def predict(self, features: dict[int, float]) -> float:
        return _sigmoid(self.bias + sum(self.weights[index] * value
                                        for index, value in features.items()))

    def to_dict(self) -> dict:
        return {"weights": self.weights, "bias": self.bias}

    @classmethod
    def from_dict(cls, data: dict) -> "LogisticHead":
        return cls([float(value) for value in data["weights"]], float(data["bias"]))


def train_logistic(features: list[dict[int, float]], targets: list[int],
                   width: int, *, epochs: int = 80, learning_rate: float = 0.08,
                   l2: float = 0.0005, seed: int = 17) -> LogisticHead:
    if len(features) != len(targets) or not features:
        raise ValueError("Feature/target count mismatch or empty training data")
    positive = sum(targets)
    negative = len(targets) - positive
    if not positive or not negative:
        raise ValueError("A logistic head needs both positive and negative train examples")
    head = LogisticHead([0.0] * width, 0.0)
    order = list(range(len(targets)))
    rng = random.Random(seed)
    positive_weight = len(targets) / (2 * positive)
    negative_weight = len(targets) / (2 * negative)
    for _ in range(epochs):
        rng.shuffle(order)
        for row in order:
            probability = head.predict(features[row])
            class_weight = positive_weight if targets[row] else negative_weight
            error = (probability - targets[row]) * class_weight
            head.bias -= learning_rate * error
            for index, value in features[row].items():
                head.weights[index] -= learning_rate * (error * value + l2 * head.weights[index])
    return head
