from __future__ import annotations


def binary_metrics(labels: list[int], scores: list[float], threshold: float) -> dict:
    if len(labels) != len(scores) or not labels:
        raise ValueError("Metric input mismatch or empty set")
    tp = sum(label == 1 and score >= threshold for label, score in zip(labels, scores))
    fp = sum(label == 0 and score >= threshold for label, score in zip(labels, scores))
    fn = sum(label == 1 and score < threshold for label, score in zip(labels, scores))
    tn = len(labels) - tp - fp - fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    positives = sum(labels)
    average_precision = None
    if 0 < positives < len(labels):
        # Integrate the stepwise precision-recall curve by unique score so ties
        # do not depend on input row order.
        groups: dict[float, list[int]] = {}
        for label, score in zip(labels, scores):
            groups.setdefault(score, []).append(label)
        found = 0
        selected = 0
        area = 0.0
        for score in sorted(groups, reverse=True):
            group = groups[score]
            new_positives = sum(group)
            selected += len(group)
            found += new_positives
            area += (new_positives / positives) * (found / selected)
        average_precision = area
    return {
        "n": len(labels), "positives": positives, "tp": tp, "fp": fp,
        "fn": fn, "tn": tn, "precision": precision, "recall": recall,
        "f1": f1, "average_precision": average_precision,
    }


def choose_threshold(labels: list[int], scores: list[float]) -> float:
    if not 0 < sum(labels) < len(labels):
        raise ValueError("Validation requires both classes to select threshold")
    candidates = sorted(set(scores) | {0.5, 1.0})
    return max(candidates, key=lambda value: (binary_metrics(labels, scores, value)["f1"], value))
