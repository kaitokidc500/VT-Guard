"""Small deterministic decision-tree rule induction over deployable event tokens."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from vtguard.data.schema import TARGET_TTPS, NormalizedEvent
from vtguard.features.event import event_tokens
from vtguard.training.reviewed import ReviewedExample


HEADS = ("attack",) + TARGET_TTPS


@dataclass(frozen=True)
class Rule:
    rule_id: str
    head: str
    required: tuple[str, ...]
    forbidden: tuple[str, ...]
    train_support: int
    train_precision: float
    validation_matches: int
    validation_precision: float
    validation_recall: float

    def matches(self, event: NormalizedEvent) -> bool:
        return self.matches_tokens(event_tokens(event))

    def matches_tokens(self, tokens: frozenset[str] | set[str]) -> bool:
        return all(term in tokens for term in self.required) and not any(
            term in tokens for term in self.forbidden)

    def to_dict(self) -> dict:
        return asdict(self) | {"required": list(self.required), "forbidden": list(self.forbidden)}

    @classmethod
    def from_dict(cls, value: dict) -> "Rule":
        if value["head"] not in HEADS:
            raise ValueError("Rule head outside the detector contract")
        return cls(value["rule_id"], value["head"], tuple(value["required"]),
                   tuple(value["forbidden"]), int(value["train_support"]),
                   float(value["train_precision"]), int(value["validation_matches"]),
                   float(value["validation_precision"]), float(value["validation_recall"]))


def _positive(row: ReviewedExample, head: str) -> bool:
    return (row.event.labels.activity == "attack" if head == "attack"
            else head in row.event.labels.ttps)


def _gini(positive: int, total: int) -> float:
    if not total:
        return 0.0
    fraction = positive / total
    return 2 * fraction * (1 - fraction)


def induce_rules(train: list[ReviewedExample], validation: list[ReviewedExample], *,
                 max_depth: int = 2, min_support: int = 3,
                 min_train_precision: float = 0.8,
                 min_validation_matches: int = 2,
                 min_validation_precision: float = 0.7) -> list[Rule]:
    """Fit binary CART splits on train, retain positive leaves checked on validation."""
    if not train or not validation or max_depth < 1 or min_support < 1:
        raise ValueError("Rule induction needs train/validation and positive limits")
    vocabulary = sorted({token for row in train for token in event_tokens(row.event)})
    train_tokens = [event_tokens(row.event) for row in train]
    validation_tokens = [event_tokens(row.event) for row in validation]
    rules: list[Rule] = []
    for head in HEADS:
        train_y = [_positive(row, head) for row in train]
        validation_y = [_positive(row, head) for row in validation]
        if not any(train_y) or all(train_y):
            continue

        def visit(indices: list[int], depth: int, required: tuple[str, ...],
                  forbidden: tuple[str, ...]) -> None:
            positives = sum(train_y[index] for index in indices)
            best_token = None
            best_gain = 0.0
            base = _gini(positives, len(indices))
            if depth < max_depth and positives and positives < len(indices):
                for token in vocabulary:
                    if token in required or token in forbidden:
                        continue
                    yes = [index for index in indices if token in train_tokens[index]]
                    no = [index for index in indices if token not in train_tokens[index]]
                    if not yes or not no:
                        continue
                    impurity = (len(yes) * _gini(sum(train_y[index] for index in yes), len(yes))
                                + len(no) * _gini(sum(train_y[index] for index in no), len(no))) / len(indices)
                    gain = base - impurity
                    if gain > best_gain + 1e-12:
                        best_gain, best_token = gain, token
            if best_token:
                visit([index for index in indices if best_token in train_tokens[index]],
                      depth + 1, required + (best_token,), forbidden)
                visit([index for index in indices if best_token not in train_tokens[index]],
                      depth + 1, required, forbidden + (best_token,))
                return
            if (not required and not forbidden) or positives < min_support or positives / len(indices) < min_train_precision:
                return
            matched = [index for index, tokens in enumerate(validation_tokens)
                       if all(term in tokens for term in required)
                       and not any(term in tokens for term in forbidden)]
            if len(matched) < min_validation_matches:
                return
            true_positive = sum(validation_y[index] for index in matched)
            precision = true_positive / len(matched)
            if precision < min_validation_precision:
                return
            recall = true_positive / sum(validation_y) if any(validation_y) else 0.0
            rules.append(Rule(f"{head}-{len(rules) + 1:03d}", head, required, forbidden,
                              positives, positives / len(indices), len(matched),
                              precision, recall))

        visit(list(range(len(train))), 0, (), ())
    return rules


def match_vector(event: NormalizedEvent, rules: list[Rule]) -> dict[str, int]:
    return {rule.rule_id: int(rule.matches(event)) for rule in rules}
