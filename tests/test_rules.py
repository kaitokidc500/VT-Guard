import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.data.schema import Labels, NormalizedEvent, Provenance, TARGET_TTPS
from vtguard.rule_induction.tree import Rule, induce_rules, match_vector
from vtguard.training.reviewed import ReviewedExample


def row(uid, command, activity, split):
    event = NormalizedEvent(uid, Provenance("fixture", "1", "raw", uid, run_id=uid),
                            labels=Labels(activity, ["T1654"] if "wevtutil" in command else []),
                            command_line=command)
    return ReviewedExample(event, split)


class RuleTests(unittest.TestCase):
    def test_tree_rule_semantics_and_validation_gate(self):
        train = [row("a", "wevtutil qe Security", "attack", "train"),
                 row("b", "wevtutil qe System", "attack", "train"),
                 row("c", "ipconfig /all", "benign-admin", "train"),
                 row("d", "netstat -ano", "benign-admin", "train")]
        validation = [row("e", "wevtutil qe Security", "attack", "validation"),
                      row("f", "ipconfig /all", "benign-admin", "validation")]
        rules = induce_rules(train, validation, min_support=1,
                             min_validation_matches=1)
        self.assertTrue(rules)
        self.assertTrue(any(rule.head == "attack" and rule.matches(validation[0].event)
                            for rule in rules))
        self.assertTrue(all(not rule.matches(validation[1].event)
                            for rule in rules if rule.head == "attack"))
        restored = Rule.from_dict(rules[0].to_dict())
        self.assertEqual(restored, rules[0])
        self.assertEqual(match_vector(validation[0].event, [restored])[restored.rule_id], 1)
        rejected = induce_rules(train, validation, min_support=1,
                                min_validation_matches=2)
        self.assertEqual(rejected, [])


if __name__ == "__main__":
    unittest.main()
