import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.data.adapters import read_events
from vtguard.fusion.scores import fuse_scores
from vtguard.inference.hybrid import HybridBundle
from vtguard.rule_induction.tree import HEADS
from vtguard.training.hybrid import train_hybrid
from vtguard.training.synthetic_fixture import make_fixture


class HybridTests(unittest.TestCase):
    def test_synthetic_training_bundle_and_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = make_fixture(root / "input")
            output = root / "hybrid"
            result = train_hybrid(manifest, output, allow_synthetic=True,
                                  min_rule_support=1, min_validation_matches=1)
            self.assertEqual(result["status"], "synthetic_smoke")
            bundle = HybridBundle.load(output)
            self.assertFalse(bundle.content["deployable"])
            event = next(read_events(root / "input/runs/fixture_test_attack_t1654.jsonl",
                                     "wazuh-jsonl", "fixture", "v1", synthetic=True))
            prediction = bundle.predict(event)
            self.assertEqual(set(prediction["hybrid_scores"]), set(HEADS))
            self.assertEqual(set(bundle.content["comparisons"]), set(HEADS))

    def test_fusion_rejects_missing_heads(self):
        with self.assertRaisesRegex(ValueError, "all six"):
            fuse_scores({"attack": 0.7}, {}, [], {"attack": 0.5})


if __name__ == "__main__":
    unittest.main()
