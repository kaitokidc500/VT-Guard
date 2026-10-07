import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

if importlib.util.find_spec("torch"):
    import torch
    from vtguard.inference.sequence_hybrid import SequenceHybridBundle
    from vtguard.training.sequence import train_sequence
    from vtguard.training.sequence_hybrid import fit_sequence_hybrid
from vtguard.data.adapters import read_events
from vtguard.training.synthetic_fixture import make_fixture


@unittest.skipUnless(importlib.util.find_spec("torch"), "PyTorch CPU not installed")
class SequenceHybridTests(unittest.TestCase):
    def test_combined_bundle_round_trip(self):
        torch.set_num_threads(1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = make_fixture(root / "input")
            train_sequence(manifest, root / "sequence", model_kind="gru_attention",
                           hidden_size=8, epochs=2, batch_size=7,
                           allow_synthetic=True, device="cpu")
            result = fit_sequence_hybrid(manifest, root / "sequence", root / "combined",
                                         allow_synthetic=True, min_rule_support=1,
                                         min_validation_matches=1)
            self.assertEqual(result["status"], "synthetic_smoke")
            bundle = SequenceHybridBundle.load(root / "combined")
            event = next(read_events(root / "input/runs/fixture_test_attack_t1654.jsonl",
                                     "wazuh-jsonl", "fixture", "v1", synthetic=True))
            prediction = bundle.predict((event,))
            self.assertEqual(len(prediction["hybrid_scores"]), 6)
            self.assertFalse(bundle.content["deployable"])
            with (root / "combined/hybrid.json").open("ab") as handle:
                handle.write(b" ")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                SequenceHybridBundle.load(root / "combined")


if __name__ == "__main__":
    unittest.main()
