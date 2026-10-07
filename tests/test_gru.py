import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

if importlib.util.find_spec("torch"):
    import torch
    from vtguard.inference.sequence import SequenceBundle
    from vtguard.models.gru import GRUDetector
    from vtguard.training.sequence import train_sequence
from vtguard.training.synthetic_fixture import make_fixture


@unittest.skipUnless(importlib.util.find_spec("torch"), "PyTorch CPU not installed")
class GRUTests(unittest.TestCase):
    def test_padding_mask_and_two_model_bundles(self):
        torch.set_num_threads(1)
        model = GRUDetector(4, 8, attention=True).eval()
        values = torch.randn(2, 3, 4)
        lengths = torch.tensor([1, 3])
        first = model(values, lengths).detach()
        values[0, 1:] = 1000.0
        second = model(values, lengths).detach()
        self.assertTrue(torch.allclose(first[0], second[0], atol=1e-6))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = make_fixture(root / "input", events_per_run=2)
            for kind in ("gru", "gru_attention"):
                output = root / kind
                result = train_sequence(manifest, output, model_kind=kind,
                                        hidden_size=8, epochs=2, batch_size=7,
                                        allow_synthetic=True, device="cpu")
                self.assertEqual(result["status"], "synthetic_smoke")
                bundle = SequenceBundle.load(output)
                self.assertFalse(bundle.content["deployable"])
                self.assertEqual(len(bundle.content["labels"]), 6)
                self.assertEqual(result["counts"]["train"]["multi_event_windows"], 7)
            resumed = train_sequence(manifest, root / "gru_attention",
                                     model_kind="gru_attention", hidden_size=8,
                                     epochs=3, batch_size=7, allow_synthetic=True,
                                     device="cpu", resume=True)
            self.assertEqual(resumed["status"], "synthetic_smoke")


if __name__ == "__main__":
    unittest.main()
