import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.training.readiness import inspect_reviewed
from vtguard.training.synthetic_fixture import make_fixture


class ReadinessTests(unittest.TestCase):
    def test_synthetic_corpus_is_not_real_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = inspect_reviewed(make_fixture(Path(tmp)), allow_synthetic=True)
            self.assertFalse(report["sequence_window_present"])
            self.assertEqual(report["by_split"]["train"]["multi_event_windows"], 0)
            self.assertIn("T1654", report["by_split"]["test"]["ttp_positives"])


if __name__ == "__main__":
    unittest.main()
