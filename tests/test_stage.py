import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.data.stage import stage_reviewed
from vtguard.training.reviewed import load_reviewed
from vtguard.training.synthetic_fixture import make_fixture


class StageTests(unittest.TestCase):
    def test_stage_keeps_manifest_valid_and_raw_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = make_fixture(root / "input")
            staged = stage_reviewed(original, root / "scratch", allow_synthetic=True)
            rows, report = load_reviewed(staged, allow_synthetic=True)
            self.assertEqual(len(rows), 21)
            self.assertTrue(report["synthetic"])
            self.assertEqual(len(list((root / "scratch/raw").iterdir())), 21)


if __name__ == "__main__":
    unittest.main()
