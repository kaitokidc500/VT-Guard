import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.data.review_sheet import REVIEW_COLUMNS, compile_reviewed_manifest, prepare_review_sheets
from vtguard.training.reviewed import load_reviewed
from vtguard.training.synthetic_fixture import make_fixture


class ReviewSheetTests(unittest.TestCase):
    def test_manual_sheet_round_trip_and_row_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            example_manifest = make_fixture(root / "raw")
            source = json.loads(example_manifest.read_text(encoding="utf-8"))
            plan = prepare_review_sheets(example_manifest, root / "review")
            first_sheet = root / "review/review_fixture_train_benign_notepad.csv"
            with first_sheet.open("r", encoding="utf-8-sig", newline="") as handle:
                self.assertEqual(next(csv.DictReader(handle))["activity"], "")
            for run in source["runs"]:
                sheet = root / "review" / f"review_{run['run_id']}.csv"
                with sheet.open("r", encoding="utf-8-sig", newline="") as handle:
                    rows = list(csv.DictReader(handle))
                annotation = run["annotations"][0]
                rows[0].update({
                    "activity": annotation["activity"],
                    "ttps": "|".join(annotation["ttps"]),
                    "reviewed_techniques": "|".join(annotation["reviewed_techniques"]),
                    "confidence": str(annotation["confidence"]),
                    "reviewed_by": annotation["reviewed_by"],
                    "evidence": annotation["evidence"][0],
                })
                with sheet.open("w", encoding="utf-8-sig", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=REVIEW_COLUMNS)
                    writer.writeheader()
                    writer.writerows(rows)
            compiled = compile_reviewed_manifest(plan, root / "compiled/reviewed_manifest.json",
                                                 allow_synthetic=True)
            examples, _ = load_reviewed(compiled, allow_synthetic=True)
            self.assertEqual(len(examples), 21)
            with first_sheet.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            original_uid = rows[0]["event_uid"]
            rows[0]["event_uid"] = "tampered"
            with first_sheet.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=REVIEW_COLUMNS)
                writer.writeheader()
                writer.writerows(rows)
            with self.assertRaisesRegex(ValueError, "row mismatch"):
                compile_reviewed_manifest(plan, root / "compiled/reviewed_manifest.json",
                                          allow_synthetic=True)
            rows[0]["event_uid"] = original_uid
            with first_sheet.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=REVIEW_COLUMNS)
                writer.writeheader()
            with self.assertRaisesRegex(ValueError, "missing raw event rows"):
                compile_reviewed_manifest(plan, root / "compiled/reviewed_manifest.json",
                                          allow_synthetic=True)


if __name__ == "__main__":
    unittest.main()
