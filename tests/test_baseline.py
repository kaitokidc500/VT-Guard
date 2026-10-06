import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.data.adapters import read_events
from vtguard.data.normalize import normalize
from vtguard.data.schema import Provenance
from vtguard.features.event import event_tokens, fit_vocabulary, vectorize
from vtguard.inference.baseline import BaselineBundle
from vtguard.training.baseline import train_baseline
from vtguard.training.reviewed import load_reviewed
from vtguard.training.synthetic_fixture import make_fixture


class BaselineTests(unittest.TestCase):
    def test_reviewed_manifest_requires_real_labels_and_split_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = make_fixture(Path(tmp))
            with self.assertRaisesRegex(ValueError, "Synthetic data forbidden"):
                load_reviewed(manifest_path)
            examples, report = load_reviewed(manifest_path, allow_synthetic=True)
            self.assertEqual(len(examples), 21)
            self.assertEqual(report["run_counts"], {"train": 7, "validation": 7, "test": 7})
            benign_technique = [row for row in examples if row.event.provenance.run_id == "fixture_train_benign_ipconfig"][0]
            self.assertEqual(benign_technique.event.labels.activity, "benign-admin")
            self.assertIn("T1016", benign_technique.event.labels.ttps)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["runs"][7]["scenario_family"] = manifest["runs"][0]["scenario_family"]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "crosses splits"):
                load_reviewed(manifest_path, allow_synthetic=True)

    def test_only_train_vocabulary_and_online_offline_feature_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = make_fixture(Path(tmp))
            examples, _ = load_reviewed(manifest_path, allow_synthetic=True)
            train = [row.event for row in examples if row.split == "train"]
            vocabulary = fit_vocabulary(train)
            self.assertNotIn("term:arp", vocabulary)
            payload = json.loads((Path(tmp) / "runs/fixture_train_attack_t1016.jsonl").read_text(encoding="utf-8"))
            event_offline = next(row.event for row in examples
                                 if row.event.provenance.run_id == "fixture_train_attack_t1016")
            event_online = normalize(payload, Provenance("different-source", "v2", "online", "online#L1"), 1)
            self.assertEqual(event_tokens(event_online), event_tokens(event_offline))
            self.assertEqual(vectorize(event_online, vocabulary), vectorize(event_offline, vocabulary))
            self.assertFalse(any("fixture" in token for token in vocabulary))

    def test_bundle_round_trip_and_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = make_fixture(root / "input")
            output = root / "bundle"
            result = train_baseline(manifest, output, allow_synthetic=True, epochs=15)
            self.assertEqual(result["detector_status"], "synthetic_smoke")
            bundle = BaselineBundle.load(output)
            event = next(read_events(root / "input/runs/fixture_test_attack_t1654.jsonl",
                                     "wazuh-jsonl", "fixture", "v1", synthetic=True))
            self.assertEqual(set(bundle.predict(event)), set(bundle.content["labels"]))
            self.assertFalse(bundle.content["deployable"])
            with (output / "bundle.json").open("ab") as handle:
                handle.write(b" ")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                BaselineBundle.load(output)


if __name__ == "__main__":
    unittest.main()
