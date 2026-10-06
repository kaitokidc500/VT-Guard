import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.cli import run
from vtguard.data.adapters import ParseIssue, read_events
from vtguard.data.quality import assess
from vtguard.data.schema import model_input


class PipelineTests(unittest.TestCase):
    def test_wazuh_mapping_and_leakage_boundary(self):
        path = ROOT / "tests/fixtures/wazuh_synthetic.jsonl"
        events, report = assess(read_events(path, "wazuh-jsonl", "fixture", "v1", synthetic=True))
        self.assertEqual(report.parsed_events, 2)
        first, second = events
        self.assertEqual(first.event_time_utc, "2026-10-06T14:00:01.000000Z")
        self.assertEqual(first.system_time_utc, "2026-10-06T14:00:01.100000Z")
        self.assertEqual(first.ingest_time_utc, "2026-10-06T14:00:01.200000Z")
        self.assertEqual(first.labels.activity, "unknown")
        self.assertEqual(first.labels.ttps, [])
        self.assertEqual(second.fragment_total, 2)
        self.assertFalse(second.missing["script_block_text"])
        self.assertTrue(second.missing["process_guid"])
        features = model_input(first)
        self.assertNotIn("host", features)
        self.assertNotIn("labels", features)
        self.assertNotIn("source_dataset", features)
        self.assertNotIn("rule", features)
        self.assertEqual(report.events_without_run, 2)

    def test_splunk_jsonl_rejects_bad_record(self):
        path = ROOT / "tests/fixtures/splunk_synthetic.jsonl"
        items = list(read_events(path, "splunk-jsonl", "fixture", "v1", synthetic=True))
        self.assertIsInstance(items[1], ParseIssue)
        events, report = assess(items)
        self.assertEqual((report.parsed_events, report.rejected_records), (1, 1))
        self.assertEqual(events[0].image, "C:\\Windows\\System32\\netstat.exe")
        self.assertEqual(events[0].event_id, 1)

    def test_xml_mapping(self):
        path = ROOT / "tests/fixtures/event_synthetic.xml"
        events, report = assess(read_events(path, "windows-event-xml", "fixture", "v1", synthetic=True))
        self.assertEqual(report.parsed_events, 1)
        self.assertEqual(events[0].fragment_number, 1)
        self.assertEqual(events[0].script_block_text, "Get-WinEvent -ListLog *")
        self.assertEqual(events[0].event_time_utc, "2026-10-06T14:02:00.000000Z")

    def test_splunk_xml_lines_and_declared_utc(self):
        path = ROOT / "tests/fixtures/splunk_xml_synthetic.log"
        events, report = assess(read_events(path, "windows-event-xml", "fixture", "v1", synthetic=True))
        self.assertEqual((report.parsed_events, report.rejected_records), (2, 0))
        self.assertEqual(events[0].event_time_utc, "2025-04-24T09:54:30.650000Z")
        self.assertEqual(events[0].system_time_utc, "2025-04-24T09:54:30.657207Z")
        self.assertEqual(events[1].record_id, "51")

    def test_cli_smoke_output_is_untrained(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = {
                "schema_version": "1.0", "input_format": "wazuh-jsonl",
                "input_path": str(ROOT / "tests/fixtures/wazuh_synthetic.jsonl"),
                "source_dataset": "synthetic-parser-fixture", "source_version": "v1",
                "synthetic": True, "output_dir": str(Path(tmp) / "out"),
            }
            config_path = Path(tmp) / "smoke.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            report = run(config_path)
            self.assertEqual(report["parsed_events"], 2)
            self.assertEqual(report["detector_status"], "not_trained")
            normalized = (Path(tmp) / "out/normalized.jsonl").read_text(encoding="utf-8").splitlines()
            features = (Path(tmp) / "out/model_inputs.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(normalized), len(features))
            self.assertEqual(json.loads(normalized[0])["event_uid"], json.loads(features[0])["event_uid"])


if __name__ == "__main__":
    unittest.main()
