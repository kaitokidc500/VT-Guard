import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vtguard.data.schema import NormalizedEvent, Provenance
from vtguard.features.sequence import CausalSequenceBuilder, SequenceConfig, offline_windows
from vtguard.features.sequence_encoding import encode_window


def event(uid, second, run="r1", host="host-a", logon="x"):
    item = NormalizedEvent(uid, Provenance("fixture", "1", "raw", uid, run_id=run),
                           host=host, logon_id=logon,
                           event_time_utc=f"2026-10-07T00:{second // 60:02d}:{second % 60:02d}Z")
    return item


class SequenceTests(unittest.TestCase):
    def test_order_group_horizon_and_online_parity(self):
        a, b, c = event("a", 0), event("b", 2), event("c", 10)
        other = event("d", 3, run="r2")
        ordered = [a, b, other, c]
        offline = offline_windows([c, other, b, a], SequenceConfig(2, 5))
        online = CausalSequenceBuilder(SequenceConfig(2, 5))
        expected = [online.push(item) for item in ordered]
        self.assertEqual(offline, expected)
        self.assertEqual([item.event_uid for item in offline[-1]], ["c"])
        self.assertEqual([item.event_uid for item in offline[1]], ["a", "b"])
        with self.assertRaisesRegex(ValueError, "Out-of-order"):
            online.push(a)

    def test_identity_boundary(self):
        builder = CausalSequenceBuilder()
        self.assertEqual(len(builder.push(event("a", 0))), 1)
        self.assertEqual(len(builder.push(event("b", 1, logon="y"))), 1)
        live = event("live", 2)
        live.provenance.run_id = None
        self.assertEqual(len(builder.push(live)), 1)

    def test_bounded_online_groups(self):
        builder = CausalSequenceBuilder(SequenceConfig(4, 300, 1))
        builder.push(event("a", 0, run="r1"))
        builder.push(event("b", 1, run="r2"))
        self.assertEqual(len(builder._windows), 1)

    def test_two_event_encoding_uses_causal_delta(self):
        a, b = event("a", 0), event("b", 5)
        encoded = encode_window((a, b), {"event:1": 0}, SequenceConfig(4, 10))
        self.assertEqual(len(encoded), 2)
        self.assertEqual(encoded[0][-1], 0.0)
        self.assertGreater(encoded[1][-1], 0.0)
        with self.assertRaisesRegex(ValueError, "not ordered"):
            encode_window((b, a), {}, SequenceConfig())
        with self.assertRaisesRegex(ValueError, "crosses run"):
            encode_window((a, event("c", 6, run="r2")), {}, SequenceConfig())


if __name__ == "__main__":
    unittest.main()
