import json
from pathlib import Path
import unittest

from sippycup_torture.corpus import CorpusError, build_corpus, corpus_manifest, send_exact


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class CorpusTests(unittest.TestCase):
    def test_required_protocols_and_anomalies_are_covered(self):
        cases = build_corpus()
        self.assertEqual({"sip", "sdp", "rtp", "rfc4733", "rtcp"}, {c.protocol for c in cases})
        text = " ".join(c.title.lower() for c in cases)
        for term in (
            "length",
            "header",
            "cseq",
            "tag",
            "direction",
            "sequence",
            "timestamp",
            "ssrc",
            "payload",
            "event",
            "rtcp",
        ):
            self.assertIn(term, text)

    def test_manifest_is_byte_deterministic_and_self_verifying(self):
        first = corpus_manifest()
        second = corpus_manifest()
        self.assertEqual(first, second)
        self.assertEqual(
            (FIXTURES / "corpus-v1.sha256").read_text().strip(),
            first["identity"],
        )
        encoded = json.dumps(first, sort_keys=True, separators=(",", ":"))
        self.assertEqual(encoded, json.dumps(second, sort_keys=True, separators=(",", ":")))
        by_id = {case.id: case for case in build_corpus()}
        for record in first["cases"]:
            case = by_id[record["id"]]
            self.assertEqual(case.wire_bytes, bytes.fromhex(record["wireHex"]))
            self.assertEqual(case.sha256, record["sha256"])
            self.assertEqual(len(case.wire_bytes), record["trafficCost"]["bytes"])
            self.assertEqual(
                len(case.wire_bytes),
                sum(record["trafficCost"]["packetLengths"]),
            )

    def test_reference_sender_receives_each_exact_packet_once(self):
        for case in build_corpus():
            writes = []

            def sender(data):
                writes.append(data)
                return len(data)

            self.assertEqual(len(case.wire_bytes), send_exact(case, sender))
            lengths = case.packet_lengths or (len(case.wire_bytes),)
            expected = []
            offset = 0
            for length in lengths:
                expected.append(case.wire_bytes[offset : offset + length])
                offset += length
            self.assertEqual(expected, writes)

    def test_short_write_fails_without_retry(self):
        case = build_corpus()[0]
        writes = []

        def sender(data):
            writes.append(data)
            return len(data) - 1

        with self.assertRaisesRegex(CorpusError, "short write"):
            send_exact(case, sender)
        self.assertEqual(1, len(writes))

    def test_every_case_is_strictly_bounded_and_provenanced(self):
        for case in build_corpus():
            self.assertLessEqual(case.packet_count, 3)
            self.assertLessEqual(len(case.wire_bytes), 4096)
            self.assertTrue(case.provenance)
            self.assertIn(case.validity, {"valid", "valid-unusual", "invalid"})
            self.assertIn(case.risk, {"low", "medium"})


if __name__ == "__main__":
    unittest.main()
