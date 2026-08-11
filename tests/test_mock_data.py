import hashlib
import importlib.util
import ipaddress
import json
import pathlib
import unittest
from datetime import datetime, timezone

MODULE_PATH = pathlib.Path(__file__).parents[1] / "scripts" / "generate_mock_data.py"
SPEC = importlib.util.spec_from_file_location("generate_mock_data", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class MockDataTests(unittest.TestCase):
    def test_scenarios_and_schema(self):
        rows, scenarios = MODULE.generate(
            20260811, datetime(2026, 8, 11, 3, 0, tzinfo=timezone.utc)
        )
        self.assertGreater(len(rows), 500)
        self.assertGreaterEqual(scenarios["port_scan"], 50)
        self.assertGreaterEqual(scenarios["high_volume_egress"], 10)
        self.assertGreaterEqual(scenarios["rdp_bruteforce"], 40)
        self.assertGreaterEqual(scenarios["periodic_beaconing"], 40)
        self.assertGreaterEqual(scenarios["icmp_sweep"], 40)
        self.assertEqual(
            {"NODATA", "SKIPDATA"}, {row["LogStatus"] for row in rows if row["LogStatus"] != "OK"}
        )
        required = {
            "TimeGenerated",
            "AccountId",
            "Action",
            "Bytes",
            "DstAddr",
            "DstPort",
            "FlowDirection",
            "LogStatus",
            "Packets",
            "Protocol",
            "SrcAddr",
            "SrcPort",
            "VpcId",
        }
        self.assertTrue(all(required.issubset(row) for row in rows))

    def test_scale_seven_produces_repository_sample_size(self):
        rows, scenarios = MODULE.generate(
            20260811,
            datetime(2026, 8, 11, 3, 0, tzinfo=timezone.utc),
            scale=7,
        )
        self.assertEqual(5110, len(rows))
        self.assertEqual(2240, scenarios["normal"])
        self.assertEqual(560, scenarios["port_scan"])

    def test_all_addresses_are_private_or_documentation_ranges(self):
        rows, _ = MODULE.generate(
            20260811,
            datetime(2026, 8, 11, 3, 0, tzinfo=timezone.utc),
            scale=2,
        )
        allowed = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
            ipaddress.ip_network("2001:db8::/32"),
        ]
        for row in rows:
            self.assertEqual("123456789012", row["AccountId"])
            for field in ("SrcAddr", "DstAddr", "PktSrcAddr", "PktDstAddr"):
                if row[field] == "-":
                    continue
                address = ipaddress.ip_address(row[field])
                self.assertTrue(
                    any(address in network for network in allowed),
                    f"{field} contains non-synthetic address {address}",
                )

    def test_repository_sample_matches_manifest(self):
        root = pathlib.Path(__file__).parents[1]
        sample_path = root / "samples" / "aws-vpc-flow-sample.json"
        manifest_path = root / "samples" / "manifest.json"
        sample_bytes = sample_path.read_bytes()
        rows = json.loads(sample_bytes)
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(5110, len(rows))
        self.assertEqual(len(rows), manifest["records"])
        self.assertEqual(len(sample_bytes), manifest["bytes"])
        self.assertEqual(hashlib.sha256(sample_bytes).hexdigest(), manifest["sha256"])
        self.assertEqual(5110, sum(manifest["scenarios"].values()))


if __name__ == "__main__":
    unittest.main()
