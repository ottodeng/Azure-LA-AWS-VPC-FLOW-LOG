import importlib.util
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
        self.assertEqual({"NODATA", "SKIPDATA"}, {
            row["LogStatus"] for row in rows if row["LogStatus"] != "OK"
        })
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


if __name__ == "__main__":
    unittest.main()
