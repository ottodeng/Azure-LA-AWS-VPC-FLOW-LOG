import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "scripts" / "query_aws_vpc_flow.py"
SPEC = importlib.util.spec_from_file_location("query_aws_vpc_flow", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class QueryGuardTests(unittest.TestCase):
    def test_accepts_allowed_table(self):
        query = "AWSVPCFlow | where TimeGenerated >= ago(1h) | take 10"
        self.assertEqual(MODULE.validate_query(query), query)

    def test_requires_allowed_table(self):
        with self.assertRaises(MODULE.QueryError):
            MODULE.validate_query("Heartbeat | take 10")

    def test_rejects_table_name_only_in_string(self):
        with self.assertRaises(MODULE.QueryError):
            MODULE.validate_query('Heartbeat | extend x = "AWSVPCFlow" | take 10')

    def test_blocks_cross_workspace(self):
        with self.assertRaises(MODULE.QueryError):
            MODULE.validate_query('workspace("other").AWSVPCFlow | where TimeGenerated >= ago(1h)')

    def test_blocks_external_data(self):
        with self.assertRaises(MODULE.QueryError):
            MODULE.validate_query(
                'AWSVPCFlow | join (externaldata(x:string)["https://example"]) on x'
            )

    def test_blocks_join_to_other_table(self):
        with self.assertRaises(MODULE.QueryError):
            MODULE.validate_query("AWSVPCFlow | join kind=inner (Heartbeat) on TenantId")

    def test_blocks_management_command(self):
        with self.assertRaises(MODULE.QueryError):
            MODULE.validate_query(".show tables\nAWSVPCFlow | take 1")

    def test_blocks_second_statement(self):
        with self.assertRaises(MODULE.QueryError):
            MODULE.validate_query("AWSVPCFlow | take 1; Heartbeat | take 1")


if __name__ == "__main__":
    unittest.main()
