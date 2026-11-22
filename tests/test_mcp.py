import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    ClientSession = None

from hpt_siem.mcp_server import arguments
from hpt_siem.discover import alert_expression, hit_matches_source, responses, rison_string
from hpt_siem.search import search_options


class ToolArgumentsTests(unittest.TestCase):
    def test_inline_dsl_uses_shared_query_validation(self):
        body = {"query": {"term": {"event.kind": "alert"}}}
        args = arguments("query", {"siem": "demo", "index": "logs-*", "last_minutes": 5}, body)
        _, clause, language = search_options(args)
        self.assertEqual(clause, body["query"])
        self.assertEqual(language, "dsl")

    def test_query_text_remains_one_argument(self):
        expression = '-field: "value" | test'
        args = arguments("query", {"siem": "demo", "index": "logs-*", "last_minutes": 5,
                                  "expression": expression, "fields": ["@timestamp", "event.kind"]})
        self.assertEqual(args.expression, expression)
        self.assertEqual(args.fields, ["@timestamp", "event.kind"])

    def test_discover_state_and_alert_id_encode_literals(self):
        self.assertEqual(rison_string("name:'a!b'"), "'name:!'a!!b!''")
        self.assertEqual(alert_expression([
            {"terms": {"kibana.alert.severity": ["high", "critical"]}},
            {"ids": {"values": ["example-id"]}},
        ]), 'kibana.alert.severity: ("high" OR "critical") AND _id: "example-id"')

    def test_discover_collects_async_followups_arriving_during_processing(self):
        first, followup = Mock(), Mock()
        queued = [(first, True)]

        def read(response):
            if response is first:
                queued.append((followup, False))
                return [{"stage": "pending"}]
            return [{"stage": "done"}]

        with patch("hpt_siem.discover.response_json", side_effect=read):
            messages = responses(Mock(), queued, 1)
            self.assertEqual(next(messages), {"stage": "pending"})
            self.assertEqual(next(messages), {"stage": "done"})

    def test_discover_checks_source_with_data_stream_and_alert_backing_indices(self):
        self.assertTrue(hit_matches_source({"_index": ".ds-logs-firewall-2026.01.01-000001"}, "logs-firewall"))
        self.assertTrue(hit_matches_source({"_index": ".internal.alerts-security.alerts-demo-000002"},
                                           ".alerts-security.alerts-demo"))
        self.assertFalse(hit_matches_source({"_index": "logs-other-default"}, "logs-firewall"))
        self.assertFalse(hit_matches_source({"_index": ".ds-logs-firewall-test-2026.01.01-000001"},
                                            "logs-*,-logs-*-test"))

@unittest.skipIf(ClientSession is None, "The MCP extra is optional.")
class MCPProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_tool_discovery_and_typed_calls_over_stdio(self):
        with tempfile.TemporaryDirectory() as state:
            params = StdioServerParameters(command=sys.executable, args=["-m", "hpt_siem.mcp_server"],
                                           env={**os.environ, "HPT_SIEM_DATA_DIR": state})
            async with stdio_client(params) as (reader, writer), ClientSession(reader, writer) as session:
                await session.initialize()
                tools = {item.name: item for item in (await session.list_tools()).tools}
                self.assertEqual(set(tools), {
                    "HPT_query", "HPT_check_alerts", "HPT_check_query", "HPT_list_siems",
                    "HPT_status", "HPT_health", "HPT_list_rules", "HPT_get_rule",
                    "HPT_list_spaces", "HPT_list_data_views", "HPT_list_data_streams",
                    "HPT_register_siem", "HPT_login", "HPT_logout",
                })
                self.assertIn("query", tools["HPT_query"].inputSchema["properties"])
                self.assertTrue(tools["HPT_query"].annotations.readOnlyHint)
                props = tools["HPT_check_alerts"].inputSchema["properties"]
                self.assertEqual(props["api"]["enum"], ["auto", "detection-engine", "console"])
                self.assertEqual(props["backend"]["enum"], ["auto", "api", "discover"])
                result = await session.call_tool("HPT_register_siem", {"url": "https://siem.example.org/s/soc/", "siem": "demo"})
                self.assertTrue(result.structuredContent["ok"])
                self.assertEqual(result.structuredContent["data"]["space"], "soc")
                result = await session.call_tool("HPT_list_siems", {})
                self.assertEqual(result.structuredContent["data"]["siems"][0]["id"], "demo")
                result = await session.call_tool("HPT_query", {"siem": "demo", "index": "logs-*",
                                                            "query": {"query": {"match_all": {}}}})
                self.assertEqual(result.structuredContent["code"], "login_required")
                result = await session.call_tool("HPT_check_alerts", {"siem": "demo", "alert_id": "bad/id"})
                self.assertEqual(result.structuredContent["code"], "invalid_input")
                for name, params in (("HPT_list_rules", {}), ("HPT_get_rule", {"rule_id": "example"})):
                    result = await session.call_tool(name, {"siem": "demo", **params})
                    self.assertEqual(result.structuredContent["code"], "login_required")
