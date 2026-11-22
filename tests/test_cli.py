import contextlib
import io
import json
import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cryptography.fernet import Fernet

from hpt_siem.cli import main
from hpt_siem.http import Client, protected_routes
from hpt_siem.model import Error, parse_target
from hpt_siem.store import Store


SECRET = "fixture-credential-value"
ROTATED = "fixture-credential-refresh"
VIEWS = "/gateway/s/triage/api/data_views"
SEARCH = "/gateway/s/triage/api/console/proxy"
BUILDER = "/gateway/s/triage/api/agent_builder/tools/_execute"
FLEET = "/gateway/s/triage/api/fleet/data_streams"
SIGNALS = "/gateway/s/triage/api/detection_engine/signals/search"
RULES = "/gateway/s/triage/api/detection_engine/rules"
RULE_UUID = "70bd0476-571a-4f1d-b458-9fd58569e15b"
RULE_STABLE_ID = "fixture&team=triage"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, payload, headers=None):
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        split = urlsplit(self.path)
        path = split.path
        if path == "/gateway/api/status":
            unavailable = self.server.mode == "health_unavailable"
            self.reply(503 if unavailable else 200, {"version": {"number": "8.14.3"},
                       "status": {"overall": {"level": "unavailable" if unavailable else "available"}}})
            return
        if path == "/gateway/api/security/me":
            self.reply(404, {})
            return
        if path == VIEWS and self.server.mode == "public":
            self.reply(200, {"data_view": []})
            return
        cookie = self.headers.get("Cookie")
        if self.server.mode == "rotating":
            self.server.observed.append(cookie)
            if cookie == "sid=" + SECRET:
                time.sleep(0.1)
                self.reply(200, {"data_view": []},
                           {"Set-Cookie": "sid=" + ROTATED + "; Path=/gateway; HttpOnly"})
                return
            self.reply(200 if cookie == "sid=" + ROTATED else 401, {"data_view": []})
            return
        if cookie != "sid=" + SECRET or self.server.mode == "expired":
            self.reply(401, {"message": SECRET})
        elif self.server.mode == "denied":
            self.reply(403, {"message": SECRET})
        elif path == VIEWS or path == VIEWS + "/data_view/example-id":
            view = {"id": "example-id", "name": "Friendly logs", "title": "raw-events-*"}
            if path == VIEWS:
                self.reply(200, {"data_view": [view]})
            else:
                self.reply(200, {"data_view": {**view, "timeFieldName": "event.created"}})
        elif path == "/gateway/api/spaces/space":
            self.reply(200, [{"id": "triage", "name": "Triage", "imageUrl": SECRET}])
        elif path == FLEET:
            self.reply(200, {"data_streams": [{"index": "logs-fleet-example", "ignored": SECRET}]})
        elif path in {RULES, RULES + "/_find"}:
            rule = {"id": RULE_UUID, "rule_id": RULE_STABLE_ID, "name": "Example rule",
                    "enabled": True, "severity": "medium", "query": "event.kind:alert",
                    "description": SECRET, "actions": [{"credentials": SECRET}]}
            params = parse_qs(split.query)
            self.server.observed.append((path, params, None))
            self.reply(200, {"data": [rule], "total": 2} if path.endswith("/_find") else rule)
        else:
            self.reply(404, {})

    def do_POST(self):
        parts = urlsplit(self.path)
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        body = json.loads(raw) if raw else None
        params = parse_qs(parts.query)
        self.server.observed.append((parts.path, params, body))
        if parts.path == SIGNALS:
            mode = self.server.mode
            if mode == "signals":
                if {"track_total_hits", "timeout"} & body.keys():
                    self.reply(400, {"message": "Bad request"})
                    return
                self.reply(200, {"_shards": {"total": 1, "successful": 1, "failed": 0}, "hits": {
                    "total": {"value": 1, "relation": "eq"}, "hits": [{
                        "_id": "alert-one", "_index": ".internal.alerts-security.alerts-triage-000001",
                        "fields": {"kibana.alert.rule.name": ["Example alert"], "unrequested": [SECRET]},
                    }]}})
            elif mode == "signals_denied":
                self.reply(403, {"message": SECRET})
            elif mode == "signals_invalid":
                self.reply(400, {"message": "Bad request"})
            elif mode == "signals_unavailable":
                self.reply(400, {"message": "This API is not available in the current configuration."})
            elif mode == "signals_old_offset":
                self.reply(400, {"message": '[request body]: invalid keys "from"'})
            else:
                self.reply(404, {})
            return
        if parts.path == BUILDER:
            if self.server.mode != "builder":
                self.reply(403, {"message": SECRET})
            else:
                table = self.esql_response(body["tool_params"]["query"])
                self.reply(200, {"results": [{"type": "query", "data": {"query": SECRET}},
                                             {"type": "esql_results", "data": table}]})
            return
        if parts.path != SEARCH:
            self.reply(404, {})
            return
        if self.server.mode in {"builder", "no_alert_rest"}:
            self.reply(400, {"message": SECRET})
            return
        path = params["path"][0]
        if path == "_data_stream":
            self.reply(200, {"data_streams": [{"name": "logs-fixture", "ignored": SECRET}]})
            return
        if self.server.mode == "upstream_denied" and "FROM" in json.dumps(body):
            self.reply(200, {"error": {"reason": SECRET}}, {"x-console-proxy-status-code": "403"})
            return
        if path == "_query?format=json":
            self.reply(200, self.esql_response(body["query"]))
            return
        if self.server.mode == "upstream_denied":
            self.reply(200, {"error": {"reason": SECRET}}, {"x-console-proxy-status-code": "403"})
            return
        if self.server.mode == "old_engine" and '"kql"' in json.dumps(body):
            self.reply(200, {"error": {"root_cause": [{"reason": "unknown query [kql]"}]}},
                       {"x-console-proxy-status-code": "400"})
            return
        if self.server.mode == "redirect":
            self.reply(302, {}, {"Location": "http://127.0.0.1:1/other"})
            return
        if self.server.mode == "invalid_json":
            self.reply(200, b'{"x":1e999}')
            return
        details = {"shard": 1, "index": "raw-events-1",
                   "reason": {"type": "query_shard_exception", "reason": SECRET}}
        if self.server.mode == "all_failed":
            self.reply(503, {"error": {"failed_shards": [details]}})
            return
        partial = self.server.mode == "partial"
        no_shards = self.server.mode == "no_shards"
        self.reply(200, {
            "timed_out": partial,
            "_shards": {"total": 0 if no_shards else 2, "successful": 0 if no_shards else 2 - partial,
                        "failed": int(partial), "failures": [details] if partial else []},
            "hits": {"total": {"value": 0 if no_shards else 500,
                               "relation": "gte" if partial else "eq"},
                     "hits": [] if no_shards else [{
                         "_index": "raw-events-1", "_id": "one",
                         "_source": {"unrequested": SECRET, "event": {"created": "sample", "extra": "hidden"}},
                         "fields": {"event.created": [SECRET], "private.note": ["unexpected"]},
                     }]},
        })

    @staticmethod
    def esql_response(query):
        if "hpt_probe" in query:
            return {"columns": [{"name": "hpt_probe"}], "values": [[1 if query.startswith("ROW") else 0]]}
        return {"columns": [{"name": "events"}, {"name": "unsolicited"}],
                "values": [[12, SECRET]], "is_partial": True}


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/gateway/s/triage/app/home"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {"HPT_SIEM_DATA_DIR": self.tmp.name})
        env.start()
        self.addCleanup(env.stop)
        cipher = patch.object(Store, "cipher", return_value=Fernet(Fernet.generate_key()))
        cipher.start()
        self.addCleanup(cipher.stop)
        self.server.mode = "normal"
        self.server.observed = []
        self.store = Store()
        self.target = self.store.register(parse_target(self.url, "fixture", allow_http=True))
        self.session = {"space": "triage", "probes": ["views"], "cookies": [{
            "domain": "127.0.0.1", "host_only": True, "path": "/gateway", "expires": None,
            "name": "sid", "value": SECRET, "secure": False,
        }]}
        self.store.save(self.target, 0, self.session, replace=True)

    def cli(self, *args):
        stdout = io.StringIO()
        with patch("sys.argv", ["hpt-siem", *args]), contextlib.redirect_stdout(stdout):
            status = main()
        self.assertNotIn(SECRET, stdout.getvalue())
        self.assertNotIn(ROTATED, stdout.getvalue())
        output = json.loads(stdout.getvalue())
        self.assertEqual(bool(status), not output["ok"])
        return output

    def query(self, *args):
        return self.cli("query", "--siem", "fixture", "--data-view-id", "example-id",
                        "--last-minutes", "5", "--limit", "1", *args)

    def test_parse_and_registration(self):
        self.assertEqual(self.target.space, "triage")
        self.assertEqual(self.target.base_path, "/gateway")
        self.assertEqual(self.target.origin, f"http://127.0.0.1:{self.server.server_port}")
        for bad in ("/gateway/%2e%2e/app/home", "/gateway//app/home", "/gateway/../app/home"):
            with self.assertRaises(Error):
                parse_target(self.target.origin + bad)
        basic = self.store.register(parse_target(self.url, "basic", context="another"))
        self.assertFalse(basic.allow_http)
        upgraded = self.store.register(parse_target(self.url, "basic", context="another", allow_http=True))
        self.assertTrue(upgraded.allow_http)
        self.assertEqual(len(self.cli("list-siems")["data"]["siems"]), 2)

    def test_metadata_and_protected_status(self):
        status = self.cli("status", "--siem", "fixture")["data"]
        self.assertEqual((status["probe"], status["kibanaVersion"]), ("views", "8.14.3"))
        row = self.cli("list-data-views", "--siem", "fixture")["data"]["dataViews"][0]
        self.assertEqual((row["id"], row["name"], row["indexPattern"]), ("example-id", "Friendly logs", "raw-events-*"))
        spaces = self.cli("list-spaces", "--siem", "fixture")["data"]["spaces"]
        self.assertEqual(spaces, [{"id": "triage", "name": "Triage"}])

    def test_public_version_and_views_do_not_verify_login(self):
        self.server.mode = "public"
        with Client(self.target) as client, self.assertRaisesRegex(Error, "anonymous-access denial"):
            protected_routes(client, "triage")

    def test_query_applies_time_projection_and_retains_partial(self):
        self.server.mode = "partial"
        output = self.query("--fields", "event.created", "--source", "event.created",
                            "--coverage-note", "subset")
        self.assertEqual(output["code"], "partial_results")
        data = output["data"]
        self.assertTrue(data["coverageRestricted"])
        self.assertTrue(data["timedOut"])
        self.assertEqual(data["total"]["relation"], "gte")
        self.assertEqual(data["shards"]["failed"], 1)
        self.assertEqual(data["shardFailures"][0]["type"], "query_shard_exception")
        self.assertEqual(data["hits"][0]["fields"], {"event.created": ["[redacted]"]})
        self.assertEqual(data["hits"][0]["_source"], {"event": {"created": "sample"}})
        path, params, body = self.server.observed[-1]
        self.assertEqual(path, SEARCH)
        self.assertEqual(params["path"], ["raw-events-*/_search?allow_partial_search_results=true"])
        self.assertIn("event.created", body["query"]["bool"]["filter"][0]["range"])
        self.assertEqual(body["size"], 1)

    def test_query_without_fields_discards_unrequested_data(self):
        raw = self.query()["data"]["hits"][0]
        self.assertEqual(set(raw), {"_id", "_index"})

    def test_url_query_reuses_registered_session_without_browser(self):
        with patch("hpt_siem.cli.browser_login") as login:
            result = self.cli("query", "--url", self.url, "--interactive", "--index", "raw-events-*",
                              "--last-minutes", "5")
        self.assertEqual(result["data"]["siem"], "fixture")
        login.assert_not_called()

    def test_query_language_defaults_and_override(self):
        result = self.query("--expression", "event.kind:alert")
        self.assertEqual(result["data"]["language"], "kql")
        body = self.server.observed[-1][2]
        self.assertIn({"kql": {"query": "event.kind:alert"}}, body["query"]["bool"]["filter"])
        result = self.query("--intent", "stats", "--language", "lucene", "--expression", "event.kind:alert")
        self.assertEqual(result["data"]["language"], "lucene")
        body = self.server.observed[-1][2]
        self.assertIn("query_string", body["query"]["bool"]["filter"][-1])
        path = Path(self.tmp.name) / "match.json"
        path.write_text('{"query":{"match_all":{}}}', encoding="utf-8")
        self.assertEqual(self.query("--dsl-file", str(path))["data"]["language"], "dsl")

    def test_esql_stats_preserves_time_projection_limit_and_partial(self):
        result = self.query("--intent", "stats", "--expression",
                            'WHERE agent.name == "a|b" | STATS events=COUNT(*)', "--fields", "events")
        self.assertEqual(result["code"], "partial_results")
        self.assertEqual(result["data"]["rows"], [[12]])
        self.assertEqual(result["data"]["columns"], ["events"])
        path, params, body = self.server.observed[-1]
        self.assertEqual(path, SEARCH)
        self.assertEqual(params["path"], ["_query?format=json"])
        self.assertTrue(body["query"].startswith("FROM raw-events-* METADATA _index | WHERE `event.created` >= "))
        self.assertIn('WHERE agent.name == "a|b"', body["query"])
        self.assertTrue(body["query"].endswith("| KEEP `events` | LIMIT 1"))

    def test_reject_esql_commands_outside_bounded_pipeline(self):
        for expression in ("FROM test", "WHERE true | LOOKUP JOIN other ON user", "STATS x=COUNT(*); ROW x=1",
                           'WHERE name == """raw"""', "WHERE true /* comment */", "WHERE true | LIMIT 2000"):
            self.assertEqual(self.query("--language", "esql", "--expression", expression,
                                        "--fields", "events")["code"], "invalid_input")
        self.assertEqual(self.server.observed, [])

    def test_capabilities_distinguish_missing_kql_from_missing_access(self):
        self.server.mode = "old_engine"
        data = self.cli("check-query", "--siem", "fixture", "--index", "raw-events-*")["data"]
        self.assertEqual(data["verifiedChoices"], {"filter": "dsl", "stats": "esql"})
        self.assertEqual(data["languages"]["kql"]["checks"]["console"]["state"], "unsupported")
        self.assertEqual(data["languages"]["esql"]["checks"]["agent-builder"]["indexRead"], "unverified")
        probes = [item[2] for item in self.server.observed if "_search?" in str(item[1])]
        self.assertTrue(probes)
        self.assertTrue(all(p["size"] == 0 and p["_source"] is False for p in probes))
        self.server.mode = "upstream_denied"
        data = self.cli("check-query", "--siem", "fixture", "--index", "raw-events-*")["data"]
        self.assertEqual(data["languages"]["dsl"]["checks"]["console"]["indexRead"], "denied")
        self.assertEqual(data["languages"]["esql"]["checks"]["console"]["engineProbe"], "verified")
        self.assertEqual(data["languages"]["esql"]["checks"]["console"]["indexRead"], "denied")

    def test_capabilities_without_source_only_probe_esql_engine(self):
        result = self.cli("check-query", "--siem", "fixture")["data"]
        self.assertEqual(result["scope"], "engine_only")
        self.assertEqual(result["verifiedChoices"], {"filter": None, "stats": None})
        self.assertEqual(result["languages"]["esql"]["checks"]["console"]["indexRead"], "not_checked")
        self.assertEqual(len(self.server.observed), 2)
        self.assertEqual(self.server.observed[0][2]["query"], "ROW hpt_probe = 1")

    def test_esql_uses_fixed_builder_tool_on_kibana_rejection_only(self):
        self.server.mode = "builder"
        result = self.query("--intent", "stats")
        self.assertEqual(result["data"]["adapter"], "agent-builder")
        path, _, body = self.server.observed[-1]
        self.assertEqual(path, BUILDER)
        self.assertEqual(body["tool_id"], "platform.core.execute_esql")
        self.assertEqual(set(body["tool_params"]), {"query"})
        self.server.mode = "upstream_denied"
        self.server.observed = []
        result = self.query("--intent", "stats")
        self.assertEqual(result["code"], "permission_denied")
        self.assertEqual([entry[0] for entry in self.server.observed], [SEARCH])

    def test_auto_query_falls_back_only_for_compatible_inputs(self):
        self.server.mode = "builder"
        with patch("hpt_siem.discover.discover_query", return_value={"adapter": "discover"}) as discover:
            result = self.query("--backend", "auto", "--expression", "event.kind:alert")
            self.assertEqual(result["data"]["adapter"], "discover")
            self.assertEqual(result["data"]["apiFallback"], "request_rejected")
            discover.assert_called_once()
            discover.reset_mock()
            for flags in (("--backend", "api"), ("--backend", "auto", "--language", "dsl"),
                          ("--backend", "auto", "--api", "console")):
                self.assertEqual(self.query(*flags)["code"], "request_rejected")
            self.assertEqual(self.query("--backend", "discover", "--language", "dsl")["code"], "invalid_input")
            self.server.mode = "upstream_denied"
            self.assertEqual(self.query("--backend", "auto")["details"]["layer"], "elasticsearch")
            discover.assert_not_called()

    def test_alerts_use_discover_only_after_rest_routes_unavailable(self):
        args = ("list-alerts", "--siem", "fixture", "--last-minutes", "5", "--backend", "auto")
        with patch("hpt_siem.discover.discover_query", return_value={"adapter": "discover"}) as discover:
            self.server.mode = "signals_denied"
            self.assertEqual(self.cli(*args)["code"], "permission_denied")
            discover.assert_not_called()
            self.server.mode = "signals"
            self.assertEqual(self.cli(*args)["data"]["adapter"], "detection-engine")
            discover.assert_not_called()
            self.server.mode = "no_alert_rest"
            self.assertEqual(self.cli(*args)["data"]["adapter"], "discover")
            discover.assert_called_once()

    def test_data_stream_inventory_reports_source_coverage(self):
        args = ("list-data-streams", "--siem", "fixture")
        result = self.cli(*args)["data"]
        self.assertEqual(result["dataStreams"], ["logs-fixture"])
        self.assertEqual(self.server.observed[-1][1]["method"], ["GET"])
        self.server.mode = "builder"
        result = self.cli(*args)["data"]
        self.assertEqual(result["coverage"], "fleet_managed")
        self.assertEqual(result["dataStreams"], ["logs-fleet-example"])

    def test_alert_request_uses_security_alias_and_filters(self):
        output = self.cli("list-alerts", "--siem", "fixture", "--last-minutes", "5",
                          "--limit", "1", "--severity", "high", "--workflow-status", "open")
        self.assertTrue(output["ok"])
        self.assertEqual(output["data"]["apiFallback"], "route_not_found")
        _, params, body = self.server.observed[-1]
        self.assertTrue(params["path"][0].startswith(".alerts-security.alerts-triage/_search"))
        self.assertIn({"terms": {"kibana.alert.workflow_status": ["open"]}}, body["query"]["bool"]["filter"])
        self.assertIn({"terms": {"kibana.alert.severity": ["high"]}}, body["query"]["bool"]["filter"])

    def test_detection_engine_preserves_filters_projection_and_alert_id(self):
        self.server.mode = "signals"
        result = self.cli("list-alerts", "--siem", "fixture", "--last-minutes", "5", "--alert-id", "alert-one",
                          "--severity", "high", "--workflow-status", "open", "--limit", "1")
        self.assertEqual(result["data"]["adapter"], "detection-engine")
        self.assertEqual(result["data"]["hits"][0]["fields"], {"kibana.alert.rule.name": ["Example alert"]})
        [(path, params, body)] = self.server.observed
        self.assertEqual((path, params), (SIGNALS, {}))
        self.assertIn({"ids": {"values": ["alert-one"]}}, body["query"]["bool"]["filter"])
        self.assertIn({"terms": {"kibana.alert.severity": ["high"]}}, body["query"]["bool"]["filter"])
        self.assertNotIn("track_total_hits", body)
        self.assertNotIn("timeout", body)
        self.assertNotIn("from", body)

    def test_detection_engine_fallback_respects_permissions_and_bad_requests(self):
        args = ("list-alerts", "--siem", "fixture", "--last-minutes", "5", "--limit", "1")
        for state, code in (("signals_denied", "permission_denied"), ("signals_invalid", "request_rejected")):
            self.server.mode = state
            self.server.observed = []
            self.assertEqual(self.cli(*args)["code"], code)
            self.assertEqual([entry[0] for entry in self.server.observed], [SIGNALS])
        self.server.mode = "signals_unavailable"
        self.server.observed = []
        result = self.cli(*args)
        self.assertEqual(result["data"]["apiFallback"], "unsupported_capability")
        self.assertEqual([entry[0] for entry in self.server.observed], [SIGNALS, SEARCH])
        self.server.observed = []
        self.assertEqual(self.cli(*args, "--api", "detection-engine")["code"], "unsupported_capability")
        self.assertEqual([entry[0] for entry in self.server.observed], [SIGNALS])
        self.server.mode = "signals_old_offset"
        self.server.observed = []
        result = self.cli(*args, "--offset", "1")
        self.assertEqual(result["data"]["adapter"], "console")
        self.assertEqual(self.server.observed[0][2]["from"], 1)
        self.assertEqual(self.server.observed[1][2]["from"], 1)

    def test_detection_engine_custom_index_requires_console(self):
        args = ("list-alerts", "--siem", "fixture", "--last-minutes", "5", "--alert-index", "test-alerts")
        self.assertEqual(self.cli(*args, "--api", "detection-engine")["code"], "invalid_input")
        self.assertEqual(self.server.observed, [])
        self.assertEqual(self.cli(*args)["data"]["adapter"], "console")
        self.assertEqual([entry[0] for entry in self.server.observed], [SEARCH])

    def test_rule_list_and_detail_are_scoped_and_bounded(self):
        listed = self.cli("list-rules", "--siem", "fixture", "--limit", "1")["data"]
        self.assertEqual(listed["nextPage"], 2)
        self.assertEqual(listed["rules"][0]["id"], RULE_UUID)
        self.assertNotIn("query", listed["rules"][0])
        result = self.cli("get-rule", "--siem", "fixture", "--rule-id", RULE_STABLE_ID, "--include-query")["data"]
        self.assertEqual(result["rule"]["query"], "event.kind:alert")
        self.assertEqual(result["rule"]["description"], "[redacted]")
        self.assertNotIn("actions", result["rule"])
        self.assertEqual(self.server.observed[-1], (RULES, {"rule_id": [RULE_STABLE_ID]}, None))
        default = self.cli("get-rule", "--siem", "fixture", "--id", RULE_UUID)["data"]
        self.assertNotIn("query", default["rule"])

    def test_health_does_not_require_a_session_and_reports_503(self):
        self.store.logout(self.target)
        self.assertEqual(self.cli("status", "--siem", "fixture")["code"], "login_required")
        self.assertEqual(self.cli("health", "--siem", "fixture")["data"]["kibanaStatus"], "available")
        self.server.mode = "health_unavailable"
        self.assertEqual(self.cli("health", "--siem", "fixture")["data"]["httpStatus"], 503)

    def test_error_and_no_coverage_diagnostics(self):
        for mode, code in (("redirect", "redirect_blocked"), ("invalid_json", "invalid_response"),
                           ("no_shards", "no_shards"), ("all_failed", "search_failed")):
            self.server.mode = mode
            output = self.query()
            self.assertEqual(output["code"], code)
            if mode == "all_failed":
                self.assertEqual(output["details"]["reportedShardFailureGroups"], 1)
        self.assertEqual(len(self.server.observed), 4)

    def test_unauthorized_and_denied_session(self):
        self.server.mode = "expired"
        self.assertEqual(self.cli("status", "--siem", "fixture")["code"], "login_required")
        self.server.mode = "denied"
        self.assertEqual(self.cli("status", "--siem", "fixture")["code"], "permission_denied")

    def test_block_encoding_mutation_and_sensitive_projection(self):
        for index in ("logs%2f_update", "x/../_bulk", "cluster:logs", "https://example.org"):
            result = self.cli("query", "--siem", "fixture", "--index", index, "--last-minutes", "5")
            self.assertEqual(result["code"], "invalid_input")
        self.assertEqual(self.query("--fields", "headers.authorization")["code"], "invalid_input")
        path = Path(self.tmp.name) / "dsl.json"
        path.write_text(json.dumps({"query": {"script": {"script": "return true"}}}), encoding="utf-8")
        self.assertEqual(self.query("--dsl-file", str(path))["code"], "invalid_input")
        self.assertEqual(self.server.observed, [])

    def test_atomic_isolation_and_logout(self):
        other = self.store.register(parse_target(self.url, "other", context="other", allow_http=True))
        self.store.save(other, 0, self.session, replace=True)
        with self.store.db() as db:
            self.assertTrue(all(SECRET.encode() not in row[0] for row in db.execute("SELECT encrypted FROM targets")))
        generation = self.store.generation(self.target)
        result = self.cli("logout", "--siem", "fixture")["data"]
        self.assertEqual(result, {"siem": "fixture", "localSessionRemoved": True, "serverRevoked": False})
        self.assertEqual(self.cli("status", "--siem", "fixture")["code"], "login_required")
        self.assertEqual(self.store.load(other)[1], self.session)
        with self.assertRaisesRegex(Error, "Another login or logout"):
            self.store.save(self.target, generation, self.session, replace=True)

    def test_concurrent_refresh_reuses_latest_cookie(self):
        from argparse import Namespace
        from hpt_siem.cli import execute

        self.server.mode = "rotating"
        args = Namespace(command="list-data-views", siem="fixture", space=None, limit=10, offset=0)
        with ThreadPoolExecutor(max_workers=2) as workers:
            work = [workers.submit(execute, args, Store()) for _ in range(2)]
            self.assertEqual([item.result()["total"] for item in work], [0, 0])
        self.assertEqual(self.server.observed, ["sid=" + SECRET, "sid=" + ROTATED])
        self.assertEqual(self.store.load(self.target)[1]["cookies"][0]["value"], ROTATED)

    def test_cookie_scope(self):
        for overrides in ({"secure": True}, {"path": "/other"}, {"domain": "example.org"},
                          {"expires": int(time.time()) - 1}):
            with Client(self.target, [{**self.session["cookies"][0], **overrides}]) as client:
                with self.assertRaisesRegex(Error, "rejected"):
                    client.call("views", "triage")

    def test_early_browser_close_retains_session(self):
        try:
            import playwright.sync_api
        except ImportError:
            self.skipTest("Install the optional [login] extra for the browser lifecycle test.")
        with patch.object(playwright.sync_api, "sync_playwright") as launch:
            browser = launch.return_value.__enter__.return_value.chromium.launch.return_value
            browser.new_context.return_value.pages = []
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(self.cli("login", "--siem", "fixture")["code"], "browser_closed")
            browser.close.assert_called_once()
        self.assertEqual(self.store.load(self.target)[1], self.session)


if __name__ == "__main__":
    unittest.main()
