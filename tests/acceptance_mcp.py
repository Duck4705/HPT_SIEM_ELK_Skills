"""Optional live MCP readiness test against a user-authorized Kibana URL."""

import argparse
import asyncio
import json
import os
import re
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


TOOLS = {"HPT_register_siem", "HPT_list_siems", "HPT_login", "HPT_status", "HPT_list_spaces", "HPT_list_data_views",
         "HPT_list_data_streams", "HPT_check_query", "HPT_query", "HPT_check_alerts", "HPT_logout", "HPT_health", "HPT_list_rules", "HPT_get_rule"}
SOURCE = re.compile(r"[a-z0-9_.-]+\*?")
FIELD = re.compile(r"[@A-Za-z0-9_][@A-Za-z0-9_.-]{0,127}")


def report(stage, **result):
    print(json.dumps({"stage": stage, **result}, ensure_ascii=True), flush=True)


@asynccontextmanager
async def connect(args):
    params = StdioServerParameters(command=sys.executable, args=["-m", "hpt_siem.mcp_server"],
                                   env=dict(os.environ))
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer, read_timeout_seconds=timedelta(
                seconds=args.login_timeout + 70)) as mcp:
            await mcp.initialize()
            yield mcp


async def run(mcp, stage, tool, params):
    result = await mcp.call_tool(tool, params)
    response = result.structuredContent
    if result.isError or not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        report(stage, tool=tool, ok=False, code="protocol_error")
        return {}
    data = response.get("data") or {}
    if not isinstance(data, dict):
        report(stage, tool=tool, ok=False, code="protocol_error")
        return {}
    details = response.get("details") or {}
    summary = {}
    for key in ("adapter", "apiFallback", "kibanaVersion", "kibanaStatus", "isPartial", "coverage", "coverageStatus",
                "total", "shards", "serverRevoked", "localSessionRemoved"):
        if key in data:
            summary[key] = data[key]
    for key in ("siems", "spaces", "dataViews", "dataStreams", "hits", "rows", "rules"):
        if isinstance(data.get(key), list):
            summary[key + "Count"] = len(data[key])
    if isinstance(data.get("languages"), dict):
        summary["verifiedApis"] = {language: entry.get("verifiedApi") for language, entry in data["languages"].items()}
    if isinstance(details, dict):
        summary.update({key: details[key] for key in ("layer", "httpStatus", "apiCode") if key in details})
    report(stage, tool=tool, ok=response["ok"], code=response.get("code"), **summary)
    return response


def choose_view(result):
    views = (result.get("data") or {}).get("dataViews") or []
    candidates = [item for item in views if isinstance(item, dict)
                  and isinstance(item.get("id"), str)
                  and isinstance(item.get("indexPattern"), str)
                  and SOURCE.fullmatch(item["indexPattern"])
                  and not item["indexPattern"].startswith((".", "_"))
                  and item["indexPattern"] not in {"logs-*", "metrics-*", "traces-*", "filebeat-*", "winlogbeat-*"}]
    return min(candidates, key=lambda item: (
        not item["indexPattern"].startswith(("logs-", "filebeat-")),
        "*" in item["indexPattern"], len(item["indexPattern"]), item["id"]), default=None)


def usable(result):
    return result.get("ok") is True and result.get("code") == "ok"


async def acceptance(args):
    identity = {"siem": args.siem}
    login_attempted = False
    passed = False
    try:
        async with connect(args) as mcp:
            names = {tool.name for tool in (await mcp.list_tools()).tools}
            missing = sorted(TOOLS - names)
            report("tool_discovery", ok=not missing, count=len(names), missing=missing)
            if missing:
                return 1
            before = await run(mcp, "before_register", "HPT_list_siems", {})
            if not before.get("ok"):
                return 1
            if any(item.get("id") == args.siem for item in before["data"]["siems"]):
                report("test_target_already_exists", ok=False)
                return 1
            registered = await run(mcp, "register", "HPT_register_siem", {
                **identity, "url": args.url, "context": args.siem, "allow_http": args.allow_http,
            })
            if not registered.get("ok"):
                return 1
            listed = await run(mcp, "after_register", "HPT_list_siems", {})
            if not listed.get("ok") or not any(item.get("id") == args.siem for item in listed["data"]["siems"]):
                return 1
            health = await run(mcp, "kibana_health", "HPT_health", identity)
            fresh = await run(mcp, "before_login", "HPT_status", identity)
            if fresh.get("code") != "login_required":
                return 1
            login_attempted = True
            report("awaiting_interactive_login")
            logged_in = await run(mcp, "login", "HPT_login", {
                **identity, "browser": args.browser, "login_timeout": args.login_timeout,
            })
            if not logged_in.get("ok"):
                return 1
        async with connect(args) as mcp:
            status = await run(mcp, "session_after_mcp_restart", "HPT_status", identity)
            if not status.get("ok"):
                return 1
            spaces = await run(mcp, "space_inventory", "HPT_list_spaces", {**identity, "limit": 10})
            views = await run(mcp, "data_view_inventory", "HPT_list_data_views", {**identity, "limit": 100})
            scope = identity.copy()
            view = choose_view(views)
            if view is None:
                available = (spaces.get("data") or {}).get("spaces") or []
                for space in [row.get("id") for row in available if row.get("id") != status["data"]["space"]][:2]:
                    if not isinstance(space, str):
                        continue
                    alternate = {**identity, "space": space}
                    views = await run(mcp, "alternate_data_view_inventory", "HPT_list_data_views",
                                      {**alternate, "limit": 100})
                    view = choose_view(views)
                    if view is not None:
                        scope = alternate
                        break
            streams = await run(mcp, "stream_inventory", "HPT_list_data_streams", {**scope, "limit": 3})
            source = {**scope, "data_view_id": view["id"]} if view else scope
            capabilities = await run(mcp, "query_capability", "HPT_check_query", source)
            searches = []
            if view:
                end = datetime.now(timezone.utc)
                start = end - timedelta(minutes=5)
                bounded = {**source, "start": start.isoformat(), "end": end.isoformat(), "limit": 1}
                time_field = view.get("timeField") or "@timestamp"
                if not isinstance(time_field, str) or not FIELD.fullmatch(time_field):
                    time_field = "@timestamp"
                kql = {**bounded, "query": time_field + ": *"}
                searches.append(await run(mcp, "query_reads", "HPT_query", kql))
                searches.append(await run(mcp, "query_stats", "HPT_query", {**bounded, "intent": "stats"}))
                searches.append(await run(mcp, "query_reads_repeat", "HPT_query", kql))
            else:
                report("query_reads", ok=False, code="no_narrow_data_view")
            alerts = await run(mcp, "alert_read", "HPT_check_alerts", {**scope, "last_minutes": 1440, "limit": 1})
            hits = (alerts.get("data") or {}).get("hits") or []
            exact_alert = True
            if hits and hits[0].get("_id"):
                alert_id = hits[0]["_id"]
                filtered = await run(mcp, "alert_by_id", "HPT_check_alerts",
                                     {**scope, "last_minutes": 1440, "limit": 1, "alert_id": alert_id})
                filtered_hits = (filtered.get("data") or {}).get("hits") or []
                exact_alert = usable(filtered) and len(filtered_hits) == 1 and filtered_hits[0].get("_id") == alert_id
            listed_rules = await run(mcp, "rule_list", "HPT_list_rules", {**scope, "limit": 1})
            rules = (listed_rules.get("data") or {}).get("rules") or []
            exact_rule = False
            if rules and rules[0].get("rule_id"):
                detail = await run(mcp, "rule_detail", "HPT_get_rule", {
                    **scope, "rule_id": rules[0]["rule_id"],
                })
                exact_rule = usable(detail) and (detail["data"]["rule"]["id"] == rules[0]["id"])
            else:
                report("rule_detail", ok=False, code="no_rule_to_verify")
            healthy = usable(health) and health["data"].get("kibanaStatus") == "available"
            passed = healthy and len(searches) == 3 and exact_alert and exact_rule and all(
                map(usable, [spaces, views, streams, capabilities, alerts, listed_rules, *searches]))
    finally:
        if login_attempted:
            async with connect(args) as mcp:
                logout = await run(mcp, "logout_test_session", "HPT_logout", identity)
                after = await run(mcp, "after_logout", "HPT_status", identity)
                data = logout.get("data") or {}
                passed = (passed and usable(logout) and data.get("localSessionRemoved") is True
                          and data.get("serverRevoked") is False and after.get("code") == "login_required")
    report("readiness", ok=passed)
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--siem", required=True, help="Unused local ID for a dedicated test session.")
    parser.add_argument("--allow-http", action="store_true")
    parser.add_argument("--browser", choices=("msedge", "chrome", "chromium"), default="msedge")
    parser.add_argument("--login-timeout", type=int, default=300)
    args = parser.parse_args()
    return asyncio.run(acceptance(args))


if __name__ == "__main__":
    raise SystemExit(main())
