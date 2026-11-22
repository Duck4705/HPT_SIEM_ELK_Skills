"""Typed MCP tools over the same operations used by the local CLI."""

import asyncio
import sys
from typing import Any, Literal

from .cli import operate, parser

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.types import ToolAnnotations
except ImportError:
    FastMCP = None

Result = dict[str, Any]
Backend = Literal["auto", "api", "discover"]
Browser = Literal["msedge", "chrome", "chromium"]
Language = Literal["kql", "esql", "dsl", "lucene"]
Severity = Literal["low", "medium", "high", "critical"]
Workflow = Literal["open", "acknowledged", "closed"]


def arguments(command, options, inline_dsl=None):
    argv = [command]
    for name, value in options.items():
        flag = "--" + name.replace("_", "-")
        if value is True:
            argv.append(flag)
        elif value is not None and value is not False:
            values = value if isinstance(value, list) else [value]
            argv.extend(f"{flag}={item}" for item in values)
    parsed = parser().parse_args(argv)
    parsed.inline_dsl = inline_dsl
    return parsed


async def call(command, options, inline_dsl=None):
    return await asyncio.to_thread(operate, lambda: arguments(command, options, inline_dsl))


def window(options, minutes):
    if options["start"] is None and options["end"] is None and options["last_minutes"] is None:
        options["last_minutes"] = minutes
    return options


async def query(siem: str, query: str | dict[str, Any] | None = None, *,
                index: str | None = None, data_view_id: str | None = None, space: str | None = None,
                language: Language | None = None, intent: Literal["filter", "stats"] = "filter",
                last_minutes: int | None = None, start: str | None = None, end: str | None = None,
                limit: int = 5, fields: list[str] | None = None, source: list[str] | None = None,
                offset: int = 0, timeout: int = 10, time_field: str | None = None,
                backend: Backend = "auto", api: Literal["auto", "console", "agent-builder"] = "auto",
                coverage_note: Literal["subset"] | None = None, browser: Browser = "msedge") -> Result:
    """Search logs with KQL, Lucene, ES|QL or Search DSL. Auto tries Kibana REST first and uses Discover for compatible queries if needed. Use backend=api for REST only."""
    options = window(locals().copy(), 5)
    expression = options.pop("query")
    if isinstance(expression, str):
        options["expression"] = expression
    return await call("query", options, expression if isinstance(expression, dict) else None)


async def check_alerts(siem: str, *, space: str | None = None, alert_id: str | None = None,
                       severity: list[Severity] | None = None, workflow_status: list[Workflow] | None = None,
                       last_minutes: int | None = None, start: str | None = None, end: str | None = None,
                       limit: int = 5, fields: list[str] | None = None, offset: int = 0, timeout: int = 10,
                       alert_index: str | None = None, alert_schema: Literal["modern", "legacy"] = "modern",
                       backend: Backend = "auto",
                       api: Literal["auto", "detection-engine", "console"] = "auto",
                       browser: Browser = "msedge") -> Result:
    """Read Security Alerts by newest timestamp or exact ID. Auto prefers Detection Engine, then Console for unsupported API routes, then Discover when eligible."""
    return await call("list-alerts", window(locals().copy(), 1440))


async def check_query(siem: str, *, space: str | None = None, index: str | None = None,
                      data_view_id: str | None = None) -> Result:
    """Probe query languages, API routes and source read access without returning documents."""
    return await call("check-query", locals())


async def list_siems() -> Result:
    """List registered SIEM IDs, scopes and defaults."""
    return await call("list-siems", {})


async def status(siem: str, *, space: str | None = None) -> Result:
    """Verify the local SIEM session against a protected API."""
    return await call("status", locals())


async def health(siem: str) -> Result:
    """Read Kibana operational health without credentials. Use status to verify a saved session."""
    return await call("health", locals())


async def list_rules(siem: str, *, space: str | None = None, page: int = 1, limit: int = 10) -> Result:
    """List detection rule summaries through Kibana's Detection Engine."""
    return await call("list-rules", locals())


async def get_rule(siem: str, *, space: str | None = None, id: str | None = None,
                   rule_id: str | None = None, include_query: bool = False) -> Result:
    """Read one detection rule by Kibana UUID (id) or stable rule_id. Request the query only if needed."""
    return await call("get-rule", locals())


async def list_spaces(siem: str, *, limit: int = 25, offset: int = 0) -> Result:
    """List Kibana spaces available to the current user."""
    return await call("list-spaces", locals())


async def list_data_views(siem: str, *, space: str | None = None, limit: int = 25, offset: int = 0) -> Result:
    """List data view IDs, display names and underlying index patterns."""
    return await call("list-data-views", locals())


async def list_data_streams(siem: str, *, space: str | None = None, limit: int = 25, offset: int = 0) -> Result:
    """List data streams visible through an authorized inventory API."""
    return await call("list-data-streams", locals())


async def register_siem(url: str, siem: str, *, context: str = "default", allow_http: bool = False) -> Result:
    """Register a user-provided Kibana URL locally. Set allow_http only for an approved HTTP deployment."""
    return await call("register", {"url": url, "id": siem, "context": context, "allow_http": allow_http})


async def login(siem: str, *, space: str | None = None, browser: Browser = "msedge",
                login_timeout: int = 180) -> Result:
    """Open a dedicated browser for the user to sign in. Call only when the user is ready to interact."""
    return await call("login", locals())


async def logout(siem: str) -> Result:
    """Remove the selected local session after the user requests it."""
    return await call("logout", locals())


def server():
    mcp = FastMCP("hpt-siem")
    read_only = ToolAnnotations(readOnlyHint=True, openWorldHint=True)
    for tool in (query, check_alerts, check_query, list_siems, status, health, list_rules, get_rule,
                 list_spaces, list_data_views, list_data_streams):
        mcp.add_tool(tool, name=f"HPT_{tool.__name__}", annotations=read_only)
    for tool in (register_siem, login, logout):
        mcp.add_tool(tool, name=f"HPT_{tool.__name__}")
    return mcp


def main():
    if FastMCP is None:
        print("Install HPT_SIEM_ELK_Skills with its [mcp] extra.", file=sys.stderr)
        return 1
    server().run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
