import json
import re

from .metadata import invalid_response
from .model import Error, invalid
from .search import MAX_OUTPUT, compact, resolve_source


ADAPTERS = {"console": "esql", "agent-builder": "esql_tool"}
STAGES = {"WHERE", "STATS", "SORT", "EVAL", "KEEP", "DROP", "RENAME"}


def pipeline(expression):
    if not expression:
        return ""
    if '"""' in expression:
        raise invalid("ES|QL pipelines use ordinary quoted strings.")
    # Mask quoted literals so delimiters inside a filter value stay part of that value.
    masked = re.sub(r'"(?:[^"\\\r\n]|\\.)*"', lambda match: "x" * len(match[0]), expression)
    if re.search(r'[";`/\\\x00-\x08\x0b\x0c\x0e-\x1f]', masked):
        raise invalid("ES|QL accepts processing stages with ordinary quoted strings.")
    for stage in masked.strip().removeprefix("|").split("|"):
        parts = stage.split(maxsplit=1)
        if len(parts) != 2 or parts[0].upper() not in STAGES:
            raise invalid("Use ES|QL processing stages after FROM. Set source and limit using CLI options.")
    return expression.strip().removeprefix("|").strip()


def parse_table(payload, adapter):
    if not isinstance(payload, dict):
        raise invalid_response()
    if adapter == "agent-builder":
        results = payload.get("results")
        if not isinstance(results, list):
            raise invalid_response()
        if any(isinstance(item, dict) and item.get("type") == "error" for item in results):
            raise Error("request_rejected", "Agent Builder returned an ES|QL tool error.",
                        {"layer": "agent-builder"})
        tables = [item.get("data") for item in results if isinstance(item, dict)
                  and item.get("type") == "esql_results"]
        if len(tables) != 1 or not isinstance(tables[0], dict):
            raise invalid_response()
        payload = tables[0]
    columns, rows = payload.get("columns"), payload.get("values")
    if not isinstance(columns, list) or not columns or not isinstance(rows, list):
        raise invalid_response()
    if not all(isinstance(col, dict) and isinstance(col.get("name"), str) for col in columns):
        raise invalid_response()
    names = [col["name"] for col in columns]
    if len(names) != len(set(names)) or not all(isinstance(row, list) and len(row) == len(names) for row in rows):
        raise invalid_response()
    partial = payload.get("is_partial")
    clusters = payload.get("_clusters")
    if isinstance(clusters, dict) and any(type(clusters.get(key)) is int and clusters[key] > 0
                                          for key in ("partial", "failed", "skipped")):
        partial = True
    return names, rows, partial if isinstance(partial, bool) else None


def call_esql(client, space, query, adapter, timeout):
    response = client.call(ADAPTERS[adapter], space, body={"query": query}, timeout=timeout)
    return parse_table(response, adapter)


def can_try_other_api(error):
    return (error.code in {"permission_denied", "request_rejected", "route_not_found", "unsupported_capability"}
            and (error.details or {}).get("layer") == "kibana")


def build_esql(args, options, index, timestamp):
    bounds, expression, _ = options
    start, end = (date.isoformat(timespec="milliseconds") for date in bounds)
    query = (f"FROM {index} METADATA _index | WHERE `{timestamp}` >= TO_DATETIME({json.dumps(start)}) "
             f"AND `{timestamp}` < TO_DATETIME({json.dumps(end)})")
    fields = args.fields or (["events"] if not expression and args.intent == "stats" else [timestamp, "_index"])
    if expression:
        query += " | " + expression
    elif args.intent == "stats":
        query += " | STATS events = COUNT(*)"
    query += " | KEEP " + ", ".join(f"`{name}`" for name in fields) + f" | LIMIT {args.limit}"
    return query, fields, start, end


def query_esql(client, space, args, options):
    index, timestamp, view_id = resolve_source(client, space, args)
    query, fields, start, end = build_esql(args, options, index, timestamp)
    secrets = [record["value"] for record in client.records() if record["value"]]
    adapter = "console" if args.api == "auto" else args.api
    try:
        columns, rows, partial = call_esql(client, space, query, adapter, args.timeout)
    except Error as exc:
        if args.api != "auto" or not can_try_other_api(exc):
            raise
        adapter = "agent-builder"
        columns, rows, partial = call_esql(client, space, query, adapter, args.timeout)
    secrets += [record["value"] for record in client.records() if record["value"]]
    return format_esql(columns, rows, partial, fields, secrets, args.limit, {
        "siem": client.target.id, "space": space, "index": index, "dataViewId": view_id,
        "timeField": timestamp, "start": start, "end": end, "language": "esql", "adapter": adapter,
        "coverageRestricted": args.coverage_note == "subset",
    })


def format_esql(columns, rows, partial, fields, secrets, limit, context):
    if any(name not in columns for name in fields):
        raise invalid_response()
    projected = []
    budget = MAX_OUTPUT
    positions = [columns.index(name) for name in fields]
    for row in rows[:limit]:
        clean = [compact(row[position], secrets) for position in positions]
        budget -= len(json.dumps(clean, ensure_ascii=True))
        if budget < 0:
            break
        projected.append(clean)
    return {**context, "columns": fields, "rows": projected,
            "rowsTruncated": len(projected) < len(rows), "isPartial": partial}
