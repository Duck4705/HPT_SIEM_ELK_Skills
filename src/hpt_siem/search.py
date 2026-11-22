import json
import re
import sys
from datetime import datetime, timedelta, timezone

from .http import failure_info, finite_float, reject_constant, validate_index
from .metadata import data_view, invalid_response
from .model import Error, invalid, segment


FIELD = re.compile(r"[@A-Za-z0-9_][@A-Za-z0-9_.-]{0,127}")
SENSITIVE_FIELD = re.compile(r"authorization|password|passwd|secret|token|cookie|apikey|privatekey|credential|otp")
UNSUPPORTED_DSL = {
    "script", "script_score", "script_fields", "runtime_mappings", "indexed_shape",
    "percolate", "wrapper", "more_like_this", "terms_set", "geo_shape", "shape", "has_child", "has_parent",
}
MAX_DSL = 65536
MAX_OUTPUT = 65536


def sensitive(name):
    return SENSITIVE_FIELD.search(re.sub(r"[^a-z0-9]", "", name.lower())) is not None


def field(value, *, projection=False):
    if not isinstance(value, str) or not FIELD.fullmatch(value) or (projection and sensitive(value)):
        raise invalid("Use an explicit, non-sensitive field name without wildcards for field selection.")
    return value


def parse_date(value):
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.tzinfo is None:
            raise ValueError
        return date.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise invalid("Use ISO 8601 timestamps with an explicit time zone.") from None


def time_bounds(args):
    if args.last_minutes:
        if args.end:
            raise invalid("--end requires --start.")
        end = datetime.now(timezone.utc)
        return end - timedelta(minutes=args.last_minutes), end
    if not args.end:
        raise invalid("--start requires --end.")
    start, end = parse_date(args.start), parse_date(args.end)
    if not timedelta(0) < end - start <= timedelta(days=31):
        raise invalid("The range must be positive and at most 31 days.")
    return start, end


def validate_query(value, depth=0):
    if depth > 24:
        raise invalid("Search DSL is nested too deeply.")
    if isinstance(value, dict):
        if value.keys() & UNSUPPORTED_DSL:
            raise invalid("This Search DSL clause is outside the supported read subset.")
        if "terms" in value:
            terms = value["terms"]
            if not isinstance(terms, dict) or not all(
                isinstance(item, list) or name in {"boost", "_name"} for name, item in terms.items()
            ):
                raise invalid("Terms lookups are outside the supported read subset.")
        for item in value.values():
            validate_query(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            validate_query(item, depth + 1)


def load_dsl(filename):
    if not filename:
        return None
    try:
        if filename == "-":
            data = sys.stdin.buffer.read(MAX_DSL + 1)
        else:
            with open(filename, "rb") as source:
                data = source.read(MAX_DSL + 1)
        if len(data) > MAX_DSL:
            raise ValueError
        options = json.loads(data, parse_constant=reject_constant, parse_float=finite_float)
    except (OSError, ValueError, RecursionError):
        raise invalid("The DSL must be a valid UTF-8 JSON object of at most 64 KiB.") from None
    return dsl_query(options)


def dsl_query(options):
    try:
        if len(json.dumps(options, ensure_ascii=True, allow_nan=False)) > MAX_DSL:
            raise ValueError
    except (ValueError, TypeError, RecursionError):
        raise invalid("The DSL must be a JSON object of at most 64 KiB.") from None
    if not isinstance(options, dict) or options.keys() != {"query"} or not isinstance(options["query"], dict):
        raise invalid("Supply a Search DSL object with a single top-level query clause.")
    validate_query(options["query"])
    return options["query"]


def search_options(args):
    if len(args.source) + len(args.fields) > 20:
        raise invalid("Select at most 20 fields per query.")
    for name in args.source + args.fields:
        field(name, projection=True)
    if args.backend == "discover" and (args.source or args.offset or args.api != "auto"):
        raise invalid("Discover uses fields and a result limit. Omit source, offset and explicit API selection.")
    if args.command == "query":
        if args.index:
            validate_index(args.index)
        if args.data_view_id:
            segment(args.data_view_id)
        if args.time_field:
            field(args.time_field)
    if args.command != "query":
        if args.alert_index:
            validate_index(args.alert_index)
        alert_id = getattr(args, "alert_id", None)
        if alert_id is not None and not re.fullmatch(r"[a-zA-Z0-9_.-]{1,255}", alert_id):
            raise invalid("Use an exact alert document ID.")
        if args.api == "detection-engine" and (args.alert_index or args.alert_schema == "legacy"):
            raise invalid("Custom alert indices and legacy schema require --api console.")
        return time_bounds(args), None, "dsl"
    inline_dsl = getattr(args, "inline_dsl", None)
    has_dsl = args.dsl_file is not None or inline_dsl is not None
    language = args.language or ("dsl" if has_dsl else "esql" if args.intent == "stats" else "kql")
    if args.backend == "discover" and language == "dsl":
        raise invalid("Discover supports KQL, Lucene and ES|QL. Use the API backend for Search DSL.")
    if args.api == "agent-builder" and language != "esql":
        raise invalid("Agent Builder is available only for ES|QL.")
    if has_dsl and language != "dsl":
        raise invalid("A JSON DSL body requires Search DSL.")
    expression = args.expression
    if expression is not None and (not expression.strip() or len(expression.encode("utf-8")) > 8192):
        raise invalid("Use a nonempty query expression of at most 8 KiB.")
    if language == "dsl" and expression is not None:
        raise invalid("Use --dsl-file for Search DSL.")
    if language == "esql":
        from .esql import pipeline
        if args.source or args.offset:
            raise invalid("ES|QL uses --fields and a row limit. Omit --source and --offset.")
        if expression and not args.fields:
            raise invalid("Select output columns with --fields for a custom ES|QL pipeline.")
        query = pipeline(expression)
    elif language == "kql" and expression:
        query = {"kql": {"query": expression}}
    elif language == "lucene" and expression:
        query = {"query_string": {"query": expression, "allow_leading_wildcard": False}}
    else:
        query = dsl_query(inline_dsl) if inline_dsl is not None else load_dsl(args.dsl_file)
    return time_bounds(args), query, language


def alert_options(args, space):
    if args.alert_schema == "legacy":
        index, prefix = f".siem-signals-{space}", "signal"
        severity, workflow = prefix + ".rule.severity", prefix + ".status"
    else:
        index, prefix = f".alerts-security.alerts-{space}", "kibana.alert"
        severity, workflow = prefix + ".severity", prefix + ".workflow_status"
    filters = []
    if args.severity:
        filters.append({"terms": {severity: args.severity}})
    if args.workflow_status:
        filters.append({"terms": {workflow: args.workflow_status}})
    if getattr(args, "alert_id", None):
        filters.append({"ids": {"values": [args.alert_id]}})
    if args.alert_schema == "legacy" and "acknowledged" in (args.workflow_status or []):
        raise invalid("The legacy alert adapter supports open and closed workflow states.")
    defaults = ["@timestamp", severity, workflow, prefix + ".rule.name", "event.kind",
                "source.ip", "destination.ip", "event.dataset"]
    return args.alert_index or index, filters, defaults


def compact(value, secrets, depth=0):
    if depth >= 5:
        return "[truncated]"
    if isinstance(value, dict):
        return {key: compact(item, secrets, depth + 1) for key, item in list(value.items())[:20]
                if not sensitive(key) and len(key) <= 128 and not any(secret in key for secret in secrets)}
    if isinstance(value, list):
        return [compact(item, secrets, depth + 1) for item in value[:20]]
    if isinstance(value, str):
        return "[redacted]" if any(secret in value for secret in secrets) else value[:1024]
    return value


def resolve_source(client, space, args):
    view_id = args.data_view_id
    view = data_view(client, space, view_id) if view_id else None
    index = validate_index(view["indexPattern"] if view else args.index)
    timestamp = field(getattr(args, "time_field", None) or (view["timeField"] if view else None) or "@timestamp")
    return index, timestamp, view_id


def run_query(client, space, args, options):
    if args.backend == "discover":
        from .discover import discover_query
        return discover_query(client, space, args, options)
    try:
        return run_api_query(client, space, args, options)
    except Error as exc:
        if not can_use_discover(args, options[2], exc):
            raise
        from .discover import discover_query
        try:
            result = discover_query(client, space, args, options)
        except Error as fallback:
            raise Error(fallback.code, str(fallback), {
                **(fallback.details or {}), "apiCode": exc.code,
            }) from None
        return {**result, "apiFallback": exc.code}


def can_use_discover(args, language, error):
    if args.backend != "auto" or args.api != "auto" or args.source or args.offset:
        return False
    if args.command == "list-alerts":
        # An explicit denial by Detection Engine is terminal. Only use the UI after
        # an unavailable Detection Engine route and an unusable Kibana Console route.
        if (error.details or {}).get("apiFallback") not in {"route_not_found", "unsupported_capability"}:
            return False
    elif language not in {"kql", "lucene", "esql"}:
        return False
    if error.code == "unsupported_language":
        return True
    return (error.code in {"permission_denied", "request_rejected", "search_target_not_found",
                           "route_not_found", "unsupported_capability"}
            and (error.details or {}).get("layer") == "kibana")


def run_api_query(client, space, args, options):
    if options[2] == "esql":
        from .esql import query_esql
        return query_esql(client, space, args, options)
    return search(client, space, args, options)


def search_payload(client, space, args, index, body):
    preferred = (args.command == "list-alerts" and args.api != "console"
                 and not args.alert_index and args.alert_schema == "modern")
    fallback = {}
    if preferred:
        # Older Detection Engine versions accept neither timeout nor a default offset.
        detection_body = {key: value for key, value in body.items() if key not in {"timeout", "track_total_hits"}}
        if not args.offset:
            detection_body.pop("from")
        try:
            result = client.call("alert_search", space, body=detection_body, timeout=args.timeout + 4)
            return result, "detection-engine", fallback
        except Error as exc:
            if args.api != "auto" or exc.code not in {"route_not_found", "unsupported_capability"}:
                raise
            fallback = {"apiFallback": exc.code}
    try:
        result = client.call("search", space, index=index, body=body, timeout=args.timeout + 4)
    except Error as exc:
        if exc.code == "route_not_found" or fallback:
            details = {**(exc.details or {}), **fallback}
            if exc.code == "route_not_found":
                raise Error("search_target_not_found", "The Console route or requested index was not found.", details) from None
            raise Error(exc.code, str(exc), details) from None
        raise
    return result, "console", fallback


def search(client, space, args, options):
    bounds, query, language = options
    start, end = (date.isoformat(timespec="milliseconds") for date in bounds)
    view_id, filters, defaults = None, [], []
    if args.command == "list-alerts":
        index, filters, defaults = alert_options(args, space)
        timestamp = "@timestamp"
    else:
        index, timestamp, view_id = resolve_source(client, space, args)
    filters.insert(0, {"range": {timestamp: {"gte": start, "lt": end, "format": "strict_date_optional_time"}}})
    if query is not None:
        filters.append(query)
    source = args.source or False
    fields = args.fields or (defaults if not source else [])
    body = {
        "query": {"bool": {"filter": filters}},
        "from": args.offset, "size": args.limit, "timeout": f"{args.timeout}s",
        "sort": [{timestamp: {"order": "desc", "unmapped_type": "date"}}],
        "track_total_hits": 10000, "_source": source,
    }
    if fields:
        body["fields"] = fields
    before = client.records()
    payload, adapter, fallback = search_payload(client, space, args, index, body)
    context = {"siem": client.target.id, "space": space, "index": index, "dataViewId": view_id,
               "timeField": timestamp, "start": start, "end": end, "adapter": adapter, "language": language, **fallback,
               "coverageRestricted": args.coverage_note == "subset"}
    return {**context, **format_result(payload, args, before + client.records(), source, fields)}


def project(value, names):
    if isinstance(value, list):
        return [project(item, names) for item in value[:20] if isinstance(item, (dict, list))]
    if not isinstance(value, dict):
        return {}
    result = {}
    for key, item in value.items():
        if key in names:
            result[key] = item
            continue
        nested = [name[len(key) + 1:] for name in names if name.startswith(key + ".")]
        if nested and isinstance(item, (dict, list)):
            result[key] = project(item, nested)
    return result


def format_result(payload, args, records, source, fields):
    if not isinstance(payload, dict):
        raise invalid_response()
    shards, hit_block = payload.get("_shards"), payload.get("hits")
    if not isinstance(shards, dict) or not isinstance(hit_block, dict):
        raise invalid_response()
    if any(type(shards.get(key)) is not int or shards[key] < 0 for key in ("total", "successful", "failed")):
        raise invalid_response()
    raw_total, hits = hit_block.get("total"), hit_block.get("hits")
    if type(raw_total) is int:
        raw_total = {"value": raw_total, "relation": "eq"}
    if (not isinstance(hits, list) or not isinstance(raw_total, dict)
            or type(raw_total.get("value")) is not int or raw_total["value"] < 0
            or raw_total.get("relation") not in ("eq", "gte")):
        raise invalid_response()
    secrets = [cookie["value"] for cookie in records if cookie["value"]]
    failures = shards.get("failures") or []
    if not isinstance(failures, list):
        raise invalid_response()
    failures = [failure_info(item, secrets) for item in failures[:20] if isinstance(item, dict)]
    limited_hits = []
    budget = MAX_OUTPUT
    for hit in hits[:args.limit]:
        if not isinstance(hit, dict):
            raise invalid_response()
        selected = {key: hit[key] for key in ("_id", "_index") if isinstance(hit.get(key), str)}
        for name, projection in (("_source", source), ("fields", fields)):
            if projection and isinstance(hit.get(name), dict):
                selected[name] = project(hit[name], projection)
        result = compact(selected, secrets)
        budget -= len(json.dumps(result, ensure_ascii=True))
        if budget < 0:
            break
        limited_hits.append(result)
    consumed = len(limited_hits)
    clusters = payload.get("_clusters")
    cluster_partial = isinstance(clusters, dict) and any(
        type(clusters.get(key)) is int and clusters[key] > 0 for key in ("partial", "failed", "skipped"))
    partial = bool(shards["failed"] or payload.get("timed_out") or payload.get("terminated_early") or cluster_partial)
    truncated = consumed < len(hits)
    next_offset = args.offset + consumed
    return {
        "total": {"value": raw_total["value"], "relation": raw_total["relation"]},
        "hits": limited_hits, "isPartial": partial, "timedOut": payload.get("timed_out") is True,
        "coverageStatus": "no_shards" if shards["total"] == 0 else "searched",
        "shards": {key: shards[key] for key in ("total", "successful", "failed")},
        "shardFailures": failures, "hitsTruncated": truncated,
        "nextOffset": next_offset if consumed and next_offset <= 9900 and
        (truncated or next_offset < raw_total["value"] or
         (raw_total["relation"] == "gte" and consumed >= args.limit)) else None,
    }
