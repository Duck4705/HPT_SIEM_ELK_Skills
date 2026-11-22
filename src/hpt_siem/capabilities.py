from .esql import ADAPTERS, call_esql, can_try_other_api
from .metadata import invalid_response
from .model import Error
from .search import resolve_source


def failure(exc, read_probe):
    details = exc.details or {}
    layer = details.get("layer")
    state = {
        "permission_denied": "denied",
        "unsupported_language": "unsupported",
        "unsupported_capability": "unavailable",
        "route_not_found": "not_found",
        "request_rejected": "rejected",
    }.get(exc.code, "unknown")
    if exc.code == "login_required":
        raise exc
    return {"state": state, "code": exc.code, "layer": layer,
            "httpStatus": details.get("httpStatus"),
            "indexRead": "denied" if read_probe and layer == "elasticsearch" and state == "denied" else "unverified"}


def probe_search(client, space, index, clause):
    filters = [{"match_none": {}}]
    if clause:
        filters.append(clause)
    try:
        payload = client.call("search", space, index=index, timeout=6, body={
            "query": {"bool": {"filter": filters}}, "timeout": "3s",
            "size": 0, "_source": False, "track_total_hits": False,
        })
        shards = payload.get("_shards") if isinstance(payload, dict) else None
        if not isinstance(shards, dict) or not isinstance(payload.get("hits"), dict):
            raise invalid_response()
        visited, failed = shards.get("successful"), shards.get("failed")
        if type(visited) is not int or type(failed) is not int:
            raise invalid_response()
        if failed or payload.get("timed_out"):
            return {"state": "partial", "code": "partial_results", "indexRead": "unverified"}
        if not visited:
            return {"state": "no_shards", "code": "no_shards", "indexRead": "unverified"}
        return {"state": "verified", "indexRead": "verified", "sampledDocuments": 0}
    except Error as exc:
        return failure(exc, True)


def probe_esql(client, space, index, adapter):
    try:
        names, rows, partial = call_esql(client, space, "ROW hpt_probe = 1", adapter, 6)
        if names != ["hpt_probe"] or rows != [[1]]:
            raise invalid_response()
    except Error as exc:
        return failure(exc, False)
    if index is None:
        return {"state": "verified", "indexRead": "not_checked"}
    try:
        names, rows, data_partial = call_esql(
            client, space, f"FROM {index} | WHERE false | STATS hpt_probe = COUNT(*) | LIMIT 1", adapter, 6)
        if names != ["hpt_probe"] or rows != [[0]]:
            raise invalid_response()
    except Error as exc:
        return {**failure(exc, True), "engineProbe": "verified"}
    if partial or data_partial:
        return {"state": "partial", "indexRead": "unverified", "engineProbe": "verified"}
    return {"state": "verified", "indexRead": "verified", "engineProbe": "verified", "sampledDocuments": 0}


def check_query(client, space, args):
    index, view_id = None, None
    if args.index or args.data_view_id:
        index, _, view_id = resolve_source(client, space, args)
    search = {"dsl": None, "kql": {"kql": {"query": "*"}},
              "lucene": {"query_string": {"query": "*", "allow_leading_wildcard": False}}}
    languages = {}
    for language, clause in search.items():
        result = {"state": "not_checked", "indexRead": "not_checked"}
        if index is not None:
            dsl = languages.get("dsl", {}).get("checks", {}).get("console")
            if dsl and dsl.get("layer") == "kibana" and dsl["state"] in {"denied", "rejected", "not_found"}:
                result = {"state": "blocked_by_api", "code": dsl["code"], "layer": "kibana", "indexRead": "unverified"}
            else:
                result = probe_search(client, space, index, clause)
        languages[language] = {"checks": {"console": result}}
    languages["esql"] = {"checks": {adapter: probe_esql(client, space, index, adapter) for adapter in ADAPTERS}}
    for info in languages.values():
        info["verifiedApi"] = next((api for api, report in info["checks"].items()
                                    if report["state"] == "verified"), None)
    suggested_filter = next((language for language in ("kql", "dsl") if languages[language]["verifiedApi"]), None)
    return {
        "siem": client.target.id, "space": space, "index": index, "dataViewId": view_id,
        "scope": "requested_index_expression" if index else "engine_only",
        "preferredLanguages": {"filter": "kql", "stats": "esql"},
        "verifiedChoices": {"filter": suggested_filter,
                            "stats": "esql" if index and languages["esql"]["verifiedApi"] else None},
        "languages": languages,
        "apis": {
            "console": {"kibana": "POST /api/console/proxy", "elasticsearch": ["POST <index>/_search", "POST /_query"],
                        "requires": ["Kibana Console access", "Elasticsearch index read"]},
            "agent-builder": {"kibana": "POST /api/agent_builder/tools/_execute",
                              "tool": "platform.core.execute_esql",
                              "requires": ["Kibana agentBuilder:read", "Elasticsearch index read"]},
        },
    }


def list_data_streams(client, space, args):
    adapter = "console"
    try:
        payload = client.call("data_streams", space)
    except Error as exc:
        if not can_try_other_api(exc):
            raise
        adapter = "fleet"
        payload = client.call("fleet_data_streams", space)
    items = payload.get("data_streams") if isinstance(payload, dict) else None
    key = "name" if adapter == "console" else "index"
    if not isinstance(items, list) or not all(isinstance(item, dict) and isinstance(item.get(key), str) for item in items):
        raise invalid_response()
    secrets = [cookie["value"] for cookie in client.records() if cookie["value"]]
    names = sorted({item[key] for item in items if len(item[key]) <= 255 and not any(
        secret in item[key] for secret in secrets)})
    end = args.offset + args.limit
    return {"siem": client.target.id, "space": space, "adapter": adapter,
            "coverage": "fleet_managed" if adapter == "fleet" else "visible_data_streams",
            "dataStreams": names[args.offset:end], "total": len(names),
            "nextOffset": end if end < len(names) else None}
