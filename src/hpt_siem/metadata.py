import re

from .http import check_probe, view_summary
from .model import Error
from .model import Error


def invalid_response():
    return Error("invalid_response", "The approved API did not return its expected data structure.")


def data_view(client, space, view_id):
    payload = client.call("view", space, view_id=view_id)
    view = payload.get("data_view") if isinstance(payload, dict) else None
    if not view_summary(view) or view["id"] != view_id:
        raise invalid_response()
    return describe_view(view)


def describe_view(view):
    name = view.get("name")
    time_field = view.get("timeFieldName")
    return {
        "id": view["id"], "name": name if isinstance(name, str) and name else view["title"],
        "indexPattern": view["title"], "timeField": time_field if isinstance(time_field, str) else None,
    }


def health(client):
    try:
        payload = client.call("version", timeout=5)
    except Error as exc:
        if (exc.details or {}).get("httpStatus") == 503:
            return {"siem": client.target.id, "reachable": True, "kibanaStatus": "unavailable", "httpStatus": 503}
        raise
    status = payload.get("status") if isinstance(payload, dict) else None
    overall = status.get("overall") if isinstance(status, dict) else None
    level = overall.get("level") if isinstance(overall, dict) else None
    if level not in ("available", "degraded", "unavailable", "critical"):
        raise invalid_response()
    return {"siem": client.target.id, "reachable": True, "kibanaStatus": level, "httpStatus": 200}


def metadata(client, space, args, probe=None):
    result = {"siem": client.target.id, "space": space}
    if args.command == "status":
        version = None
        try:
            payload = client.call("version", timeout=3)
            if isinstance(payload, dict) and isinstance(payload.get("version"), dict):
                number = payload["version"].get("number")
                if isinstance(number, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]{1,24})?", number):
                    version = number
        except Error:
            pass
        return {**result, "authenticated": True, "probe": probe, "kibanaVersion": version,
                "capabilities": {"protectedProbe": probe, "candidateSearchAdapter": "console"}}
    route = "views" if args.command == "list-data-views" else "spaces"
    payload = client.call(route, space)
    if route == "views":
        if not check_probe(route, payload):
            raise invalid_response()
        entries = [describe_view(view) for view in payload["data_view"]]
        key = "dataViews"
    else:
        if not isinstance(payload, list) or not all(
            isinstance(item, dict) and isinstance(item.get("id"), str)
            and isinstance(item.get("name"), str) for item in payload
        ):
            raise invalid_response()
        entries = [{key: item[key] for key in ("id", "name")} for item in payload]
        key = "spaces"
    page = sorted(entries, key=lambda item: item["id"])[args.offset:args.offset + args.limit]
    return {**result, key: page, "total": len(entries),
            "nextOffset": args.offset + len(page) if args.offset + len(page) < len(entries) else None}
