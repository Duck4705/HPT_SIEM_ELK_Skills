from uuid import UUID

from .metadata import invalid_response
from .model import invalid
from .search import compact


SUMMARY = ("id", "rule_id", "name", "enabled", "type", "severity", "risk_score")
DETAIL = ("description", "index", "data_view_id", "interval", "from", "to", "language", "tags",
          "timestamp_override", "max_signals")


def project_rule(payload, names, secrets):
    if not isinstance(payload, dict) or not all(isinstance(payload.get(key), str) and payload[key]
                                                for key in ("id", "rule_id", "name")):
        raise invalid_response()
    return {key: compact(payload[key], secrets) for key in names if key in payload}


def rules(client, space, args):
    context = {"siem": client.target.id, "space": space, "adapter": "detection-engine"}
    secrets = [cookie["value"] for cookie in client.records() if cookie["value"]]
    if args.command == "list-rules":
        payload = client.call("rules_list", space, query_params={"page": args.page, "per_page": args.limit})
        secrets += [cookie["value"] for cookie in client.records() if cookie["value"]]
        entries, total = (payload.get("data"), payload.get("total")) if isinstance(payload, dict) else (None, None)
        if not isinstance(entries, list) or type(total) is not int or total < 0:
            raise invalid_response()
        return {**context, "rules": [project_rule(rule, SUMMARY, secrets) for rule in entries[:args.limit]],
                "total": total, "page": args.page, "limit": args.limit,
                "nextPage": args.page + 1 if args.page * args.limit < total else None}

    if args.id is not None:
        try:
            identifier = str(UUID(args.id))
        except ValueError:
            raise invalid("Use a valid Kibana rule UUID for --id.") from None
        name = "id"
    else:
        name, identifier = "rule_id", args.rule_id
        if not identifier or len(identifier) > 255 or not identifier.isprintable():
            raise invalid("Use a printable rule ID of at most 255 characters.")
    payload = client.call("rule_detail", space, query_params={name: identifier})
    if not isinstance(payload, dict) or payload.get(name) != identifier:
        raise invalid_response()
    secrets += [cookie["value"] for cookie in client.records() if cookie["value"]]
    fields = SUMMARY + DETAIL + (("query",) if args.include_query else ())
    rule = project_rule(payload, fields, secrets)
    if args.include_query and isinstance(payload.get("query"), str):
        rule["queryTruncated"] = len(payload["query"]) > 1024
    return {**context, "rule": rule}
