"""Bounded searches via the official Discover UI for deployments with restricted HTTP adapters."""

import json
import re
import time
from fnmatch import fnmatchcase
from urllib.parse import quote, urlsplit

from .browser import disable_browser_debugging
from .esql import build_esql, format_esql, parse_table
from .metadata import data_view, invalid_response
from .model import Error, invalid
from .search import alert_options, field, format_result, resolve_source


MAX_UI_RESPONSE = 8 * 1024 * 1024
DATA_STREAM_BACKING = re.compile(r"\.ds-(.+)-\d{4}\.\d{2}\.\d{2}-\d+")
ALERT_BACKING = re.compile(r"\.internal(\.alerts-security\.alerts-.+)-\d+")


def rison_string(value):
    return "'" + value.replace("!", "!!").replace("'", "!'") + "'"


def find_view(client, space, index):
    payload = client.call("views", space)
    views = payload.get("data_view") if isinstance(payload, dict) else None
    if not isinstance(views, list):
        raise invalid_response()
    matching = [view["id"] for view in views if isinstance(view, dict) and view.get("title") == index
                and isinstance(view.get("id"), str)]
    if not matching:
        raise Error("unsupported_capability", "Discover needs a data view with the requested index pattern.")
    if len(matching) > 1:
        raise invalid("Multiple data views match. Supply an explicit data view ID for Discover.")
    return matching[0]


def alert_expression(filters):
    expressions = []
    for clause in filters:
        if "ids" in clause:
            expressions.append("_id: " + json.dumps(clause["ids"]["values"][0]))
        else:
            name, values = next(iter(clause["terms"].items()))
            expressions.append(name + ": (" + " OR ".join(map(json.dumps, values)) + ")")
    return " AND ".join(expressions)


def discover_url(client, space, start, end, state):
    prefix = client.target.prefix + client.target.scope(space) + "/app/discover"
    dates = "(time:(from:" + rison_string(start) + ",to:" + rison_string(end) + "))"
    return prefix + "#/?_g=" + quote(dates, safe="") + "&_a=" + quote(state, safe="")


def discover_query(client, space, args, options):
    bounds, expression, language = options
    start, end = (date.isoformat(timespec="milliseconds").replace("+00:00", "Z") for date in bounds)
    if args.command == "list-alerts":
        index, filters, defaults = alert_options(args, space)
        view_id = find_view(client, space, index)
        view = data_view(client, space, view_id)
        timestamp = field(view["timeField"] or "@timestamp")
        expression, fields, language = alert_expression(filters), args.fields or defaults, "kql"
    else:
        index, timestamp, view_id = resolve_source(client, space, args)
        fields = args.fields
        if language != "esql":
            view_id = view_id or find_view(client, space, index)
            view = data_view(client, space, view_id)
            if not view["timeField"] or view["timeField"] != timestamp:
                raise invalid("Discover requires a data view with the requested time field.")
            if expression:
                expression = expression["kql" if language == "kql" else "query_string"]["query"]
    context = {"siem": client.target.id, "space": space, "index": index, "dataViewId": view_id,
               "timeField": timestamp, "start": start, "end": end, "language": language,
               "adapter": "discover", "coverageRestricted": args.coverage_note == "subset"}
    before = client.records()
    if language == "esql":
        query, fields, _, _ = build_esql(args, options, index, timestamp)
        state = f"(query:(esql:{rison_string(query)}))"
        url = discover_url(client, space, start, end, state)
        table = use_browser(client, args, url, lambda page: esql_ui(page, client, url, query, args.timeout))
        secrets = [item["value"] for item in before + client.records() if item["value"]]
        return format_esql(*table, fields, secrets, args.limit, context)
    mode = "kuery" if language == "kql" else "lucene"
    columns = ",".join(map(rison_string, fields))
    state = (f"(index:{rison_string(view_id)},query:(language:{mode},query:{rison_string(expression or '')}),"
             f"sort:!(!({rison_string(timestamp)},desc)),columns:!({columns}))")
    url = discover_url(client, space, start, end, state)
    payload = use_browser(client, args, url, lambda page: search_ui(page, client, url, index, args.timeout))
    result = format_result(payload, args, before + client.records(), False, fields)
    # Discover owns server-side sampling. The tool makes no promises about subsequent pages.
    result["nextOffset"] = None
    return {**context, **result}


def use_browser(client, args, url, task):
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeout
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise Error("missing_dependency", "Install [login] for the Discover backend.") from None
    if client.target.origin.startswith("http:") and not client.target.allow_http:
        raise Error("insecure_transport", "The Discover session requires approved HTTP registration.")
    disable_browser_debugging()
    opened = False
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                channel=None if args.browser == "chromium" else args.browser, headless=True, timeout=15000)
            try:
                opened = True
                context = browser.new_context(accept_downloads=False, viewport={"width": 1920, "height": 1080})
                for record in client.records():
                    data = {key: record[key] for key in ("name", "value", "domain", "path", "secure")}
                    if record["expires"] is not None:
                        data["expires"] = record["expires"]
                    context.add_cookies([data])
                page = context.new_page()
                result = task(page)
                for item in context.cookies([url.split("#")[0], client.target.home]):
                    client.add_cookie({
                        "name": item["name"], "value": item["value"], "domain": item["domain"],
                        "path": item["path"], "secure": item["secure"],
                        "host_only": not item["domain"].startswith("."),
                        "expires": None if item["expires"] < 0 else int(item["expires"]),
                    })
                return result
            finally:
                if browser.is_connected():
                    try:
                        browser.close()
                    except PlaywrightError:
                        pass
    except PlaywrightTimeout:
        raise Error("timeout", "Kibana Discover did not finish within the allotted time.") from None
    except PlaywrightError:
        code = "discover_unavailable" if opened else "browser_unavailable"
        raise Error(code, "Could not run the authorized Kibana Discover flow.") from None


def navigate(page, client, url):
    response = page.goto(url, wait_until="commit", timeout=18000)
    target, current = urlsplit(client.target.origin), urlsplit(page.url)
    if (current.scheme, current.netloc) != (target.scheme, target.netloc):
        raise Error("login_required", "Discover redirected to sign-in. Renew the local session.")
    if "/login" in urlsplit(page.url).path or (response and response.status == 401):
        raise Error("login_required", "Discover requires a fresh sign-in.")
    if response and response.status == 403:
        raise Error("permission_denied", "Kibana denied access to Discover.", {"layer": "kibana", "httpStatus": 403})
    if response and response.status >= 400:
        raise Error("discover_unavailable", "Discover did not open in the selected space.")


def response_json(response):
    if response.status in {401, 403}:
        raise Error("login_required" if response.status == 401 else "permission_denied",
                    "Kibana rejected the Discover search.", {"layer": "kibana", "httpStatus": response.status})
    if response.status >= 400:
        raise Error("request_rejected", "Kibana rejected the Discover search.",
                    {"layer": "kibana", "httpStatus": response.status})
    raw = response.body()
    if len(raw) > MAX_UI_RESPONSE:
        raise Error("response_too_large", "Narrow the data view, time range or query used by Discover.")
    try:
        return [json.loads(raw)]
    except (ValueError, UnicodeError, RecursionError):
        items = []
        for line in raw.splitlines():
            try:
                items.append(json.loads(line))
            except (ValueError, UnicodeError, RecursionError):
                continue
        return items


def objects(value):
    if isinstance(value, dict):
        yield value
        for key, child in value.items():
            if key not in {"fields", "_source", "aggregations", "hits", "values", "columns"}:
                yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def observed(page, client, matches, route_prefixes):
    origin = urlsplit(client.target.origin)
    queued = []

    def capture(response):
        route = urlsplit(response.url)
        if (route.scheme, route.netloc) == (origin.scheme, origin.netloc) and any(
            part in route.path for part in route_prefixes
        ):
            matched = matches(response.request.post_data or "")
            queued.append((response, matched))

    page.on("response", capture)
    return queued


def responses(page, queued, timeout, *, with_match=False):
    cursor, active = 0, False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        page.wait_for_timeout(200)
        while cursor < len(queued):
            response, matched = queued[cursor]
            cursor += 1
            active = active or matched
            if active:
                for packet in response_json(response):
                    yield (packet, matched) if with_match else packet


def hit_matches_source(hit, index):
    name = hit.get("_index") if isinstance(hit, dict) else None
    if not isinstance(name, str):
        return False
    backing = DATA_STREAM_BACKING.fullmatch(name) or ALERT_BACKING.fullmatch(name)
    names = (name, backing[1]) if backing else (name,)
    includes, excludes = [], []
    for part in index.split(","):
        if part.startswith("-"):
            excludes.append(part[1:])
        else:
            includes.append(part.removeprefix("+"))
    return (any(fnmatchcase(value, expression) for value in names for expression in includes)
            and not any(fnmatchcase(value, expression) for value in names for expression in excludes))


def search_ui(page, client, url, index, timeout):
    expected = index.split(",")[0].removeprefix("+")
    queue = observed(page, client, lambda body: expected in body, ("/internal/bsearch", "/internal/search"))
    navigate(page, client, url)
    # The application must commit the requested view before its background requests are meaningful.
    page.locator('[data-test-subj="discover-dataView-switch-link"]').wait_for(timeout=30000)
    hits, total, shards = None, None, None
    timed_out, terminated, clusters = False, False, {}
    for data, request_matched in responses(page, queue, timeout + 15, with_match=True):
        for node in objects(data):
            block, counts = node.get("hits"), node.get("_shards")
            if not isinstance(block, dict) or not isinstance(counts, dict) or not isinstance(block.get("hits"), list):
                continue
            if counts.get("successful") == 0 and counts.get("failed") == 0 and counts.get("total") != 0:
                continue
            batch = block["hits"]
            scoped_hits = bool(batch) and all(hit_matches_source(hit, index) for hit in batch)
            if not (scoped_hits or (request_matched and not batch)):
                continue
            timed_out = timed_out or node.get("timed_out") is True
            terminated = terminated or node.get("terminated_early") is True
            if isinstance(node.get("_clusters"), dict):
                clusters = node["_clusters"]
            if isinstance(block.get("total"), (dict, int)):
                total = block["total"]
            if scoped_hits:
                hits, shards = batch, counts
            elif shards is None:
                shards = counts
        if shards and ((hits is not None and total is not None) or total in (0, {"value": 0, "relation": "eq"})):
            break
    if shards is None or (hits is None and total not in (0, {"value": 0, "relation": "eq"})):
        raise Error("discover_unavailable", "Discover did not return verified document results for this view.")
    if total is None:
        total = {"value": len(hits), "relation": "gte"}
    return {"hits": {"hits": hits or [], "total": total}, "_shards": shards,
            "timed_out": timed_out, "terminated_early": terminated, "_clusters": clusters}


def esql_ui(page, client, url, query, timeout):
    def matches(body):
        try:
            payload = json.loads(body)
        except ValueError:
            return False
        return any(isinstance(value, str) and value == query
                   for node in objects(payload) for value in node.values())
    queue = observed(page, client, matches, ("/internal/search/esql",))
    navigate(page, client, url)
    for data in responses(page, queue, timeout + 10):
        for node in objects(data):
            if isinstance(node.get("error"), dict):
                raise Error("request_rejected", "Discover returned an ES|QL error.")
            if node.get("is_running") is not True and node.get("columns") and isinstance(node.get("values"), list):
                return parse_table(node, "discover")
    raise Error("discover_unavailable", "Discover did not return a verified ES|QL result.")
