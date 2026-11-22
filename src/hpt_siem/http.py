import json
import math
import os
import re
import time
from http.cookiejar import Cookie, DefaultCookiePolicy
from urllib.parse import urljoin, urlsplit

import requests
from requests.cookies import RequestsCookieJar, extract_cookies_to_jar, get_cookie_header

from .model import Error, segment


ROUTES = {
    "version": ("/api/status", False),
    "identity": ("/api/security/me", False),
    "spaces": ("/api/spaces/space", False),
    "views": ("/api/data_views", True),
    "view": ("/api/data_views/data_view/", True),
    "search": ("/api/console/proxy", True),
    "esql": ("/api/console/proxy", True),
    "esql_tool": ("/api/agent_builder/tools/_execute", True),
    "alert_search": ("/api/detection_engine/signals/search", True),
    "rules_list": ("/api/detection_engine/rules/_find", True),
    "rule_detail": ("/api/detection_engine/rules", True),
    "data_streams": ("/api/console/proxy", True),
    "fleet_data_streams": ("/api/fleet/data_streams", True),
}
CONSOLE_ROUTES = {"search", "esql", "data_streams"}
INDEX = re.compile(r"[a-z0-9_.*+-]+(?:,[a-z0-9_.*+-]+){0,15}")
MAX_RESPONSE = 4 * 1024 * 1024


def validate_index(index):
    if not isinstance(index, str) or len(index) > 512 or not INDEX.fullmatch(index):
        raise Error("invalid_input", "Use a local index, alias or index pattern without URL syntax.")
    if any(part in {".", "..", "-", "+"} for part in index.split(",")):
        raise Error("invalid_input", "Invalid index expression.")
    return index


def cookie_record(cookie):
    return {
        "name": cookie.name, "value": cookie.value, "domain": cookie.domain,
        "host_only": not cookie.domain_specified, "path": cookie.path,
        "secure": cookie.secure, "expires": cookie.expires,
    }


class Client:
    def __init__(self, target, records=()):
        self.target = target
        self.host = urlsplit(target.origin).hostname
        self.jar = RequestsCookieJar(policy=DefaultCookiePolicy(
            strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain))
        self.adapter = requests.adapters.HTTPAdapter()
        for record in records:
            self.add_cookie(record)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.adapter.close()

    def add_cookie(self, record):
        domain = record["domain"].lower()
        suffix = domain.lstrip(".")
        host_only = record["host_only"]
        if suffix != self.host and (host_only or not self.host.endswith("." + suffix)):
            return
        expires = record["expires"]
        if expires is not None and expires <= time.time():
            return
        path = record["path"]
        if not path.startswith("/"):
            return
        self.jar.set_cookie(Cookie(
            0, record["name"], record["value"], None, False, domain, not host_only,
            domain.startswith("."), path, True, record["secure"], expires,
            expires is None, None, None, {}))

    def records(self):
        self.jar.clear_expired_cookies()
        return sorted((cookie_record(cookie) for cookie in self.jar),
                      key=lambda item: (item["domain"], item["path"], item["name"]))

    def call(self, route, space="default", *, view_id=None, index=None, body=None, query_params=None, timeout=10):
        endpoint, scoped = ROUTES[route]
        if route == "view":
            endpoint += segment(view_id)
        path = (self.target.scope(space) if scoped else "") + endpoint
        method, params = "GET", None
        if route == "search":
            method, params = "POST", {
                "method": "POST",
                "path": validate_index(index) + "/_search?allow_partial_search_results=true",
            }
        elif route == "esql":
            method, params = "POST", {"method": "POST", "path": "_query?format=json"}
        elif route == "esql_tool":
            method = "POST"
            body = {"tool_id": "platform.core.execute_esql", "tool_params": {"query": body["query"]}}
        elif route == "data_streams":
            method, params = "POST", {"method": "GET", "path": "_data_stream"}
        elif route == "alert_search":
            method = "POST"
        elif route in {"rules_list", "rule_detail"}:
            params = query_params
        url = self.target.prefix + path
        prepared = requests.Request(method, url, params=params, json=body, headers={
            "Accept": "application/json", "kbn-xsrf": "hpt-siem",
        }).prepare()
        if prepared.url.split("?", 1)[0] != url:
            raise Error("invalid_input", "The normalized URL does not match the approved route.")
        cookie = get_cookie_header(self.jar, prepared)
        if cookie:
            if self.target.origin.startswith("http:") and not self.target.allow_http:
                raise Error("insecure_transport", "Credentialed HTTP requires explicit --allow-http at registration.")
            prepared.headers["Cookie"] = cookie
        deadline = time.monotonic() + timeout
        try:
            with self.adapter.send(prepared, stream=True, timeout=(min(5, timeout), timeout),
                                   verify=os.environ.get("HPT_SIEM_CA_BUNDLE") or True, proxies={}) as response:
                status = response.status_code
                layer = "kibana"
                if status == 200 and route in CONSOLE_ROUTES:
                    upstream = response.headers.get("x-console-proxy-status-code", "")
                    if re.fullmatch(r"[1-5][0-9]{2}", upstream):
                        status, layer = int(upstream), "elasticsearch"
                details = {"layer": layer, "httpStatus": status}
                if 300 <= response.status_code < 400:
                    self.redirect(response, url, space)
                if status in {401, 403, 404, 405}:
                    if status in {401, 403}:
                        extract_cookies_to_jar(self.jar, prepared, response.raw)
                    code = {401: "login_required" if layer == "kibana" else "permission_denied",
                            403: "permission_denied", 404: "route_not_found",
                            405: "unsupported_capability"}[status]
                    raise Error(code, "The approved API rejected the request or is unavailable.", details)
                if status != 200:
                    if route in CONSOLE_ROUTES | {"esql_tool", "alert_search"} and status in {400, 500, 502, 503}:
                        self.search_error(response, deadline, details, route)
                    code = {400: "request_rejected", 408: "timeout", 429: "rate_limited", 501: "unsupported_capability",
                            502: "upstream_error", 503: "upstream_error", 504: "timeout"}.get(status, "upstream_error")
                    raise Error(code, f"The approved API returned HTTP {status}.", details)
                payload = read_json(response, deadline)
                extract_cookies_to_jar(self.jar, prepared, response.raw)
                return payload
        except requests.exceptions.SSLError:
            raise Error("tls_error", "TLS verification failed. Configure the approved private CA if needed.") from None
        except requests.exceptions.Timeout:
            raise Error("timeout", "The approved API did not respond within the configured timeout.") from None
        except (requests.exceptions.RequestException, OSError):
            raise Error("network_unreachable", "Could not reach the approved API. Check VPN, routing and timeout.") from None
        except (ValueError, UnicodeError, RecursionError):
            raise Error("invalid_response", "The approved API returned invalid JSON.") from None

    def search_error(self, response, deadline, details, route):
        try:
            data = read_json(response, deadline)
        except (Error, ValueError, UnicodeError, RecursionError):
            return
        error = data.get("error") if isinstance(data, dict) else None
        message = data.get("message") if isinstance(data, dict) else None
        if details["httpStatus"] == 400 and isinstance(message, str) and (
            "this api is not available in the current configuration" in message.lower()
            or ("access to internal" in message.lower() and "api" in message.lower())
        ):
            raise Error("unsupported_capability", "Kibana does not expose this API to external clients.", details)
        if route == "alert_search" and details["httpStatus"] == 400 and isinstance(message, str) and re.fullmatch(
            r"""\[request body\]: invalid keys ["']from["']\.?""", message.strip(), re.I
        ):
            raise Error("unsupported_capability", "This Detection Engine endpoint does not accept an offset.", details)
        if isinstance(error, dict):
            details["layer"] = "elasticsearch" if "root_cause" in error else details["layer"]
            causes = error.get("root_cause")
            causes = causes if isinstance(causes, list) else []
            for node in [error, error.get("caused_by"), *causes[:10]]:
                reason = node.get("reason", "") if isinstance(node, dict) else ""
                if isinstance(reason, str) and re.search(r"(?:unknown query|no \[query\] registered for) \[kql\]", reason, re.I):
                    raise Error("unsupported_language", "Elasticsearch does not recognize the native KQL query clause.", details)
        failures = error.get("failed_shards") if isinstance(error, dict) else None
        if isinstance(failures, list) and failures:
            secrets = [cookie["value"] for cookie in self.records() if cookie["value"]]
            raise Error("search_failed", "Search failed. Review the shard failure types.", {
                **details,
                "reportedShardFailureGroups": len(failures),
                "shardFailures": [failure_info(item, secrets) for item in failures[:20] if isinstance(item, dict)],
            })

    def redirect(self, response, url, space):
        try:
            destination = urlsplit(urljoin(url, response.headers.get("Location", "")))
            same_origin = destination.scheme + "://" + destination.netloc == self.target.origin
            login_paths = {self.target.base_path + scope + page
                           for scope in ("", self.target.scope(space))
                           for page in ("/login", "/security/login")}
            if same_origin and destination.path in login_paths:
                raise Error("login_required", "The approved API requires a Kibana login.")
        except ValueError:
            pass
        raise Error("redirect_blocked", "The approved API returned an unexpected redirect.")


def reject_constant(_):
    raise ValueError


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError
    return number


def read_json(response, deadline):
    if response.headers.get("Content-Type", "").lower().split(";", 1)[0].strip() != "application/json":
        raise Error("unsupported_capability", "The approved API did not return JSON.")
    data = bytearray()
    for chunk in response.iter_content(8192):
        data.extend(chunk)
        if len(data) > MAX_RESPONSE:
            raise Error("response_too_large", "Narrow the fields, page size or time range.")
        if time.monotonic() > deadline:
            raise Error("timeout", "The approved API took too long to return a response.")
    return json.loads(data, parse_constant=reject_constant, parse_float=finite_float)


def failure_info(item, secrets):
    reason = item.get("reason")
    info = {"index": item.get("index"), "shard": item.get("shard"),
            "type": reason.get("type") if isinstance(reason, dict) else None}
    for name in ("index", "type"):
        value = info[name]
        if (not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.+-]{1,255}", value)
                or any(secret in value for secret in secrets)):
            info[name] = None
    if type(info["shard"]) is not int:
        info["shard"] = None
    return info


def view_summary(value):
    return (isinstance(value, dict) and all(isinstance(value.get(key), str) and value[key]
                                            for key in ("id", "title")))


def check_probe(route, payload):
    if route == "identity":
        return (isinstance(payload, dict) and isinstance(payload.get("username"), str)
                and bool(payload["username"]) and isinstance(payload.get("roles"), list))
    return (isinstance(payload, dict) and isinstance(payload.get("data_view"), list)
            and all(view_summary(view) for view in payload["data_view"]))


def protected_routes(client, space):
    routes = []
    for route in ("views", "identity"):
        client.jar.clear()
        try:
            client.call(route, space, timeout=5)
        except Error as exc:
            if exc.code in {"login_required", "permission_denied"}:
                routes.append(route)
            elif exc.code in {"network_unreachable", "tls_error"}:
                raise
    if not routes:
        raise Error("unsupported_capability", "Could not establish an anonymous-access denial for any supported probe.")
    return routes


def verify(client, space, routes):
    errors = []
    for route in routes:
        try:
            if check_probe(route, client.call(route, space, timeout=5)):
                return route
            errors.append("unsupported_capability")
        except Error as exc:
            if exc.code in {"network_unreachable", "tls_error", "timeout"}:
                raise
            errors.append(exc.code)
    for code, message in (
        ("permission_denied", "Kibana denied access to a protected verification API."),
        ("login_required", "Kibana requires a fresh login."),
        ("unsupported_capability", "No protected verification API returned the expected authenticated JSON."),
    ):
        if code in errors or code == "unsupported_capability":
            raise Error(code, message)
