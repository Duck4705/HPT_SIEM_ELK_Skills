import argparse
import http.client
import json
import sys
from contextlib import contextmanager

from .http import Client, protected_routes, verify
from .model import Error, identifier, invalid, parse_target
from .store import Store


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise invalid("Invalid CLI arguments. Run hpt-siem <command> --help.")


def bounded(low, high):
    def check(value):
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("Expected an integer.") from None
        if not low <= number <= high:
            raise argparse.ArgumentTypeError("Integer out of bounds.")
        return number
    return check


def target_options(parser, *, url=True):
    if url:
        selector = parser.add_mutually_exclusive_group(required=True)
        selector.add_argument("--url")
        selector.add_argument("--siem")
        parser.add_argument("--context", default="default")
        parser.add_argument("--allow-http", action="store_true")
    else:
        parser.add_argument("--siem", required=True)
    parser.add_argument("--space")


def parser():
    root = Parser(prog="hpt-siem", allow_abbrev=False,
                  description="Investigate a registered Kibana deployment using approved read-only APIs.")
    commands = root.add_subparsers(dest="command", required=True)

    def add(name, help_text):
        return commands.add_parser(name, help=help_text, allow_abbrev=False)

    register = add("register", "Register a canonical Kibana URL and authentication context.")
    register.add_argument("--url", required=True)
    register.add_argument("--id", required=True)
    register.add_argument("--context", default="default")
    register.add_argument("--allow-http", action="store_true")
    add("list-siems", "List registered deployments.")
    signin = add("login", "Open a dedicated browser and verify the new session.")
    target_options(signin)
    signin.add_argument("--browser", choices=("msedge", "chrome", "chromium"), default="msedge")
    signin.add_argument("--login-timeout", type=bounded(10, 900), default=180)
    target_options(add("status", "Verify the saved session and report the Kibana version when available."), url=False)
    add("health", "Read Kibana health without using a saved session.").add_argument("--siem", required=True)
    target_options(add("logout", "Remove the selected local session."), url=False)
    check = add("check-query", "Check query APIs, languages and read access without returning documents.")
    target_options(check, url=False)
    selection = check.add_mutually_exclusive_group()
    selection.add_argument("--index")
    selection.add_argument("--data-view-id")
    for name in ("list-spaces", "list-data-views", "list-data-streams"):
        command = add(name, "List metadata in the authorized deployment.")
        target_options(command, url=False)
        command.add_argument("--limit", type=bounded(1, 100), default=50)
        command.add_argument("--offset", type=bounded(0, 10000), default=0)
    listing = add("list-rules", "List detection rules in a Kibana space.")
    target_options(listing, url=False)
    listing.add_argument("--page", type=bounded(1, 10000), default=1)
    listing.add_argument("--limit", type=bounded(1, 100), default=10)
    detail = add("get-rule", "Read one detection rule by its exact identifier.")
    target_options(detail, url=False)
    rule_id = detail.add_mutually_exclusive_group(required=True)
    rule_id.add_argument("--id", help="Kibana-generated rule UUID.")
    rule_id.add_argument("--rule-id", help="Stable rule ID.")
    detail.add_argument("--include-query", action="store_true")
    for name in ("query", "list-alerts"):
        cmd = add(name, "Run a bounded search.")
        target_options(cmd)
        cmd.add_argument("--interactive", action="store_true", help="Open one login window if the API requires sign-in.")
        cmd.add_argument("--browser", choices=("msedge", "chrome", "chromium"), default="msedge")
        cmd.add_argument("--login-timeout", type=bounded(10, 900), default=180)
        time_range = cmd.add_mutually_exclusive_group(required=True)
        time_range.add_argument("--last-minutes", type=bounded(1, 44640))
        time_range.add_argument("--start", help="ISO 8601 timestamp with time zone. Requires --end.")
        cmd.add_argument("--end")
        cmd.add_argument("--limit", type=bounded(1, 100), default=10)
        cmd.add_argument("--offset", type=bounded(0, 9900), default=0)
        cmd.add_argument("--timeout", type=bounded(1, 25), default=10)
        cmd.add_argument("--source", action="append", default=[], metavar="FIELD")
        cmd.add_argument("--fields", action="append", default=[], metavar="FIELD")
        cmd.add_argument("--coverage-note", choices=("subset",))
        cmd.add_argument("--backend", choices=("auto", "api", "discover"), default="api",
                         help="REST only, Discover only, or REST first with Discover fallback.")
        if name == "query":
            source = cmd.add_mutually_exclusive_group(required=True)
            source.add_argument("--index")
            source.add_argument("--data-view-id")
            cmd.add_argument("--time-field")
            cmd.add_argument("--language", choices=("kql", "esql", "dsl", "lucene"))
            cmd.add_argument("--intent", choices=("filter", "stats"), default="filter")
            cmd.add_argument("--api", choices=("auto", "console", "agent-builder"), default="auto")
            expression = cmd.add_mutually_exclusive_group()
            expression.add_argument("--dsl-file", help="JSON file or - for stdin. Supported top-level key is query.")
            expression.add_argument("--expression", help="KQL/Lucene filter or ES|QL pipeline after FROM.")
        else:
            cmd.add_argument("--api", choices=("auto", "detection-engine", "console"), default="auto")
            cmd.add_argument("--severity", action="append", choices=("low", "medium", "high", "critical"))
            cmd.add_argument("--workflow-status", action="append", choices=("open", "acknowledged", "closed"))
            cmd.add_argument("--alert-index")
            cmd.add_argument("--alert-id", help="Match the exact Elasticsearch document ID of a Security Alert.")
            cmd.add_argument("--alert-schema", choices=("modern", "legacy"), default="modern")
    return root


@contextmanager
def session(store, target):
    with store.locked(target.lock_key):
        generation, record = store.load(target)
        if not record:
            raise Error("login_required", "No local session is registered for this SIEM. Run login first.")
        with Client(target, record["cookies"]) as client:
            if not client.records():
                raise Error("login_required", "The local session has expired. Run login again.")
            before = client.records()
            try:
                yield client, record
            finally:
                after = client.records()
                if before != after:
                    store.save(target, generation, {**record, "cookies": after})


def browser_login(args, store, target, space):
    from .browser import login
    return login(store, target, space, args.browser, args.login_timeout)


def execute(args, store):
    command = args.command
    if command == "register":
        return store.register(parse_target(args.url, args.id, args.context, args.allow_http)).public()
    if command == "list-siems":
        return {"siems": store.list()}
    if getattr(args, "url", None):
        requested = parse_target(args.url, context=args.context, allow_http=args.allow_http)
        target = store.register(requested, use_existing_id=True)
        default_space = requested.space
    else:
        if getattr(args, "allow_http", False) or getattr(args, "context", "default") != "default":
            raise invalid("Set registration options with --url or register.")
        target = store.get(identifier(args.siem))
        default_space = target.space
    if command == "health":
        from .metadata import health
        with Client(target) as client:
            return health(client)
    space = identifier(args.space) if args.space else default_space
    if command == "login":
        return browser_login(args, store, target, space)
    if command == "logout":
        if args.space:
            raise invalid("Logout applies to the whole auth context. Omit --space.")
        return {"siem": target.id, "localSessionRemoved": store.logout(target), "serverRevoked": False}
    if command in {"query", "list-alerts"}:
        from .search import run_query, search_options, time_bounds
        options = search_options(args)
        try:
            with session(store, target) as (client, _):
                return run_query(client, space, args, options)
        except Error as exc:
            if exc.code != "login_required" or not args.interactive:
                raise
        browser_login(args, store, target, space)
        if args.last_minutes:
            options = time_bounds(args), *options[1:]
        with session(store, target) as (client, _):
            return run_query(client, space, args, options)
    from .metadata import metadata
    with session(store, target) as (client, record):
        if command in {"list-rules", "get-rule"}:
            from .rules import rules
            return rules(client, space, args)
        if command in {"check-query", "list-data-streams"}:
            from .capabilities import check_query, list_data_streams
            return check_query(client, space, args) if command == "check-query" else list_data_streams(client, space, args)
        if command == "status":
            routes = record["probes"]
            if space != record["space"]:
                with Client(target) as anonymous:
                    routes = protected_routes(anonymous, space)
            route = verify(client, space, routes)
            return metadata(client, space, args, route)
        return metadata(client, space, args)


def operate(build_args):
    # Suppress raw wire logging even if imported into a host that enabled http.client debugging.
    http.client.HTTPConnection.debuglevel = 0
    try:
        result = execute(build_args(), Store())
        code = "ok"
        if result.get("isPartial"):
            code = "partial_results"
        elif result.get("coverageStatus") == "no_shards":
            code = "no_shards"
        envelope = {"ok": True, "code": code, "data": result}
        json.dumps(envelope, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    except Error as exc:
        envelope = {"ok": False, "code": exc.code, "message": str(exc)}
        if exc.details:
            envelope["details"] = exc.details
    except KeyboardInterrupt:
        envelope = {"ok": False, "code": "cancelled", "message": "The operation was cancelled."}
    except Exception:
        envelope = {"ok": False, "code": "internal_error",
                    "message": "The operation failed locally. Check installation and local storage permissions."}
    return envelope


def main():
    envelope = operate(lambda: parser().parse_args())
    print(json.dumps(envelope, ensure_ascii=True, separators=(",", ":"), allow_nan=False))
    return 0 if envelope["ok"] else 130 if envelope["code"] == "cancelled" else 1


if __name__ == "__main__":
    raise SystemExit(main())
