import os
import sys
import time

from .http import Client, ROUTES, protected_routes, verify
from .model import Error


def disable_browser_debugging():
    for name in ("DEBUG", "PWDEBUG"):
        os.environ.pop(name, None)


def login(store, target, space, channel, timeout):
    if target.origin.startswith("http:") and not target.allow_http:
        raise Error("insecure_transport", "Credentialed HTTP requires explicit --allow-http at registration.")
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise Error("missing_dependency", "Install the project with its [login] extra first.") from None

    generation = store.generation(target)
    with Client(target) as anonymous:
        routes = protected_routes(anonymous, space)
    disable_browser_debugging()
    home = target.prefix + target.scope(space) + "/app/home"
    urls = [home, *(target.prefix + (target.scope(space) if scoped else "") + path
                    for name, (path, scoped) in ROUTES.items() if name != "view")]
    opened = False
    closed_early = False
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                channel=None if channel == "chromium" else channel, headless=False, timeout=15000)
            try:
                context = browser.new_context(accept_downloads=False)
                page = context.new_page()
                opened = True
                print("Login window opened. Complete sign-in in the browser.", file=sys.stderr, flush=True)
                deadline = time.monotonic() + timeout
                page.goto(home, wait_until="commit", timeout=min(15000, timeout * 1000))
                previous = None
                next_probe = 0
                last_error = None
                while time.monotonic() < deadline:
                    if not browser.is_connected() or not context.pages:
                        raise Error("browser_closed", "The login window closed before the session was saved.")
                    records = [{
                        "name": item["name"], "value": item["value"], "domain": item["domain"],
                        "host_only": not item["domain"].startswith("."), "path": item["path"],
                        "secure": item["secure"], "expires": None if item["expires"] < 0 else int(item["expires"]),
                    } for item in context.cookies(urls)]
                    if records and (records != previous or time.monotonic() >= next_probe):
                        previous = records
                        next_probe = time.monotonic() + 3
                        with Client(target, records) as candidate:
                            try:
                                probe = verify(candidate, space, routes)
                            except Error as exc:
                                last_error = exc
                            else:
                                with store.locked(target.lock_key):
                                    context.cookies(urls)
                                    if not browser.is_connected() or not context.pages:
                                        raise Error("browser_closed", "The login window closed before the session was saved.")
                                    if time.monotonic() >= deadline:
                                        break
                                    store.save(target, generation, {"cookies": candidate.records(),
                                               "space": space, "probes": routes}, replace=True)
                                return {"siem": target.id, "space": space, "authenticated": True, "probe": probe}
                    time.sleep(1)
                result = "login_timeout"
                if last_error and last_error.code in {"network_unreachable", "tls_error", "permission_denied"}:
                    result = last_error.code
                raise Error(result, "The login session could not be verified before the deadline. Any prior session was retained.")
            except PlaywrightError:
                closed_early = opened and (not browser.is_connected() or not context.pages)
                raise
            finally:
                if browser.is_connected():
                    try:
                        browser.close()
                    except PlaywrightError:
                        pass
    except PlaywrightError:
        if closed_early:
            raise Error("browser_closed", "The login window closed before the session was saved.") from None
        code = "browser_login_failed" if opened else "browser_unavailable"
        raise Error(code, "Could not complete the isolated browser flow. Check browser, VPN and TLS settings.") from None
