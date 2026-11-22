import hashlib
import re
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit


class Error(Exception):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.details = details


def invalid(message):
    return Error("invalid_input", message)


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9_-]{1,64}", value):
        raise invalid("Use an identifier of 1–64 lowercase letters, digits, underscores or hyphens.")
    return value


def segment(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", value) or value in {".", ".."}:
        raise invalid("Unsupported URL path segment.")
    return value


@dataclass(frozen=True)
class Target:
    id: str
    origin: str
    base_path: str
    space: str
    context: str
    allow_http: bool

    @property
    def prefix(self):
        return self.origin + self.base_path

    @property
    def home(self):
        return self.prefix + self.scope(self.space) + "/app/home"

    @property
    def lock_key(self):
        return hashlib.sha256((self.prefix + "\n" + self.context).encode()).hexdigest()

    @staticmethod
    def scope(space):
        return "" if space == "default" else "/s/" + identifier(space)

    def public(self):
        return asdict(self)


def parse_target(url, siem_id=None, context="default", allow_http=False):
    if any(ord(char) < 33 or ord(char) > 126 for char in url) or "\\" in url:
        raise invalid("Use a canonical ASCII Kibana URL.")
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise invalid("Invalid Kibana URL.") from None
    if (parts.scheme not in {"http", "https"} or not host or not re.fullmatch(r"[a-z0-9.:-]+", host)
            or parts.username is not None or parts.password is not None or port == 0):
        raise invalid("Use an HTTP(S) Kibana URL without credentials.")
    host = "[" + host + "]" if ":" in host else host
    default_port = 80 if parts.scheme == "http" else 443
    origin = f"{parts.scheme}://{host}" + (f":{port}" if port and port != default_port else "")
    if "//" in parts.path:
        raise invalid("Ambiguous Kibana path.")
    path = [segment(piece) for piece in parts.path.strip("/").split("/") if piece]
    space = "default"
    for i, piece in enumerate(path):
        if piece == "s" and i + 1 < len(path) and (i + 2 == len(path) or path[i + 2] == "app"):
            space = identifier(path[i + 1])
            path = path[:i]
            break
        if piece in {"app", "login"}:
            path = path[:i]
            break
    base_path = "/" + "/".join(path) if path else ""
    if len(base_path) > 512:
        raise invalid("Kibana base path is too long.")
    identifier(context)
    digest = hashlib.sha256(f"{origin}{base_path}\n{context}".encode()).hexdigest()
    return Target(identifier(siem_id) if siem_id else "siem-" + digest[:16],
                  origin, base_path, space, context, allow_http and parts.scheme == "http")
