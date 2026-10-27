"""URL canonicalization, structural signatures and parameter type inference.

Two URLs that mean the same thing must map to one key (canonicalize_url), and
two endpoints that differ only by an id in the path must collapse to one
structural signature (path_template + make_signature) or the crawler never
terminates on a large catalog (/item/1, /item/2, /item/3, ...).
"""
from __future__ import annotations
import hashlib
import posixpath
import re
from urllib.parse import urlsplit, urlunsplit, urljoin, parse_qsl, urlencode

TRACKING = re.compile(r"^(utm_.*|fbclid|gclid|mc_eid|mc_cid|_ga|ref_src)$", re.I)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
INT_RE = re.compile(r"^-?\d+$")
HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def canonicalize_url(url: str, base: str | None = None) -> str:
    """Lowercase host, drop default port and fragment, resolve relative/dot paths,
    sort query parameters, drop tracking parameters."""
    if base:
        url = urljoin(base, url)
    p = urlsplit(url)
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower()
    port = p.port
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = p.path or "/"
    trailing = path.endswith("/") and len(path) > 1
    path = posixpath.normpath(path)
    if path.startswith("//"):
        path = "/" + path.lstrip("/")
    if trailing and not path.endswith("/"):
        path += "/"
    q = sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not TRACKING.match(k))
    return urlunsplit((scheme, netloc, path, urlencode(q), ""))


def segment_type(seg: str) -> str | None:
    if INT_RE.match(seg):
        return "int"
    if UUID_RE.match(seg):
        return "uuid"
    if HEX_RE.match(seg):
        return "hex"
    return None


def path_template(path: str) -> str:
    """Collapse numeric / UUID / long-hex path segments to placeholders so
    /item/1 and /item/2 share one structural signature."""
    out = []
    for seg in path.split("/"):
        t = segment_type(seg)
        out.append("{%s}" % t if t else seg)
    return "/".join(out)


def infer_type(value: str) -> str:
    if value is None or value == "":
        return "text"
    if INT_RE.match(value):
        return "int"
    if UUID_RE.match(value):
        return "uuid"
    if value.lower() in ("true", "false"):
        return "boolean"
    if EMAIL_RE.match(value):
        return "email"
    return "text"


def make_signature(method: str, netloc: str, template: str, param_names) -> str:
    """Structural fingerprint: method + path template + sorted parameter names."""
    raw = f"{method.upper()}|{netloc}|{template}|{','.join(sorted(param_names))}"
    return hashlib.sha1(raw.encode()).hexdigest()
