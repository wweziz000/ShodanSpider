#!/usr/bin/env bash
# ShodanSpider 7.0.0-priority -- independent single-file Bash launcher.
# Do not source; run with bash shodan_spider-v7.sh ...
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    printf '%s\n' 'Error: run this file with bash; do not source it.' >&2
    return 1
fi
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Error: Python 3.10+ is required.' >&2
    exit 1
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
    printf '%s\n' 'Error: Python 3.10+ is required.' >&2
    exit 1
fi
export PYTHONIOENCODING=utf-8
exec python3 - "$@" <<'SHODAN_SPIDER_V7_PYTHON'
#!/usr/bin/env python3
"""ShodanSpider 7.0.0-priority. See README_AR.md."""
from __future__ import annotations

"""Strict, standard-library parser for Shodan's public facet HTML.

The live structure inspected on 2026-10-23 is a facets-card whose name,
value and bar elements are siblings. No scripts are executed and search
links are used only as data; the crawler builds its own requests.
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser
import ipaddress
import re
from urllib.parse import parse_qs, unquote, urljoin, urlsplit


SUPPORTED_FACETS = frozenset(("country", "city", "asn", "ip", "port", "version", "product", "org", "os"))
_FACET_TEXT_FIELDS = frozenset(("city", "version", "product", "org", "os"))


class FacetParseError(ValueError):
    """The response cannot safely be interpreted as the requested facet."""


@dataclass
class FacetRow:
    value: str
    count: int | None
    label: str


@dataclass
class FacetPage:
    facet: str
    rows: list[FacetRow]
    total: int | None
    warnings: list[str]
    explicit_empty: bool


@dataclass
class _FacetNode:
    tag: str
    attrs: dict[str, str]
    children: list = field(default_factory=list)
    parent: _FacetNode | None = field(default=None, repr=False)
    hidden: bool = False

    def classes(self) -> set[str]:
        return set(self.attrs.get("class", "").split())

    def walk(self):
        stack = [self]
        while stack:
            node = stack.pop()
            if node.hidden:
                continue
            yield node
            stack.extend(reversed([c for c in node.children if isinstance(c, _FacetNode)]))

    def text(self) -> str:
        pieces = []
        pending = [self]
        while pending:
            item = pending.pop()
            if isinstance(item, str):
                pieces.append(item)
            elif not item.hidden:
                pending.extend(reversed(item.children))
        return "".join(pieces).strip()


class _FacetDOM(HTMLParser):
    _void = frozenset("area base br col embed hr img input link meta param source track wbr".split())
    _hidden = frozenset(("script", "style", "noscript", "template"))

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _FacetNode("document", {})
        self.stack = [self.root]
        self.node_count = 0

    def handle_starttag(self, tag, attrs):
        self.node_count += 1
        if self.node_count > 200000 or len(self.stack) > 256:
            raise FacetParseError("[HTML_LIMIT] Facet HTML is too deeply nested or has too many elements.")
        values = {k: v or "" for k, v in attrs}
        parent = self.stack[-1]
        node = _FacetNode(tag, values, parent=parent,
                          hidden=parent.hidden or tag in self._hidden or "hidden" in values)
        parent.children.append(node)
        if tag not in self._void:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self._void:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if not self.stack[-1].hidden:
            self.stack[-1].children.append(data)


def _facet_count(text: str) -> int | None:
    """Only exact whole counts, never rounded 1.2K/percent/bar widths."""
    text = text.strip().replace("\u00a0", " ").replace("\u202f", " ")
    if len(text) > 40:
        return None
    if re.fullmatch(r"[0-9]+", text):
        return int(text)
    if re.fullmatch(r"[0-9]{1,3}(?:,[0-9]{3})+", text):
        return int(text.replace(",", ""))
    if re.fullmatch(r"[0-9]{1,3}(?: [0-9]{3})+", text):
        return int(text.replace(" ", ""))
    return None


def _facet_query_tokens(query: str) -> list[str]:
    """Split on whitespace outside double quotes; apostrophes stay literal."""
    result, token = [], []
    quoted = escaped = False
    for char in query:
        if escaped:
            token.append(char)
            escaped = False
        elif char == "\\" and quoted:
            token.append(char)
            escaped = True
        elif char == '"':
            token.append(char)
            quoted = not quoted
        elif char.isspace() and not quoted:
            if token:
                result.append("".join(token))
                token = []
        else:
            token.append(char)
    if token:
        result.append("".join(token))
    return result


def _facet_filter_value(query: str, facet: str) -> str | None:
    result = None
    for token in _facet_query_tokens(query):
        name, sep, value = token.partition(":")
        if sep and name.lower() == facet:
            if value.startswith('"'):
                if not value.endswith('"') or len(value) < 2:
                    continue
                value = re.sub(r'\\([\\"])', r'\1', value[1:-1])
            result = value
    return result


def _facet_link_value(node: _FacetNode, facet: str) -> str | None:
    for child in node.walk():
        if child.tag != "a" or not child.attrs.get("href"):
            continue
        try:
            url = urlsplit(urljoin("https://www.shodan.io/", child.attrs["href"]))
            if url.scheme != "https" or url.hostname not in ("www.shodan.io", "shodan.io"):
                continue
            if url.username or url.password or url.port not in (None, 443):
                continue
            if url.path.rstrip("/") in ("/search", "/search/facet"):
                query_values = parse_qs(url.query).get("query", [])
                if query_values:
                    value = _facet_filter_value(query_values[-1], facet)
                    if value is not None:
                        return value
            if facet == "ip" and url.path.startswith("/host/"):
                return unquote(url.path[len("/host/"):].strip("/"))
        except ValueError:
            continue
    return None


def _facet_normalize(value: str, facet: str) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 500 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return None
    if facet == "country":
        return value.upper() if re.fullmatch(r"[A-Za-z]{2}", value) else None
    if facet == "asn":
        # Shodan currently returns distinct 'as123' and '123' buckets.
        # Preserve their spelling; adding AS would silently merge buckets.
        return value if re.fullmatch(r"(?:[Aa][Ss])?[0-9]{1,10}", value) else None
    if facet == "port":
        # Port zero is reserved, but remains valid numeric facet data.
        # These values are search constraints, never connection targets.
        if not re.fullmatch(r"[0-9]{1,5}", value):
            return None
        number = int(value)
        return str(number) if 0 <= number <= 65535 else None
    if facet == "ip":
        if "%" in value:
            return None
        if value.startswith("[") and value.endswith("]"):
            value = value[1:-1]
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None
    return value if facet in _FACET_TEXT_FIELDS else None


def _facet_label(node: _FacetNode) -> str:
    for tag in ("strong", "a"):
        labels = [n.text() for n in node.walk() if n.tag == tag and n.text()]
        if labels:
            return labels[0]
    return node.text()


def parse_facet_html(html: str, facet: str, query: str | None = None, *,
                     allow_missing_facet: bool = False) -> FacetPage:
    if not isinstance(facet, str) or facet not in SUPPORTED_FACETS:
        raise FacetParseError("[FACET_UNSUPPORTED] Unsupported facet name.")
    dom = _FacetDOM()
    try:
        dom.feed(html)
        dom.close()
    except FacetParseError:
        raise
    except (ValueError, AssertionError, RecursionError) as exc:
        raise FacetParseError("[HTML_PARSE] Invalid facet HTML: " + type(exc).__name__) from None
    nodes = list(dom.root.walk())
    titles = " ".join(n.text() for n in nodes if n.tag == "title").lower()
    if re.search(r"\b(log[ -]?in|sign[ -]?in)\b", titles) or any(
            n.tag == "input" and n.attrs.get("type", "").lower() == "password" for n in nodes):
        raise FacetParseError("[LOGIN] A login page was returned instead of facet results.")
    lower_html = html.lower()
    if any(x in titles for x in ("just a moment", "attention required", "access denied", "captcha")) or any(
            x in lower_html for x in ("cf-chl-", 'id="challenge-form"', "id='challenge-form'")):
        raise FacetParseError("[ACCESS] Browser verification or access denial was returned instead of results.")
    warnings: list[str] = []
    selected_facets = []
    facet_forms = []
    for node in nodes:
        if node.tag == "select" and node.attrs.get("name") == "facet":
            selected_facets.extend(n.attrs.get("value", n.text()) for n in node.walk()
                                   if n.tag == "option" and "selected" in n.attrs)
            parent = node.parent
            while parent is not None and parent.tag != "form":
                parent = parent.parent
            if parent is not None:
                facet_forms.append(parent)
    if any(selected != facet for selected in selected_facets):
        raise FacetParseError("[FACET_MISMATCH] Response selected a different facet than requested.")
    if query is not None:
        echoed_queries = [n.attrs.get("value", "") for form in facet_forms for n in form.walk()
                          if n.tag == "input" and n.attrs.get("name") == "query"]
        if any(_facet_query_tokens(echo) != _facet_query_tokens(query) for echo in echoed_queries):
            raise FacetParseError("[QUERY_MISMATCH] Response query differs from the requested branch.")

    # Prefer actual Total headings, not a navigation counter or an IP string.
    total_values = []
    for node in nodes:
        if node.tag not in ("h1", "h2", "h3", "h4", "h5", "h6", "p", "span", "div"):
            continue
        text = " ".join(node.text().split())
        if len(text) > 80:
            continue
        match = re.fullmatch(r"(?:[/# ]*)Total\s*:\s*([0-9][0-9, \u00a0\u202f]*)", text, re.I)
        if match:
            count = _facet_count(match.group(1))
            if count is not None:
                total_values.append(count)
    total = total_values[0] if total_values else None
    if len(set(total_values)) > 1:
        warnings.append("Conflicting TOTAL counters were present; coverage is uncertain.")
        total = max(total_values)

    cards = [n for n in nodes if n.classes() & {"facets-card", "facet-results", "facet-table"}
             or n.attrs.get("id") in ("facet-results", "facet-table")]
    # Support a conventional facet table while avoiding unrelated page tables.
    if not cards and selected_facets:
        cards = [n for n in nodes if n.tag == "table"]
    pairs: list[tuple[_FacetNode, _FacetNode | None]] = []
    for card in cards:
        pending = None
        relevant = [n for n in card.walk() if n is not card and
                    n.classes() & {"name", "facet-name", "value", "facet-count"}]
        if relevant:
            for node in relevant:
                if node.classes() & {"name", "facet-name"}:
                    if pending is not None:
                        pairs.append((pending, None))
                    pending = node
                elif pending is not None:
                    pairs.append((pending, node))
                    pending = None
            if pending is not None:
                pairs.append((pending, None))
        else:
            for row in card.walk():
                if row.tag != "tr":
                    continue
                cells = [n for n in row.children if isinstance(n, _FacetNode) and n.tag == "td"]
                if cells:
                    pairs.append((cells[0], cells[1] if len(cells) > 1 else None))

    rows: list[FacetRow] = []
    seen: dict[str, FacetRow] = {}
    rejected = 0
    for name_node, count_node in pairs:
        label = _facet_label(name_node)
        linked_value = _facet_link_value(name_node, facet)
        raw_value = linked_value
        if raw_value is None:
            for key in ("data-value", "data-facet-value", "data-country-code"):
                if name_node.attrs.get(key):
                    raw_value = name_node.attrs[key]
                    break
        if raw_value is None:
            raw_value = label
        value = _facet_normalize(raw_value, facet)
        if value is None:
            rejected += 1
            continue
        count = _facet_count(count_node.text()) if count_node is not None else None
        if count is None:
            warnings.append("Missing or non-integer count for facet value " + repr(value) + ".")
        if value in seen:
            warnings.append("Duplicate facet value " + repr(value) + "; it is visited once and counts are not added.")
            continue
        row = FacetRow(value, count, label)
        rows.append(row)
        seen[value] = row
    if rejected:
        warnings.append(str(rejected) + " facet row(s) had unrecognized values and were skipped; coverage is uncertain.")
    visible = " ".join(dom.root.text().split()).lower()
    empty_pattern = re.compile(r"\b(?:no results? (?:found|matched)|0 results?\b)", re.I)
    empty_message = bool(empty_pattern.search(visible)) or any(
        empty_pattern.search(" ".join(node.text().split())) for node in nodes
        if node.tag in ("p", "h1", "h2", "h3", "h4", "h5", "h6"))
    recognizable = bool(cards or selected_facets or "facet analysis" in titles)
    explicit_empty = (total == 0 or (total is None and empty_message)) and not rows and recognizable and not rejected
    if (allow_missing_facet and facet in ("asn", "port", "version", "product", "org", "os")
            and total is not None and total > 0 and selected_facets and cards
            and not rows and not pairs and not rejected and not empty_message
            and all(not card.text() for card in cards)):
        warnings.append("No buckets for this field; query is not empty.")
        return FacetPage(facet, [], total, list(dict.fromkeys(warnings)), False)
    if rows and (total == 0 or empty_message):
        warnings.append("The page contains rows together with a zero-results marker; counters are inconsistent.")
    if not rows and not explicit_empty:
        raise FacetParseError("[LAYOUT] No recognizable " + facet + " facet rows or explicit empty result were found. "
                              "The page may be restricted or its HTML layout may have changed.")
    if rows and total is None:
        warnings.append("No exact TOTAL counter was found; page coverage cannot be checked.")
    return FacetPage(facet, rows, total, list(dict.fromkeys(warnings)), explicit_empty)


"""Small HTTP parsing helpers shared by the HTML and official API clients.

These helpers do not send requests or sleep. Retry limits and waiting belong
to the crawler, including refusing a server wait that exceeds its budget.
"""

import math
import re
import time
from datetime import timezone
from email.message import Message
from email.parser import BytesHeaderParser
from email.utils import parsedate_to_datetime


_HTTP_POLICY_MAX_HEADER_BYTES = 64 * 1024
_HTTP_STATUS_LINE = re.compile(rb"HTTP/[0-9]+(?:\.[0-9]+)?[ \t]+[0-9]{3}(?:[ \t].*)?", re.ASCII)
_HTTP_SHORT_DAY = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
_HTTP_LONG_DAY = r"(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)"
_HTTP_MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_HTTP_TIME = r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
_HTTP_DATE = re.compile(
    rf"(?:{_HTTP_SHORT_DAY}, [0-9]{{2}} {_HTTP_MONTH} [0-9]{{4}} {_HTTP_TIME} GMT"
    rf"|{_HTTP_LONG_DAY}, [0-9]{{2}}-{_HTTP_MONTH}-[0-9]{{2}} {_HTTP_TIME} GMT"
    rf"|{_HTTP_SHORT_DAY} {_HTTP_MONTH} (?: [0-9]|[0-9]{{2}}) {_HTTP_TIME} [0-9]{{4}})",
    re.ASCII,
)


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    """Return the server's minimum wait, or None for an invalid header.

    Support delay-seconds and all three HTTP-date forms. Very large integer
    waits return infinity instead of falling back to a shorter local delay.
    Integer-to-float conversion rounds upward when necessary: a caller may
    refuse an excessive wait, but must never retry earlier by truncating it.
    """
    if not isinstance(value, str):
        return None
    # Permit surrounding optional spaces/tabs, but no line breaks or controls
    # inside the header. A folded/combined malformed value is not a duration.
    text = value.strip(" \t")
    if not text:
        return None
    if re.fullmatch(r"[0-9]+", text, flags=re.ASCII):
        digits = text.lstrip("0") or "0"
        # This also avoids Python's configurable large decimal-int limit.
        if len(digits) > 309:
            return math.inf
        integer = int(digits)
        try:
            seconds = float(integer)
        except OverflowError:
            return math.inf
        if seconds < integer:
            seconds = math.nextafter(seconds, math.inf)
        return seconds
    if _HTTP_DATE.fullmatch(text) is None:
        return None
    try:
        parsed = parsedate_to_datetime(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        timestamp = parsed.astimezone(timezone.utc).timestamp()
        current = time.time() if now is None else float(now)
        if not math.isfinite(current) or not math.isfinite(timestamp):
            return None
        return max(0.0, timestamp - current)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def validate_user_agent(value: str) -> str:
    """Validate a single printable ASCII header value without echoing it."""
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError("User-Agent must contain 1 to 512 printable ASCII characters.")
    if any(ord(character) < 32 or ord(character) > 126 for character in value):
        raise ValueError("User-Agent must contain only printable ASCII characters; controls are not allowed.")
    clean = value.strip(" ")
    if not clean:
        raise ValueError("User-Agent cannot be empty or contain only spaces.")
    return clean


def parse_response_headers(data: bytes) -> Message:
    """Read the last HTTP block in curl's --dump-header output.

    Proxy CONNECT and informational responses may precede the actual response.
    Never combine their headers with the last response. Empty or unrecognized
    data yields an empty Message; the caller still validates the HTTP status.
    """
    if not isinstance(data, bytes):
        raise ValueError("Response headers must be bytes.")
    if len(data) > _HTTP_POLICY_MAX_HEADER_BYTES:
        raise ValueError("Response headers exceed the 64 KiB limit.")
    last = b""
    normalized = data.replace(b"\r\n", b"\n")
    for block in normalized.split(b"\n\n"):
        lines = block.lstrip(b"\n").split(b"\n")
        if lines and _HTTP_STATUS_LINE.fullmatch(lines[0]):
            last = b"\n".join(lines[1:])
    if not last:
        return Message()
    return BytesHeaderParser().parsebytes(last + b"\n\n")


"""Credential-aware standard-library client for the official Shodan REST API.

The API key is sent only to api.shodan.io. curl receives the authenticated URL
through stdin configuration so the key is not added to its process arguments.
No redirects, retries, cookies, API scanning, or third-party hosts are used.
"""

import errno
import http.client
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from typing import Any



API_BASE = "https://api.shodan.io"
API_MAX_BYTES = 8 * 1024 * 1024
API_USER_AGENT = "ShodanSpider/7.0 (official API client)"
_API_ALLOWED_PARAMS = {
    "/shodan/host/count": frozenset(("query", "facets")),
    "/shodan/host/search": frozenset(("query", "facets", "page", "minify")),
    "/api-info": frozenset(),
}


class ShodanAPIError(Exception):
    """Expected API error with credential-safe diagnostic text."""

    def __init__(self, message: str, http_status: int | None = None,
                 retry_after: float | None = None):
        super().__init__(message)
        self.http_status = http_status
        self.retry_after = retry_after


def api_redact(value: Any, key: str | None) -> str:
    """Redact secrets only; preserve whitespace/layout and do not truncate.

    The caller can safely apply this to serialized reports. Error messages use
    the separate bounded, one-line `_api_detail` function below.
    """
    text = str(value)
    secrets = []
    if key:
        secrets.append(key)
    for name, secret in os.environ.items():
        if secret and (name.lower().endswith("_proxy") or name.upper() == "SHODAN_API_KEY"):
            secrets.append(secret)
    variants: set[str] = set()
    for secret in secrets:
        variants.update((secret, urllib.parse.quote(secret, safe=""),
                         urllib.parse.quote_plus(secret, safe=""),
                         json.dumps(secret, ensure_ascii=True)[1:-1],
                         json.dumps(secret, ensure_ascii=False)[1:-1]))
    for variant in sorted(variants, key=len, reverse=True):
        if variant:
            text = text.replace(variant, "<redacted>")
    # Catch percent-encoding with lowercase hexadecimal, without changing the
    # case-sensitive literal key characters around the encoded escapes.
    for secret in secrets:
        encoded = urllib.parse.quote(secret, safe="")
        lower_escapes = re.sub(r"%[0-9A-F]{2}", lambda match: match.group(0).lower(), encoded)
        if lower_escapes:
            text = text.replace(lower_escapes, "<redacted>")
    text = re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/\s@]+@", r"\1<redacted>@", text)
    text = re.sub(r"(?i)([?&](?:key|api_key|token|password|passwd)=)[^&\s\"'<>]+", r"\1<redacted>", text)
    return text


def _api_detail(value: Any, key: str | None) -> str:
    text = api_redact(value, key)
    return "".join(char if char.isprintable() else " " for char in text)[:1200]


class _APINoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _api_connection_error(exc: Exception, key: str) -> ShodanAPIError:
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, socket.gaierror):
        category = "DNS"
    elif isinstance(reason, ssl.SSLCertVerificationError):
        category = "TLS_CERTIFICATE"
    elif isinstance(reason, ssl.SSLError):
        category = "TLS"
    elif isinstance(reason, TimeoutError):
        category = "TIMEOUT"
    elif isinstance(reason, ConnectionRefusedError):
        category = "CONNECTION_REFUSED"
    elif isinstance(reason, ConnectionResetError):
        category = "CONNECTION_RESET"
    elif isinstance(reason, http.client.HTTPException):
        category = "RESPONSE_READ"
    elif isinstance(reason, OSError) and reason.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        category = "NETWORK_UNREACHABLE"
    else:
        category = "CONNECTION"
    return ShodanAPIError(f"[API_{category}] {type(reason).__name__}: {_api_detail(reason, key)}")


def _api_http_hint(status: int) -> str:
    if 300 <= status <= 399:
        return "The API redirected the request; redirects are not followed and the key was not forwarded."
    if status == 400:
        return "The API rejected the request; check the search query and parameters."
    if status == 401:
        return "API authentication failed; check that the API key is valid."
    if status == 402:
        return "The API requires additional account access or available credits."
    if status == 403:
        return "API access denied; check the key, account plan, search permissions and available credits."
    if status == 407:
        return "The configured proxy requires authentication."
    if status == 429:
        return "API rate limited; the retry policy determines whether to wait."
    if status >= 500:
        return "Shodan API returned a server error; no automatic retry was made."
    return "Shodan API request failed."


def _api_decode_response(status: int, body: bytes, headers: Message, key: str) -> dict[str, Any]:
    if len(body) > API_MAX_BYTES:
        raise ShodanAPIError("[API_RESPONSE_SIZE] API response exceeds the 8 MiB limit.")
    content_type = headers.get_content_type().lower()
    is_json = content_type == "application/json" or content_type.endswith("+json")
    data: Any = None
    decode_problem = None
    if not body.strip():
        decode_problem = "empty response"
    elif not is_json:
        decode_problem = "non-JSON response"
    else:
        try:
            def reject_constant(value):
                raise ValueError("Non-finite JSON number")
            data = json.loads(body.decode("utf-8-sig"), parse_constant=reject_constant)
        except (UnicodeDecodeError, ValueError, RecursionError):
            decode_problem = "invalid JSON response"
    server_message = None
    if isinstance(data, dict) and data.get("error") is not None:
        raw_error = data["error"]
        server_message = raw_error if isinstance(raw_error, str) else json.dumps(raw_error, ensure_ascii=False)
    if status != 200:
        detail = _api_detail(server_message, key) if server_message is not None else decode_problem
        suffix = f" Server message: {detail}." if detail else ""
        raise ShodanAPIError(
            f"[API_HTTP_{status}] {_api_http_hint(status)}{suffix}",
            http_status=status,
            retry_after=parse_retry_after(headers.get("Retry-After")) if status == 429 else None,
        )
    if decode_problem:
        category = "EMPTY_RESPONSE" if not body.strip() else "RESPONSE_TYPE" if not is_json else "JSON_PARSE"
        raise ShodanAPIError(f"[API_{category}] Expected a JSON API response; received {decode_problem}.")
    if not isinstance(data, dict):
        raise ShodanAPIError("[API_SCHEMA] Expected a JSON object from the API.")
    if server_message is not None:
        raise ShodanAPIError("[API_ERROR] " + (_api_detail(server_message, key) or "The API returned an error field."))
    return data


class ShodanAPIClient:
    def __init__(self, api_key: str, transport: str = "curl", timeout: float = 30,
                 ca_bundle: Path | None = None, user_agent: str | None = None):
        if not isinstance(api_key, str):
            raise ShodanAPIError("[API_KEY] Provide a nonempty API key.")
        key = api_key.strip()
        if not key or len(key) > 4096 or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in key):
            raise ShodanAPIError("[API_KEY] API key must be nonempty and contain no whitespace/control characters.")
        if transport not in ("python", "curl"):
            raise ShodanAPIError("[API_TRANSPORT] Choose python or curl.")
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ShodanAPIError("[API_TIMEOUT] Timeout must be a positive finite number.")
        try:
            self.user_agent = validate_user_agent(API_USER_AGENT if user_agent is None else user_agent)
        except ValueError:
            raise ShodanAPIError("[API_USER_AGENT] User-Agent must be 1-512 printable ASCII characters without control characters.") from None
        self._api_key = key
        self.transport = transport
        self.timeout = float(timeout)
        self.ca_bundle = Path(ca_bundle) if ca_bundle is not None else None
        self._opener = None

    def request(self, path: str, params: dict[str, str | int]) -> dict[str, Any]:
        """GET an allowed official API method; sanitize diagnostics on failure."""
        if path not in _API_ALLOWED_PARAMS:
            raise ShodanAPIError("[API_PATH] Unsupported API endpoint; no request was sent.")
        if not isinstance(params, dict) or set(params) - _API_ALLOWED_PARAMS[path]:
            raise ShodanAPIError("[API_PARAMS] Unsupported parameters; no request was sent.")
        if any(not isinstance(value, (str, int)) or isinstance(value, bool) for value in params.values()):
            raise ShodanAPIError("[API_PARAMS] Parameter values must be strings or integers.")
        # The caller cannot override key, origin or endpoint through params.
        url = API_BASE + path + "?" + urllib.parse.urlencode({"key": self._api_key, **params})
        try:
            if self.transport == "python":
                status, body, headers = self._python_request(url)
            else:
                status, body, headers = self._curl_request(url)
            return _api_decode_response(status, body, headers, self._api_key)
        except ShodanAPIError as exc:
            # Final boundary, including transport start/configuration failures.
            raise ShodanAPIError(api_redact(str(exc), self._api_key),
                                 http_status=exc.http_status, retry_after=exc.retry_after) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as exc:
            raise _api_connection_error(exc, self._api_key) from None

    def _python_request(self, url: str) -> tuple[int, bytes, Message]:
        if self._opener is None:
            try:
                context = ssl.create_default_context(cafile=str(self.ca_bundle) if self.ca_bundle else None)
            except (OSError, ValueError) as exc:
                raise ShodanAPIError("[API_CA_BUNDLE] Cannot load trusted CA bundle: " + _api_detail(exc, self._api_key)) from None
            self._opener = urllib.request.build_opener(_APINoRedirects(), urllib.request.HTTPSHandler(context=context))
        request = urllib.request.Request(url, headers={
            "User-Agent": self.user_agent, "Accept": "application/json", "Accept-Encoding": "identity",
        })
        try:
            response = self._opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            if response.headers.get("Content-Encoding", "identity").lower() not in ("", "identity"):
                raise ShodanAPIError("[API_CONTENT_ENCODING] Unexpected compressed API response from Python transport.")
            return response.status if hasattr(response, "status") else response.code, response.read(API_MAX_BYTES + 1), response.headers

    def _curl_request(self, url: str) -> tuple[int, bytes, Message]:
        executable = shutil.which("curl")
        if executable is None:
            raise ShodanAPIError("[API_DEPENDENCY] Install curl or use --transport python.")
        with tempfile.TemporaryDirectory(prefix="shodan-api-") as directory:
            body_path = Path(directory) / "response.json"
            header_path = Path(directory) / "response.headers"
            header_path.write_bytes(b"")
            command = [
                executable, "--disable", "--silent", "--show-error", "--proto", "=https",
                "--connect-timeout", str(self.timeout), "--max-time", str(self.timeout),
                "--max-filesize", str(API_MAX_BYTES), "--compressed",
                "--user-agent", self.user_agent, "--header", "Accept: application/json",
                "--dump-header", str(header_path),
                "--output", str(body_path), "--write-out", "%{http_code}\n%{content_type}\n",
            ]
            if self.ca_bundle is not None:
                command.extend(["--cacert", str(self.ca_bundle)])
            command.extend(["--config", "-"])
            # URL encoding already removes query control characters. Escape the
            # config-string metacharacters independently; no shell is involved.
            config = 'url = "' + url.replace("\\", "\\\\").replace('"', '\\"') + '"\n'
            try:
                result = subprocess.run(command, input=config, capture_output=True, text=True,
                                        encoding="utf-8", errors="replace", timeout=self.timeout + 5, check=False,
                                        env={name: value for name, value in os.environ.items()
                                             if name.upper() != "SHODAN_API_KEY"})
            except subprocess.TimeoutExpired:
                raise ShodanAPIError("[API_TIMEOUT] curl exceeded its process deadline.") from None
            except OSError as exc:
                raise ShodanAPIError("[API_CURL_START] Cannot start curl: " + _api_detail(exc, self._api_key)) from None
            if result.returncode:
                category = {5: "DNS_PROXY", 6: "DNS", 7: "CONNECT", 28: "TIMEOUT", 35: "TLS",
                            51: "TLS_CERTIFICATE", 60: "TLS_CERTIFICATE", 77: "CA_BUNDLE",
                            52: "EMPTY_RESPONSE", 56: "RESPONSE_READ", 63: "RESPONSE_SIZE"}.get(result.returncode, "CURL")
                detail = _api_detail(result.stderr.strip(), self._api_key) or "No error detail returned."
                raise ShodanAPIError(f"[API_{category}] curl exit {result.returncode}: {detail}")
            metadata = result.stdout.splitlines()
            if not metadata or not re.fullmatch(r"[0-9]{3}", metadata[0]):
                raise ShodanAPIError("[API_CURL_RESPONSE] Missing/invalid HTTP status from curl.")
            status = int(metadata[0])
            try:
                with header_path.open("rb") as stream:
                    headers = parse_response_headers(stream.read(64 * 1024 + 1))
                with body_path.open("rb") as stream:
                    body = stream.read(API_MAX_BYTES + 1)
            except ValueError:
                raise ShodanAPIError("[API_CURL_RESPONSE] Response headers exceed the limit or could not be parsed.") from None
            except OSError as exc:
                raise ShodanAPIError("[API_CURL_RESPONSE] Cannot read API response: " + _api_detail(exc, self._api_key)) from None
            if not headers.get("Content-Type"):
                headers["Content-Type"] = metadata[1] if len(metadata) > 1 else "application/octet-stream"
            return status, body, headers


"""Private, bounded JSON checkpoints for ShodanSpider.

These functions never contact a service or store credentials deliberately.
Callers hold CheckpointLock for the entire read/modify/write session. Atomic
replacement keeps readers on a complete old or new JSON document.
"""

import json
import math
import os
from pathlib import Path
import stat
import tempfile
from typing import Any


MAX_CHECKPOINT_BYTES = 32 * 1024 * 1024
_CHECKPOINT_SECRET_FIELDS = frozenset(("api_key", "api_key_resolved", "authorization", "cookie"))


class CheckpointError(Exception):
    """A checkpoint failure described without reflecting saved data."""


def _checkpoint_target(path: Path) -> os.stat_result | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise CheckpointError("[CHECKPOINT_PATH] Cannot inspect the checkpoint path.") from None
    if stat.S_ISLNK(info.st_mode):
        raise CheckpointError("[CHECKPOINT_PATH] Symbolic-link checkpoint paths are not allowed.")
    if not stat.S_ISREG(info.st_mode):
        raise CheckpointError("[CHECKPOINT_PATH] The checkpoint path must be a regular file.")
    return info


def _checkpoint_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CheckpointError("[CHECKPOINT_JSON] Duplicate JSON object keys are not allowed.")
        result[key] = value
    return result


def _checkpoint_constant(_value: str) -> Any:
    raise CheckpointError("[CHECKPOINT_JSON] Non-finite JSON numbers are not allowed.")


def _checkpoint_validate(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise CheckpointError("[CHECKPOINT_SCHEMA] The checkpoint must be a JSON object.")
    if type(payload.get("schema_version")) is not int or payload["schema_version"] != 1:
        raise CheckpointError("[CHECKPOINT_SCHEMA] Unsupported checkpoint schema; expected version 1.")
    if payload.get("app") != "ShodanSpider":
        raise CheckpointError("[CHECKPOINT_SCHEMA] This is not a ShodanSpider checkpoint.")
    if not isinstance(payload.get("config"), dict) or not isinstance(payload.get("state"), dict):
        raise CheckpointError("[CHECKPOINT_SCHEMA] Checkpoint config and state must be JSON objects.")

    ancestors: set[int] = set()

    def visit(value: Any, depth: int) -> None:
        if depth > 128:
            raise CheckpointError("[CHECKPOINT_JSON] Checkpoint nesting is too deep.")
        if isinstance(value, (dict, list)):
            identity = id(value)
            if identity in ancestors:
                raise CheckpointError("[CHECKPOINT_JSON] Cyclic checkpoint data is not allowed.")
            ancestors.add(identity)
            try:
                if isinstance(value, dict):
                    for key, item in value.items():
                        if not isinstance(key, str):
                            raise CheckpointError("[CHECKPOINT_JSON] JSON object keys must be strings.")
                        if key.casefold() in _CHECKPOINT_SECRET_FIELDS and item not in (None, "", False, [], {}):
                            raise CheckpointError("[CHECKPOINT_SECRET] Credential fields cannot be saved in checkpoints.")
                        visit(item, depth + 1)
                else:
                    for item in value:
                        visit(item, depth + 1)
            finally:
                ancestors.remove(identity)
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise CheckpointError("[CHECKPOINT_JSON] Non-finite JSON numbers are not allowed.")
        elif value is not None and not isinstance(value, (str, int, bool)):
            raise CheckpointError("[CHECKPOINT_JSON] Checkpoint values must be JSON data.")

    visit(payload, 0)


def load_checkpoint(path: Path) -> dict[str, Any]:
    """Load at most 32 MiB of strict JSON, rejecting unsafe file targets."""
    path = Path(path)
    original = _checkpoint_target(path)
    if original is None:
        raise CheckpointError("[CHECKPOINT_MISSING] The checkpoint file does not exist.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (original.st_dev, original.st_ino):
            raise CheckpointError("[CHECKPOINT_PATH] Checkpoint target changed while opening it.")
        if info.st_size > MAX_CHECKPOINT_BYTES:
            raise CheckpointError("[CHECKPOINT_SIZE] Checkpoint exceeds the 32 MiB size limit.")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(MAX_CHECKPOINT_BYTES + 1)
    except OSError:
        raise CheckpointError("[CHECKPOINT_READ] Cannot read the checkpoint file.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise CheckpointError("[CHECKPOINT_SIZE] Checkpoint exceeds the 32 MiB size limit.")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_checkpoint_pairs,
                             parse_constant=_checkpoint_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise CheckpointError("[CHECKPOINT_JSON] Checkpoint is not valid bounded UTF-8 JSON.") from None
    _checkpoint_validate(payload)
    return payload


def save_checkpoint(path: Path, payload: dict, *, allow_replace: bool = False) -> None:
    """Write private JSON atomically; preserve the prior file on write failure.

    Validation, JSON conversion, file writing, flushing, and fsync all happen
    before publishing the staged file. No fallible work occurs after commit.
    A fresh path uses link/create semantics so an existing target is not
    overwritten even if another process creates it during staging.
    """
    path = Path(path)
    _checkpoint_validate(payload)
    try:
        raw = (json.dumps(payload, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise CheckpointError("[CHECKPOINT_JSON] Checkpoint cannot be encoded as strict UTF-8 JSON.") from None
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise CheckpointError("[CHECKPOINT_SIZE] Checkpoint exceeds the 32 MiB size limit.")
    original = _checkpoint_target(path)
    if original is not None and not allow_replace:
        raise CheckpointError("[CHECKPOINT_EXISTS] A checkpoint already exists; resume it or choose another path.")
    if not path.parent.is_dir():
        raise CheckpointError("[CHECKPOINT_PATH] Checkpoint parent directory does not exist.")
    staged: Path | None = None
    descriptor: int | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".shodan-checkpoint-", dir=str(path.parent))
        staged = Path(name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        current = _checkpoint_target(path)
        identity_before = None if original is None else (original.st_dev, original.st_ino)
        identity_now = None if current is None else (current.st_dev, current.st_ino)
        if identity_before != identity_now:
            raise CheckpointError("[CHECKPOINT_CHANGED] Checkpoint target changed while saving; no replacement made.")
        if allow_replace:
            os.replace(staged, path)
            staged = None
        else:
            os.link(staged, path, follow_symlinks=False)
            # Once published, cleanup is best-effort and cannot turn success
            # into an apparent failure after an existing result changed.
    except FileExistsError:
        raise CheckpointError("[CHECKPOINT_EXISTS] A checkpoint already exists; resume it or choose another path.") from None
    except OSError:
        raise CheckpointError("[CHECKPOINT_WRITE] Cannot save checkpoint; the prior checkpoint was preserved.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if staged is not None:
            try:
                staged.unlink(missing_ok=True)
            except OSError:
                pass


class CheckpointLock:
    """Non-blocking Linux/POSIX lock beside a checkpoint.

    The empty private lock file remains after release to avoid lock-inode
    replacement races. A crashed process releases flock automatically.
    """

    def __init__(self, path: Path):
        self.path = Path(str(Path(path)) + ".lock")
        self._descriptor: int | None = None

    def __enter__(self) -> "CheckpointLock":
        if self._descriptor is not None:
            raise CheckpointError("[CHECKPOINT_LOCK] This checkpoint lock is already held.")
        try:
            import fcntl
        except ImportError:
            raise CheckpointError("[CHECKPOINT_LOCK] This system does not support the required file locking.") from None
        _checkpoint_target(self.path)
        descriptor: int | None = None
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise CheckpointError("[CHECKPOINT_LOCK] Lock path must be a regular file.")
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CheckpointError("[CHECKPOINT_BUSY] Another process is using this checkpoint; stop that process or choose another file.") from None
            current = _checkpoint_target(self.path)
            if current is None or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise CheckpointError("[CHECKPOINT_LOCK] Lock file changed while acquiring it.")
            self._descriptor = descriptor
            descriptor = None
            return self
        except OSError:
            raise CheckpointError("[CHECKPOINT_LOCK] Cannot acquire the checkpoint lock.") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is None:
            return
        import fcntl
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


"""Local session controls: HTTP identity selection and an explicit TTY pause.

No browser is launched, no network/IP detection is performed, and no request
is sent by this module. The crawler owns waiting, checkpoints, and retries.
"""

from collections import deque
from collections.abc import Sequence
import random



DEFAULT_USER_AGENTS = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/122.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15) Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.2210.133",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Edge/120.0.2210.133",
    "Mozilla/5.0 (X11; Linux x86_64) Edge/120.0.2210.133",
)


class SessionControlError(Exception):
    """A local interactive control could not be completed."""


class UserAgentPool:
    """Choose every value once per shuffled bag, without adjacent repeats.

    An injected ``random.Random`` supports deterministic tests. A custom pool
    must contain at least two distinct values; fixed identities are handled by
    the caller without using this rotation class.
    """

    def __init__(self, values: Sequence[str] | None = None, rng=None):
        supplied = DEFAULT_USER_AGENTS if values is None else values
        if isinstance(supplied, (str, bytes)) or not isinstance(supplied, Sequence):
            raise ValueError("User-Agent pool must be a sequence of header values.")
        clean = tuple(dict.fromkeys(validate_user_agent(value) for value in supplied))
        if len(clean) < 2:
            raise ValueError("User-Agent rotation requires at least two distinct values.")
        self.values = clean
        self._rng = random.SystemRandom() if rng is None else rng
        self._remaining: deque[str] = deque()
        self._previous: str | None = None

    def next(self) -> str:
        if not self._remaining:
            bag = list(self.values)
            self._rng.shuffle(bag)
            if self._previous is not None and bag[0] == self._previous:
                bag[0], bag[1] = bag[1], bag[0]
            self._remaining.extend(bag)
        selected = self._remaining.popleft()
        self._previous = selected
        return selected


def terminal_continue(message: str) -> bool:
    """Wait on the controlling terminal: Enter/r continues; q exits cleanly.

    The standalone launcher uses stdin for embedded Python. Opening /dev/tty
    independently avoids consuming that source, a pipe, or redirected input.
    The caller must save its checkpoint before invoking this function.
    """
    notice = "".join(char if char.isprintable() or char == "\n" else " "
                     for char in str(message))[:4000]
    prompt = "Press Enter or r to retry the same request; q to save and exit: "
    try:
        # Separate read/write handles work with non-seekable terminal devices.
        with open("/dev/tty", "w", encoding="utf-8", errors="replace") as output:
            with open("/dev/tty", "r", encoding="utf-8", errors="replace") as terminal:
                if not output.isatty() or not terminal.isatty():
                    raise SessionControlError("No controlling terminal is available; continue later with --resume.")
                output.write("\a\n" + notice + "\n")
                output.flush()
                while True:
                    output.write(prompt)
                    output.flush()
                    line = terminal.readline(256)
                    if line == "":
                        raise SessionControlError("Terminal input closed; continue later with --resume.")
                    if not line.endswith("\n"):
                        # Discard an overlong line so its trailing newline
                        # cannot accidentally become an Enter confirmation.
                        while line and not line.endswith("\n"):
                            line = terminal.readline(256)
                        if not line:
                            raise SessionControlError("Terminal input closed; continue later with --resume.")
                        output.write("Unrecognized choice. Enter/r continues; q exits.\n")
                        continue
                    choice = line.strip().casefold()
                    if choice in ("", "r"):
                        return True
                    if choice == "q":
                        return False
                    output.write("Unrecognized choice. Enter/r continues; q exits.\n")
    except OSError:
        raise SessionControlError("Cannot read the controlling terminal; continue later with --resume.") from None


"""Plan scoped facet partitions and rank extractable leaves before collection.

The planner performs no network or disk I/O itself. Its page callback can use
the crawler's existing, checkpointed cache, making a resumed plan deterministic
without trusting a persisted queue or URLs. Counts rank records, not unique IPs.
"""

from dataclasses import dataclass, replace
import heapq
from typing import Any, Callable, Iterable


DEFAULT_SPLIT_FACETS = ("asn", "port", "version", "product")
SUPPORTED_SPLIT_FACETS = frozenset((*DEFAULT_SPLIT_FACETS, "org", "os"))


class PriorityPlanError(ValueError):
    """Invalid planner configuration or callback data, without echoing data."""


PlannerError = PriorityPlanError


@dataclass(frozen=True)
class PlanBranch:
    query: str
    count: int | None
    used_facets: tuple[str, ...] = ()
    path: tuple[tuple[str, str], ...] = ()
    depth: int = 0
    fallback_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"query": self.query, "expected_count": self.count,
                "used_facets": list(self.used_facets),
                "path": [{"facet": facet, "value": value} for facet, value in self.path],
                "depth": self.depth, "fallback_reason": self.fallback_reason}


@dataclass
class PriorityPlan:
    ready: list[PlanBranch]
    fallback: list[PlanBranch]
    events: list[dict[str, Any]]
    probe_count: int
    leaf_limit: int

    @property
    def ordered(self) -> list[PlanBranch]:
        """Normal 1..limit leaves first; unresolved branches are visibly last."""
        return self.ready + self.fallback

    def to_dict(self) -> dict[str, Any]:
        extraction = []
        for rank, branch in enumerate(self.ordered, 1):
            extraction.append({"rank": rank, "kind": "fallback" if branch.fallback_reason else "ready",
                               **branch.to_dict()})
        return {"strategy": "priority", "leaf_limit": self.leaf_limit,
                "ready_branches": len(self.ready), "fallback_branches": len(self.fallback),
                "facet_probes": self.probe_count, "extraction_order": extraction,
                "events": list(self.events),
                "ordering_basis": "record counts; not guaranteed unique-IP yield",
                "optimization": "first useful configured facet, then global descending leaf counts; heuristic"}


def _plan_count(value: Any) -> int | None:
    if value is not None and (type(value) is not int or value < 0):
        raise PriorityPlanError("[PLAN_SCHEMA] Facet counts must be nonnegative integers or unknown.")
    return value


def _plan_text(value: Any, maximum: int) -> str:
    if (not isinstance(value, str) or not value or len(value) > maximum or
            any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise PriorityPlanError("[PLAN_SCHEMA] Invalid query or facet text in planner input.")
    return value


def _plan_branch_valid(branch: Any) -> PlanBranch:
    if not isinstance(branch, PlanBranch):
        raise PriorityPlanError("[PLAN_SCHEMA] Expected a PlanBranch seed.")
    _plan_text(branch.query, 100000)
    _plan_count(branch.count)
    if type(branch.depth) is not int or branch.depth < 0:
        raise PriorityPlanError("[PLAN_SCHEMA] Invalid branch depth.")
    if (not isinstance(branch.used_facets, tuple) or
            not all(isinstance(facet, str) and facet in SUPPORTED_SPLIT_FACETS | {"country", "city"}
                    for facet in branch.used_facets) or
            len(set(branch.used_facets)) != len(branch.used_facets)):
        raise PriorityPlanError("[PLAN_SCHEMA] Invalid used-facet list.")
    if not isinstance(branch.path, tuple):
        raise PriorityPlanError("[PLAN_SCHEMA] Invalid branch path.")
    for item in branch.path:
        if (not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], str) or
                item[0] not in SUPPORTED_SPLIT_FACETS | {"country", "city"}):
            raise PriorityPlanError("[PLAN_SCHEMA] Invalid branch path.")
        _plan_text(item[1], 512)
    if branch.fallback_reason is not None:
        _plan_text(branch.fallback_reason, 100)
    return branch


class PriorityPlanner:
    """Expand only oversized/unknown seeds, then rank all ready leaves.

    read_page(query, facet, expected_count) returns an object with .rows,
    .total and .facet, or None for a specifically recognized unavailable facet.
    Its rows expose .value and .count. Unexpected callback exceptions propagate.
    narrow_branch(query, facet, row) returns a complete narrowed query or None
    when that value conflicts with the original scope.

    The first productive configured facet is accepted. We do not probe every
    facet of every branch merely to compare it: each probe costs a request in
    HTML mode. Missing buckets remain coverage limitations, reported by the
    crawler and by plan events; this heuristic is not a minimum-query proof.
    """

    def __init__(self, read_page: Callable[[str, str, int | None], Any],
                 narrow_branch: Callable[[str, str, Any], str | None], *,
                 split_facets: Iterable[str] = DEFAULT_SPLIT_FACETS,
                 leaf_limit: int = 100, max_nodes: int = 20000, max_depth: int = 12):
        if isinstance(split_facets, (str, bytes)):
            raise PriorityPlanError("[PLAN_CONFIG] Split facets must be an ordered sequence.")
        self.split_facets = tuple(split_facets)
        if (not self.split_facets or
                any(not isinstance(facet, str) or facet not in SUPPORTED_SPLIT_FACETS
                    for facet in self.split_facets) or len(set(self.split_facets)) != len(self.split_facets)):
            raise PriorityPlanError("[PLAN_CONFIG] Unsupported, repeated or empty split-facet list.")
        if any(type(value) is not int or value < 1 for value in (leaf_limit, max_nodes, max_depth)):
            raise PriorityPlanError("[PLAN_CONFIG] Leaf, node and depth limits must be positive integers.")
        if not callable(read_page) or not callable(narrow_branch):
            raise PriorityPlanError("[PLAN_CONFIG] Planner callbacks must be callable.")
        self.read_page, self.narrow_branch = read_page, narrow_branch
        self.leaf_limit, self.max_nodes, self.max_depth = leaf_limit, max_nodes, max_depth

    def plan(self, seeds: Iterable[PlanBranch]) -> PriorityPlan:
        ready: list[PlanBranch] = []
        fallback: list[PlanBranch] = []
        events: list[dict[str, Any]] = []
        pending: list[tuple[bool, int, int, PlanBranch]] = []
        seen_queries: set[str] = set()
        probed: set[tuple[str, str]] = set()
        serial = 0

        def event(code: str, branch: PlanBranch, facet: str | None = None, **details: Any) -> None:
            events.append({"code": code, "query": branch.query, "facet": facet,
                           "expected_count": branch.count, **details})

        def unresolved(branch: PlanBranch, reason: str) -> None:
            fallback.append(replace(branch, fallback_reason=reason))
            event("UNRESOLVED_BRANCH", branch, reason=reason)

        def admit(branch: PlanBranch) -> None:
            nonlocal serial
            if branch.count == 0:
                event("ZERO_BRANCH_SKIPPED", branch)
                return
            if branch.query in seen_queries:
                event("DUPLICATE_BRANCH_SKIPPED", branch)
                return
            seen_queries.add(branch.query)
            serial += 1
            if branch.fallback_reason:
                fallback.append(branch)
            elif branch.count is not None and branch.count <= self.leaf_limit:
                ready.append(branch)
            else:
                heapq.heappush(pending, (branch.count is None, -(branch.count or 0), serial, branch))

        # A small eager seed list bounds accidental or corrupted caller input.
        # The root crawler limits the network work that produces these seeds.
        for seed in seeds:
            branch = _plan_branch_valid(seed)
            if len(seen_queries) >= self.max_nodes and branch.query not in seen_queries and branch.count != 0:
                # Do not silently omit an unadmitted seed: callers may recover
                # by increasing the configured planning limit.
                raise PriorityPlanError("[PLAN_LIMIT] Initial branches exceed the planner node limit.")
            admit(branch)

        while pending:
            _, _, _, branch = heapq.heappop(pending)
            if branch.depth >= self.max_depth:
                unresolved(branch, "depth_limit")
                continue
            used = list(branch.used_facets)
            chosen = False
            actual_empty = False
            for facet in self.split_facets:
                if facet in used:
                    continue
                used.append(facet)
                key = (branch.query, facet)
                if key in probed:
                    event("FACET_ALREADY_PROBED", branch, facet)
                    continue
                probed.add(key)
                page = self.read_page(branch.query, facet, branch.count)
                if page is None:
                    event("FACET_UNAVAILABLE", branch, facet)
                    continue
                if (getattr(page, "facet", None) != facet or
                        not isinstance(getattr(page, "rows", None), (list, tuple))):
                    raise PriorityPlanError("[PLAN_SCHEMA] Callback returned the wrong facet or invalid rows.")
                total = _plan_count(getattr(page, "total", None))
                if total == 0 and not page.rows:
                    event("BRANCH_NOW_EMPTY", branch, facet)
                    actual_empty = True
                    break
                children: list[PlanBranch] = []
                child_queries: set[str] = set()
                values_seen: set[str] = set()
                for row in page.rows:
                    value = _plan_text(getattr(row, "value", None), 512)
                    count = _plan_count(getattr(row, "count", None))
                    if count == 0 or value in values_seen:
                        continue
                    values_seen.add(value)
                    child_query = self.narrow_branch(branch.query, facet, row)
                    if child_query is None:
                        continue
                    _plan_text(child_query, 100000)
                    if child_query == branch.query or child_query in child_queries:
                        continue
                    child_queries.add(child_query)
                    children.append(PlanBranch(child_query, count, tuple(used),
                                               branch.path + ((facet, value),), branch.depth + 1))
                known = all(child.count is not None for child in children)
                child_sum = sum(child.count for child in children if child.count is not None) if known else None
                if not children:
                    event("FACET_NOT_PRODUCTIVE", branch, facet, reason="no_narrowing_nonzero_buckets")
                    continue
                reference_count = branch.count if branch.count is not None else total
                if (len(children) == 1 and children[0].count is not None and reference_count is not None and
                        children[0].count >= reference_count):
                    event("FACET_NOT_PRODUCTIVE", branch, facet, reason="single_bucket_does_not_reduce_count")
                    continue
                new_queries = child_queries - seen_queries
                if not new_queries:
                    event("FACET_NOT_PRODUCTIVE", branch, facet, reason="all_children_already_planned")
                    continue
                if len(seen_queries) + len(new_queries) > self.max_nodes:
                    unresolved(replace(branch, used_facets=tuple(used)), "node_limit")
                    chosen = True
                    break
                event("PARTITION_CHOSEN", branch, facet, children=len(children), sum_child_counts=child_sum,
                      ready_children=sum(child.count is not None and child.count <= self.leaf_limit for child in children),
                      oversized_children=sum(child.count is not None and child.count > self.leaf_limit for child in children),
                      unknown_children=sum(child.count is None for child in children))
                if child_sum is not None and reference_count is not None and child_sum != reference_count:
                    event("PARTITION_COUNT_GAP", branch, facet, sum_child_counts=child_sum,
                          reference_count=reference_count, difference=reference_count - child_sum)
                for child in children:
                    admit(child)
                chosen = True
                break
            if not chosen and not actual_empty:
                unresolved(replace(branch, used_facets=tuple(used)), "facets_exhausted")

        # Stable sorting preserves deterministic discovery order for ties.
        ready.sort(key=lambda branch: -branch.count)
        fallback.sort(key=lambda branch: (branch.count is None, -(branch.count or 0)))
        return PriorityPlan(ready, fallback, events, len(probed), self.leaf_limit)


#!/usr/bin/env python3
"""ShodanSpider v6: resumable traversal, optional API, rotation and manual pause.

Reads Shodan HTML or official API results. Never connects to discovered IPs.
Python standard library, Python 3.10+. See README_AR.md for coverage limits.
"""

import argparse
import contextlib
import csv
import errno
import getpass
import hashlib
import http.client
import io
import ipaddress
import json
import math
import os
import re
import shutil
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from typing import Any, Callable


VERSION = "7.0.0-priority"
ENDPOINT = "https://www.shodan.io/search/facet"
USER_AGENT = "ShodanSpider/7.0 (facet reader)"
API_DEFAULT_USER_AGENT = "ShodanSpider/7.0 (official API client)"
MAX_BYTES = 8 * 1024 * 1024
FACET_LIMIT = 100
SPLIT_FACETS = frozenset(("asn", "port", "version", "product", "org", "os"))
SCOPE_FIELDS = SUPPORTED_FACETS - {"ip"}
IP = ipaddress.IPv4Address | ipaddress.IPv6Address
API_KEY_PROMPT = object()
_REGISTERED_SECRETS: set[str] = set()


class SpiderError(Exception):
    """Expected failure suitable for one terminal message."""

    def __init__(self, message: str, http_status: int | None = None,
                 retry_after: float | None = None):
        super().__init__(message)
        self.http_status = http_status
        self.retry_after = retry_after


class ScopeConflict(SpiderError):
    """A returned bucket conflicts with a retained original restriction."""


class PauseRequested(SpiderError):
    """A deliberate pause; a checkpoint can be resumed in another process."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_detail(value: Any) -> str:
    text = str(value)
    for secret in _REGISTERED_SECRETS:
        text = api_redact(text, secret)
    for key, secret in os.environ.items():
        if secret and (key.lower().endswith("_proxy") or key.upper() == "SHODAN_API_KEY"):
            text = text.replace(secret, "<redacted>")
    text = re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/\s@]+@", r"\1<redacted>@", text)
    text = re.sub(r"(?i)([?&](?:key|api_key|token|password|passwd)=)[^&\s]+", r"\1<redacted>", text)
    return "".join(ch if ch.isprintable() else " " for ch in text)[:1200]


def redact_report(value: Any, key: str | None) -> Any:
    """Sanitize a complete report, including reflected errors/query strings."""
    if not key:
        return value
    if isinstance(value, str):
        return api_redact(value, key)
    if isinstance(value, dict):
        return {api_redact(str(k), key): redact_report(v, key) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_report(v, key) for v in value]
    return value


def bounded_float(text: str, low: float, high: float, name: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{name} must be a number.") from None
    if not math.isfinite(value) or not low <= value <= high:
        raise argparse.ArgumentTypeError(f"{name} must be between {low:g} and {high:g}.")
    return value


def positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("Expected a positive integer.") from None
    if value < 1:
        raise argparse.ArgumentTypeError("Expected a positive integer.")
    return value


def split_facet_list(text: str) -> tuple[str, ...]:
    values = tuple(part.strip().lower() for part in text.split(","))
    if not values or any(value not in SPLIT_FACETS for value in values) or len(set(values)) != len(values):
        raise argparse.ArgumentTypeError("Use a nonempty, nonrepeating comma list of asn,port,version,product,org,os.")
    return values


def query_tokens(query: str) -> list[tuple[int, int, str]]:
    """Keep original spans; understand double-quoted Shodan values, not a shell."""
    result = []
    start = None
    quoted = False
    escaped = False
    for index, char in enumerate(query):
        if start is None:
            if char.isspace():
                continue
            start = index
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char.isspace() and not quoted:
            result.append((start, index, query[start:index]))
            start = None
    if quoted or escaped:
        raise SpiderError('[QUERY] Unclosed double quote or trailing escape in query.')
    if start is not None:
        result.append((start, len(query), query[start:]))
    return result


def filter_values(raw: str) -> list[str]:
    """Read a comma list of quoted/unquoted filter values without evaluation."""
    values = []
    current = []
    quoted = False
    escaped = False
    for char in raw:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            values.append("".join(current))
            current = []
        else:
            current.append(char)
    if quoted or escaped:
        raise SpiderError("[QUERY] Invalid quoted filter value.")
    values.append("".join(current))
    if not all(values):
        raise SpiderError("[QUERY] Empty filter value.")
    return values


def comparable(field: str, value: str) -> str:
    return value.upper() if field in ("country", "asn") else value.casefold()


def scope_filters(query: str) -> dict[str, list[tuple[int, int, list[str], bool]]]:
    found: dict[str, list[tuple[int, int, list[str], bool]]] = {}
    for start, end, token in query_tokens(query):
        match = re.fullmatch(r"(-?)(country|city|asn|port|version|product|org|os):(.+)", token, re.I)
        if match:
            field = match.group(2).lower()
            found.setdefault(field, []).append((start, end, filter_values(match.group(3)), bool(match.group(1))))
    return found


def validate_scope_query(query: str) -> None:
    for field, entries in scope_filters(query).items():
        positive = [entry for entry in entries if not entry[3]]
        if len(positive) > 1:
            raise SpiderError(f"[QUERY_SCOPE] Repeated positive {field}: filters are ambiguous; use one comma-separated filter or separate runs.")


def quote_value(value: str) -> str:
    if not value or len(value) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ScopeConflict("[QUERY_SCOPE] Invalid facet value; branch skipped.")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def narrow_query(query: str, field: str, value: str) -> str:
    """Only add restrictions, or narrow a documented comma-list OR filter.

    A fixed matching filter stays byte-for-byte unchanged. A comma list is
    narrowed to its selected member; all other original terms stay unchanged.
    Never trust a result link as a replacement for the complete query.
    """
    if field not in SCOPE_FIELDS:
        raise ScopeConflict("[QUERY_SCOPE] Unsupported branch filter.")
    quoted = quote_value(value)
    entries = scope_filters(query).get(field, [])
    positive = [entry for entry in entries if not entry[3]]
    if len(positive) > 1:
        raise ScopeConflict(f"[QUERY_SCOPE] Ambiguous repeated {field}: filters.")
    requested = comparable(field, value)
    for _, _, values, negative in entries:
        if negative and requested in {comparable(field, item) for item in values}:
            raise ScopeConflict(f"[QUERY_SCOPE] Returned {field} bucket conflicts with an excluded value.")
    if positive:
        start, end, values, _ = positive[0]
        if requested not in {comparable(field, item) for item in values}:
            raise ScopeConflict(f"[QUERY_SCOPE] Returned {field} bucket conflicts with the original filter.")
        if len(values) == 1:
            return query
        return query[:start] + f"{field}:{quoted}" + query[end:]
    return query + f" {field}:{quoted}"


def build_url(query: str, facet: str) -> str:
    if facet not in SUPPORTED_FACETS:
        raise SpiderError("Unsupported facet.")
    return ENDPOINT + "?" + urllib.parse.urlencode({"query": query, "facet": facet}, quote_via=urllib.parse.quote)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="shodan_spider-v7.sh", allow_abbrev=False,
        description="Plan Shodan branches with <=100 records, then extract largest branches first; optional official API.",
        epilog="With an API key, uses api.shodan.io. API permissions/credits apply. No target hosts are scanned.",
    )
    parser.add_argument("-q", "--query", help="Original Shodan query (wrap it in single shell quotes)")
    parser.add_argument("-cve", "--cve", help="Optional CVE filter, combined with --query")
    parser.add_argument("--net", help="Canonical CIDR; added to query and applied locally to output IPs")
    parser.add_argument("-o", "--output", type=Path, help="IP output file (default: stdout); also writes FILE.report.json")
    parser.add_argument("-f", "--format", choices=("txt", "json", "csv"), default="txt")
    parser.add_argument("--always-asn", action="store_true", help="Visit ASN for every city, including <=100 records")
    parser.add_argument("--strategy", choices=("priority", "tree"), default="priority",
                        help="priority: split large branches then extract global descending queue; tree: v6 traversal (default: priority)")
    parser.add_argument("--split-facets", type=split_facet_list, default="asn,port,version,product",
                        help="Ordered facets for oversized priority branches; first useful split is retained (default: asn,port,version,product)")
    parser.add_argument("--max-plan-nodes", type=positive_int, default=20000,
                        help="Bound priority planning branches; unresolved branches get an explicit fallback warning (default: 20000)")
    parser.add_argument("--api-key", "--api_key", nargs="?", const=API_KEY_PROMPT, metavar="KEY",
                        help="Use official API; omit KEY for a hidden terminal prompt. Also reads SHODAN_API_KEY.")
    parser.add_argument("--api-facet-limit", type=positive_int, default=1000,
                        help="Top buckets requested for each API country/city/ASN facet (default: 1000)")
    parser.add_argument("--mode", choices=("auto", "html", "api"), default="auto",
                        help="Select source explicitly; html ignores SHODAN_API_KEY (default: auto)")
    parser.add_argument("--transport", choices=("curl", "python"), default="curl", help="HTTP client (default: curl)")
    parser.add_argument("--timeout", type=lambda s: bounded_float(s, 1, 180, "Timeout"), default=30.0)
    parser.add_argument("--delay", type=lambda s: bounded_float(s, 0, 3600, "Delay"), default=2.0,
                        help="Seconds between completed request and next request (default: 2)")
    parser.add_argument("--user-agent", metavar="TEXT", help="Fixed HTTP User-Agent for this run; changes a header, not the browser or quota")
    parser.add_argument("--rotate-user-agents", action=argparse.BooleanOptionalAction, default=False,
                        help="Shuffle browser User-Agent values for successive HTTP requests (no adjacent repeats)")
    parser.add_argument("--on-rate-limit", choices=("pause", "stop"), default="stop",
                        help="After automatic 429 retries: ask on /dev/tty to continue, or stop (default: stop)")
    parser.add_argument("--checkpoint", type=Path, metavar="FILE", help="Atomically save successful pages and IPs for --resume")
    parser.add_argument("--resume", type=Path, metavar="FILE", help="Continue a v6/v7 checkpoint with its original query, strategy and output")
    parser.add_argument("--rate-limit-retries", type=int, default=3, metavar="N",
                        help="Additional attempts for HTTP 429 only, 0-10 (default: 3)")
    parser.add_argument("--retry-base-delay", type=lambda s: bounded_float(s, 1, 3600, "Retry base delay"),
                        default=30.0, metavar="SECONDS", help="Initial 429 backoff; doubles on successive retries (default: 30)")
    parser.add_argument("--max-retry-wait", type=lambda s: bounded_float(s, 0, 86400, "Retry wait budget"),
                        default=600.0, metavar="SECONDS", help="HTTP 429 automatic wait budget per cycle; explicit manual continuation starts a new cycle (default: 600)")
    parser.add_argument("--max-requests", type=positive_int, default=500, help="Maximum attempted requests, including retries (default: 500)")
    parser.add_argument("--ca-bundle", type=Path, help="Trusted PEM CA bundle; keeps certificate verification enabled")
    parser.add_argument("--ip-version", choices=("4", "6", "all"), default="all")
    parser.add_argument("--include-non-global", action="store_true", help="Also keep valid non-global/reserved/multicast IPs")
    parser.add_argument("--from-html", type=Path, help="Offline: extract one saved IP-facet HTML page, without traversal")
    parser.add_argument("--save-partial", action="store_true", help="On failed/interrupted traversal, explicitly save collected IPs and failure report")
    parser.add_argument("--force", action="store_true", help="Replace existing output AND report files")
    parser.add_argument("--debug", action="store_true", help="Print connection settings, without credential values")
    parser.add_argument("--quiet", action="store_true", help="Hide progress, not warnings or errors")
    parser.add_argument("--dry-run", action="store_true", help="Show initial plan; no connection and no file writes")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(raw_argv)
    args.api_key_resolved = None
    args.api_key_source = None
    args.resume_payload = None
    args.resume_output_owned = False
    supplied = set()
    for token in raw_argv:
        option = token.split("=", 1)[0]
        action = parser._option_string_actions.get(option)
        if action is None and token.startswith(("-q", "-o", "-f")) and not token.startswith("--"):
            action = parser._option_string_actions.get(token[:2])
        if action is not None:
            supplied.add(action.dest)
    if args.resume is not None:
        forbidden = {"query", "cve", "net", "output", "format", "always_asn", "ip_version",
                     "include_non_global", "api_facet_limit", "from_html", "strategy", "split_facets", "max_plan_nodes"}
        if supplied & forbidden:
            parser.error("--resume restores its query/output/filter settings; omit query, output and scope-changing options.")
        try:
            payload = load_checkpoint(args.resume)
            cfg = payload["config"]
            validate_saved_config(cfg)
        except (CheckpointError, SpiderError) as exc:
            parser.error(safe_detail(exc))
        if args.mode != "auto" and args.mode != cfg["mode"]:
            parser.error("--resume cannot change HTML/API mode; start a new checkpoint for a different source.")
        if args.checkpoint is not None and args.checkpoint.absolute() != args.resume.absolute():
            parser.error("--resume and --checkpoint must identify the same file.")
        args.checkpoint = args.resume.absolute()
        args.resume_payload = payload
        for field in ("query", "cve", "net", "format", "always_asn", "ip_version", "include_non_global", "api_facet_limit"):
            setattr(args, field, cfg[field])
        args.output = Path(cfg["output"]) if cfg["output"] is not None else None
        args.mode = cfg["mode"]
        # Old checkpoints retain their original traversal, rather than silently
        # changing the work already performed by v6.
        args.strategy = cfg.get("strategy", "tree")
        args.split_facets = tuple(cfg.get("split_facets", ("asn", "port", "version", "product")))
        args.max_plan_nodes = cfg.get("max_plan_nodes", 20000)
        runtime = cfg.get("runtime", {})
        for field in ("rotate_user_agents", "on_rate_limit", "user_agent"):
            if field not in supplied and field in runtime:
                setattr(args, field, runtime[field])
        if "user_agent" in supplied and "rotate_user_agents" not in supplied:
            args.rotate_user_agents = False
        if "rotate_user_agents" in supplied and args.rotate_user_agents and "user_agent" not in supplied:
            args.user_agent = None
    if args.rotate_user_agents and args.user_agent is not None:
        parser.error("Use --rotate-user-agents or --user-agent, not both.")
    if args.from_html is not None and (args.checkpoint is not None or args.resume is not None):
        parser.error("Checkpoint/resume applies to live traversal; --from-html is a single offline page.")
    if args.checkpoint is not None:
        args.checkpoint = args.checkpoint.absolute()
    if not 0 <= args.rate_limit_retries <= 10:
        parser.error("--rate-limit-retries must be between 0 and 10.")
    if args.user_agent is not None:
        try:
            args.user_agent = validate_user_agent(args.user_agent)
        except ValueError:
            parser.error("--user-agent must contain 1-512 printable ASCII characters, without control characters.")
    explicit_api = args.api_key is not None
    environment_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if args.mode == "html" and explicit_api:
        parser.error("--mode html cannot be combined with --api-key.")
    if args.from_html is not None and explicit_api:
        parser.error("--from-html is offline and cannot be combined with --api-key.")
    if args.from_html is not None:
        args.mode = "local-html"
    elif args.mode == "auto":
        args.mode = "api" if explicit_api or environment_key else "html"
    if args.mode == "api" and not explicit_api and not environment_key:
        args.api_key = API_KEY_PROMPT
    if isinstance(args.api_key, str):
        # Register before any later argument/query diagnostics.
        if args.api_key:
            _REGISTERED_SECRETS.add(args.api_key)
        args.api_key_resolved = args.api_key
        args.api_key_source = "argument"
    elif args.api_key is API_KEY_PROMPT:
        args.api_key_source = "prompt"
    elif environment_key and args.mode == "api":
        args.api_key_resolved = environment_key
        args.api_key_source = "environment"
        _REGISTERED_SECRETS.add(environment_key)
    if args.api_key_resolved is not None:
        try:
            validate_api_key(args.api_key_resolved)
        except SpiderError as exc:
            parser.error(str(exc))
    parts = []
    if args.query is not None:
        query = args.query.strip()
        if not query or any(ord(c) < 32 or ord(c) == 127 for c in query):
            parser.error("--query must be nonempty and contain no control characters.")
        parts.append(query)
    if args.cve is not None:
        cve = args.cve.strip().upper()
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
            parser.error("--cve must look like CVE-2021-34473.")
        parts.append("vuln:" + cve)
    args.network = None
    if args.net is not None:
        try:
            if "/" not in args.net or "%" in args.net:
                raise ValueError
            args.network = ipaddress.ip_network(args.net, strict=True)
        except ValueError:
            parser.error("--net must be a canonical IPv4 or IPv6 CIDR.")
        if args.ip_version != "all" and int(args.ip_version) != args.network.version:
            parser.error("--net and --ip-version use different IP families.")
        parts.append("net:" + str(args.network))
    if args.from_html is not None and (args.query is not None or args.cve is not None):
        parser.error("--from-html is a single saved IP page, not a live query. Use only --net for local filtering.")
    if args.from_html is None and not parts:
        parser.error("Provide --query, --cve, --net, or --from-html.")
    args.effective_query = " ".join(parts)
    if args.resume_payload is not None and args.effective_query != args.resume_payload["config"]["effective_query"]:
        parser.error("Saved query inputs do not match the checkpoint query; refusing an inconsistent checkpoint.")
    args.report_path = Path(str(args.output) + ".report.json") if args.output is not None else None
    try:
        validate_scope_query(args.effective_query)
    except SpiderError as exc:
        parser.error(str(exc))
    return args


def validate_saved_config(cfg: dict[str, Any]) -> None:
    """Validate checkpoint settings before interpreting paths or requests."""
    required = {"query", "cve", "net", "format", "output", "mode", "always_asn", "ip_version",
                "include_non_global", "api_facet_limit", "effective_query", "runtime"}
    if not required.issubset(cfg):
        raise SpiderError("[CHECKPOINT_CONFIG] Missing saved settings; a v6/v7 checkpoint is required.")
    for field in ("query", "cve", "net", "output"):
        value = cfg[field]
        if value is not None and (not isinstance(value, str) or len(value) > 100000 or any(ord(c) < 32 for c in value)):
            raise SpiderError("[CHECKPOINT_CONFIG] Invalid saved text setting.")
    if cfg["mode"] not in ("html", "api") or cfg["format"] not in ("txt", "json", "csv") or cfg["ip_version"] not in ("all", "4", "6"):
        raise SpiderError("[CHECKPOINT_CONFIG] Unsupported saved source or output setting.")
    if cfg["output"] is not None and not Path(cfg["output"]).is_absolute():
        raise SpiderError("[CHECKPOINT_CONFIG] Saved output path must be absolute.")
    if type(cfg["always_asn"]) is not bool or type(cfg["include_non_global"]) is not bool:
        raise SpiderError("[CHECKPOINT_CONFIG] Invalid saved filter setting.")
    if type(cfg["api_facet_limit"]) is not int or cfg["api_facet_limit"] < 1:
        raise SpiderError("[CHECKPOINT_CONFIG] Invalid saved facet limit.")
    if not isinstance(cfg["effective_query"], str) or not cfg["effective_query"]:
        raise SpiderError("[CHECKPOINT_CONFIG] Missing original query.")
    if cfg.get("strategy", "tree") not in ("priority", "tree"):
        raise SpiderError("[CHECKPOINT_CONFIG] Unsupported saved traversal strategy.")
    if "split_facets" in cfg:
        values = cfg["split_facets"]
        if not isinstance(values, list) or not values or any(not isinstance(value, str) or value not in SPLIT_FACETS for value in values) or len(set(values)) != len(values):
            raise SpiderError("[CHECKPOINT_CONFIG] Invalid saved splitting facets.")
    if "max_plan_nodes" in cfg and (type(cfg["max_plan_nodes"]) is not int or cfg["max_plan_nodes"] < 1):
        raise SpiderError("[CHECKPOINT_CONFIG] Invalid saved planner bound.")
    runtime = cfg["runtime"]
    if not isinstance(runtime, dict) or type(runtime.get("rotate_user_agents")) is not bool or runtime.get("on_rate_limit") not in ("pause", "stop"):
        raise SpiderError("[CHECKPOINT_CONFIG] Invalid saved runtime options.")
    if runtime.get("user_agent") is not None:
        try:
            validate_user_agent(runtime["user_agent"])
        except ValueError:
            raise SpiderError("[CHECKPOINT_CONFIG] Invalid saved User-Agent.") from None


def validate_api_key(key: str) -> None:
    if not key or len(key) > 512 or any(not c.isprintable() or c.isspace() for c in key):
        raise SpiderError("[API_KEY] Key must be nonempty, at most 512 characters, without whitespace/control characters.")


def resolve_api_key(args: argparse.Namespace, prompt: bool = True) -> str | None:
    if args.mode != "api":
        return None
    key = args.api_key_resolved
    if key is None:
        if not prompt:
            return None
        try:
            # Python stdin is the embedded source in the standalone launcher.
            # Require a controlling terminal; never fall back to echoed stdin.
            with open("/dev/tty", "w", encoding="utf-8") as terminal:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", getpass.GetPassWarning)
                    key = getpass.getpass("Shodan API key (hidden): ", stream=terminal)
        except (OSError, EOFError, getpass.GetPassWarning):
            raise SpiderError("[API_KEY] A controlling terminal is required for hidden entry; set SHODAN_API_KEY or supply --api-key KEY.") from None
        args.api_key_source = "prompt"
    validate_api_key(key)
    _REGISTERED_SECRETS.add(key)
    args.api_key_resolved = key
    return key


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def connection_error(exc: Exception) -> SpiderError:
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    detail = f"{type(reason).__name__}: {safe_detail(reason)}"
    if isinstance(reason, socket.gaierror):
        kind, hint = "DNS", "Name resolution failed for the destination or configured proxy."
    elif isinstance(reason, ssl.SSLCertVerificationError):
        kind, hint = "TLS_CERTIFICATE", "Check the clock and trusted CA bundle; TLS verification remains enabled."
    elif isinstance(reason, ssl.SSLError):
        kind, hint = "TLS", "TLS handshake/read failed."
    elif isinstance(reason, TimeoutError):
        kind, hint = "TIMEOUT", "A connection/read operation timed out."
    elif isinstance(reason, ConnectionRefusedError):
        kind, hint = "CONNECTION_REFUSED", "The destination or configured proxy refused the connection."
    elif isinstance(reason, ConnectionResetError):
        kind, hint = "CONNECTION_RESET", "The connection was reset by the peer or an intermediary."
    elif isinstance(reason, http.client.HTTPException):
        kind, hint = "RESPONSE_READ", "The HTTP response was interrupted or invalid."
    elif isinstance(reason, OSError) and reason.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        kind, hint = "NETWORK_UNREACHABLE", "Check routing and connectivity."
    else:
        kind, hint = "CONNECTION", "Underlying failure shown; no empty result has been assumed."
    return SpiderError(f"[{kind}] {detail}. {hint}")


def http_failure(code: int, headers: Message | None = None) -> SpiderError:
    if 300 <= code <= 399:
        return SpiderError(f"[HTTP_{code}] Redirect, possibly to login; redirects are not followed.")
    if code in (401, 403):
        return SpiderError(f"[HTTP_{code}] Access denied; website login/membership or browser verification may be required.")
    if code == 407:
        return SpiderError("[HTTP_407] The configured proxy requires authentication.")
    if code == 429:
        return SpiderError("[HTTP_429] Rate limited; the retry policy determines whether to wait.",
                           http_status=429,
                           retry_after=parse_retry_after(headers.get("Retry-After")) if headers is not None else None)
    return SpiderError(f"[HTTP_{code}] Website request failed.")


def decode_html(body: bytes, headers: Message) -> str:
    if headers.get_content_type() not in ("text/html", "application/xhtml+xml"):
        raise SpiderError("[RESPONSE_TYPE] Expected HTML; website returned another content type.")
    if len(body) > MAX_BYTES:
        raise SpiderError("[RESPONSE_SIZE] HTML exceeds the 8 MiB limit.")
    if not body.strip():
        raise SpiderError("[EMPTY_RESPONSE] Empty response, not an explicit zero-results page.")
    try:
        return body.decode(headers.get_content_charset() or "utf-8", errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def fetch_html(url: str, timeout: float, opener: Any = None, ca_bundle: Path | None = None,
               user_agent: str | None = None) -> str:
    try:
        effective_agent = validate_user_agent(user_agent if user_agent is not None else USER_AGENT)
    except ValueError:
        raise SpiderError("[USER_AGENT] Expected 1-512 printable ASCII characters without control characters.") from None
    if opener is None:
        try:
            context = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
        except (OSError, ValueError) as exc:
            raise SpiderError(f"[CA_BUNDLE] Cannot load trusted CA bundle: {safe_detail(exc)}") from None
        opener = urllib.request.build_opener(NoRedirects(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, headers={
        "User-Agent": effective_agent, "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "identity",
    })
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise http_failure(response.status, response.headers)
            if response.headers.get("Content-Encoding", "identity").lower() not in ("", "identity"):
                raise SpiderError("[CONTENT_ENCODING] Unexpected compressed Python response.")
            return decode_html(response.read(MAX_BYTES + 1), response.headers)
    except urllib.error.HTTPError as exc:
        error = http_failure(exc.code, exc.headers)
        exc.close()
        raise error from None
    except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as exc:
        raise connection_error(exc) from None


def fetch_html_curl(url: str, timeout: float, ca_bundle: Path | None = None,
                    user_agent: str | None = None) -> str:
    try:
        effective_agent = validate_user_agent(user_agent if user_agent is not None else USER_AGENT)
    except ValueError:
        raise SpiderError("[USER_AGENT] Expected 1-512 printable ASCII characters without control characters.") from None
    executable = shutil.which("curl")
    if executable is None:
        raise SpiderError("[DEPENDENCY] Install curl or use --transport python.")
    with tempfile.TemporaryDirectory(prefix="shodan-facet-") as directory:
        body_path = Path(directory) / "response.html"
        header_path = Path(directory) / "headers.txt"
        header_path.touch(mode=0o600)
        command = [
            executable, "--disable", "--silent", "--show-error", "--proto", "=https",
            "--connect-timeout", str(timeout), "--max-time", str(timeout),
            "--max-filesize", str(MAX_BYTES), "--compressed",
            "--user-agent", effective_agent, "--header", "Accept: text/html,application/xhtml+xml",
            "--header", "Accept-Language: en-US,en;q=0.9",
            "--dump-header", str(header_path),
            "--output", str(body_path), "--write-out", "%{http_code}\n%{content_type}\n",
        ]
        if ca_bundle is not None:
            command.extend(["--cacert", str(ca_bundle)])
        command.extend(["--url", url])
        try:
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=timeout + 5, check=False)
        except subprocess.TimeoutExpired:
            raise SpiderError("[TIMEOUT] curl exceeded its process deadline.") from None
        except OSError as exc:
            raise SpiderError(f"[CURL_START] Cannot start curl: {safe_detail(exc)}") from None
        if result.returncode:
            category = {5: "DNS_PROXY", 6: "DNS", 7: "CONNECT", 28: "TIMEOUT", 35: "TLS",
                        51: "TLS_CERTIFICATE", 60: "TLS_CERTIFICATE", 77: "CA_BUNDLE",
                        52: "EMPTY_RESPONSE", 56: "RESPONSE_READ", 63: "RESPONSE_SIZE"}.get(result.returncode, "CURL")
            raise SpiderError(f"[{category}] curl exit {result.returncode}: {safe_detail(result.stderr.strip()) or 'No error detail returned.'}")
        metadata = result.stdout.splitlines()
        if not metadata or not re.fullmatch(r"[0-9]{3}", metadata[0]):
            raise SpiderError("[CURL_RESPONSE] Missing/invalid HTTP status.")
        try:
            with header_path.open("rb") as stream:
                headers = parse_response_headers(stream.read(65537))
        except (OSError, ValueError) as exc:
            raise SpiderError(f"[CURL_RESPONSE] Cannot read response headers: {safe_detail(exc)}") from None
        if int(metadata[0]) != 200:
            raise http_failure(int(metadata[0]), headers)
        if not headers.get("Content-Type"):
            headers["Content-Type"] = metadata[1] if len(metadata) > 1 else "application/octet-stream"
        try:
            with body_path.open("rb") as stream:
                body = stream.read(MAX_BYTES + 1)
        except OSError as exc:
            raise SpiderError(f"[CURL_RESPONSE] Cannot read response: {safe_detail(exc)}") from None
        return decode_html(body, headers)


def print_debug_settings(args: argparse.Namespace) -> None:
    settings = {
        "version": VERSION, "transport": args.transport, "python_version": sys.version.split()[0],
        "openssl": ssl.OPENSSL_VERSION, "destination": "api.shodan.io:443" if args.mode == "api" else "www.shodan.io:443",
        "mode": args.mode, "api_key_source": args.api_key_source,
        "timeout_seconds": args.timeout, "delay_seconds": args.delay, "max_requests": args.max_requests,
        "proxy_environment_variable_names": sorted(k for k, v in os.environ.items() if v and k.lower().endswith("_proxy")),
        "custom_ca_bundle": args.ca_bundle is not None, "tls_verification": True,
        "requires_api_key": args.mode == "api", "automatic_retries": args.rate_limit_retries,
        "retry_http_statuses": [429], "retry_base_delay_seconds": args.retry_base_delay,
        "max_retry_wait_seconds": args.max_retry_wait, "follow_redirects": False,
        "user_agent": args.user_agent or (API_DEFAULT_USER_AGENT if args.mode == "api" else USER_AGENT),
        "rotate_user_agents": args.rotate_user_agents, "on_rate_limit": args.on_rate_limit,
        "checkpoint": str(args.checkpoint) if args.checkpoint else None, "resuming": args.resume is not None,
        "strategy": args.strategy, "split_facets": list(args.split_facets), "max_plan_nodes": args.max_plan_nodes,
    }
    print("Debug: " + json.dumps(redact_report(settings, args.api_key_resolved), ensure_ascii=False), file=sys.stderr)


def parse_ip(text: str) -> IP | None:
    if "%" in text or len(text) > 47:
        return None
    try:
        return ipaddress.ip_address(text.strip().removeprefix("[").removesuffix("]"))
    except ValueError:
        return None


def public_unicast(address: IP) -> bool:
    return address.is_global and not (address.is_multicast or address.is_reserved)


class Crawler:
    def __init__(self, args: argparse.Namespace, fetcher: Callable[[str], str] | None = None,
                 clock: Callable[[], float] = time.monotonic, sleeper: Callable[[float], None] = time.sleep,
                 continue_prompt: Callable[[str], bool] | None = None, wall_clock: Callable[[], float] = time.time):
        self.args = args
        self.fetcher = fetcher or self._network_fetch
        self.clock, self.sleeper = clock, sleeper
        self.wall_clock = wall_clock
        self.continue_prompt = continue_prompt or terminal_continue
        self.agent_pool = UserAgentPool() if args.rotate_user_agents else None
        self.current_user_agent = args.user_agent
        self.api_progress: dict[str, dict[str, Any]] = {}
        self.pending_request: dict[str, Any] | None = None
        self.not_before_utc: float | None = None
        self.wait_unbounded = False
        self.output_hashes: dict[str, str] = {}
        self.previous_requests = 0
        self._retry_budget_baseline = 0.0
        self.session_number = 1
        self.checkpoint_written = args.resume_payload is not None
        self.last_finished: float | None = None
        self.cache: dict[tuple[str, str], FacetPage] = {}
        self.candidates: set[IP] = set()
        self.accepted: set[IP] = set()
        self.report: dict[str, Any] = {
            "version": VERSION, "started_at_utc": utc_now(), "finished_at_utc": None,
            "source": "local-html" if args.from_html else "website-html",
            "original_query": args.effective_query, "status": "running", "traversal_completed": False,
            "complete_export": False, "coverage_assessment": "not_yet_assessed",
            "coverage_note": "Facets contain record counts, not guaranteed unique-IP totals. Displayed totals may cover only top buckets. No full-export guarantee.",
            "settings": {"always_asn": args.always_asn, "city_threshold": FACET_LIMIT,
                         "strategy": args.strategy, "split_facets": list(args.split_facets),
                         "max_plan_nodes": args.max_plan_nodes,
                         "transport": args.transport, "delay_seconds": args.delay, "max_requests": args.max_requests,
                         "timeout_seconds": args.timeout, "requires_api_key": False,
                         "tls_verification": True, "ip_version": args.ip_version,
                         "network_filter": str(args.network) if args.network else None,
                         "include_non_global": args.include_non_global,
                         "user_agent": args.user_agent or USER_AGENT,
                         "rotate_user_agents": args.rotate_user_agents,
                         "on_rate_limit": args.on_rate_limit,
                         "checkpoint": str(args.checkpoint) if args.checkpoint else None,
                         "rate_limit_retries": args.rate_limit_retries,
                         "retry_base_delay_seconds": args.retry_base_delay,
                         "max_retry_wait_seconds": args.max_retry_wait},
            "requests_attempted": 0, "pages_read": 0, "cache_hits": 0,
            "rate_limit_events": [], "retry_wait_seconds": 0.0,
            "manual_continuations": 0,
            "visited": {"country": 0, "city": 0, "asn": 0, "port": 0,
                        "version": 0, "product": 0, "org": 0, "os": 0, "ip_leaves": 0},
            "pages": [], "warnings": [], "error": None,
        }
        if args.resume_payload is not None:
            self.restore_checkpoint(args.resume_payload["state"])

    def saved_config(self) -> dict[str, Any]:
        args = self.args
        return {"query": args.query, "cve": args.cve, "net": args.net, "effective_query": args.effective_query,
                "output": str(args.output.absolute()) if args.output else None,
                "mode": args.mode, "format": args.format, "always_asn": args.always_asn,
                "ip_version": args.ip_version, "include_non_global": args.include_non_global,
                "api_facet_limit": args.api_facet_limit,
                "strategy": args.strategy, "split_facets": list(args.split_facets),
                "max_plan_nodes": args.max_plan_nodes,
                "runtime": {"rotate_user_agents": args.rotate_user_agents,
                            "on_rate_limit": args.on_rate_limit, "user_agent": args.user_agent}}

    def checkpoint(self, status: str | None = None) -> None:
        if self.args.checkpoint is None:
            return
        cache = [{"query": query, "facet": facet, "total": page.total, "warnings": page.warnings,
                  "explicit_empty": page.explicit_empty,
                  "rows": [{"value": row.value, "count": row.count, "label": row.label} for row in page.rows]}
                 for (query, facet), page in self.cache.items()]
        payload = {"app": "ShodanSpider", "schema_version": 1, "version": VERSION,
                   "saved_at_utc": utc_now(), "config": self.saved_config(),
                   "state": {"status": status or self.report["status"], "cache": cache,
                             "candidates": [str(ip) for ip in sorted(self.candidates, key=lambda a: (a.version, int(a)))],
                             "api_progress": self.api_progress, "pending_request": self.pending_request,
                             "not_before_utc": self.not_before_utc, "wait_unbounded": self.wait_unbounded,
                             "output_hashes": self.output_hashes, "warnings": self.report["warnings"],
                             "requests_total": self.previous_requests + self.report["requests_attempted"],
                             "session_number": self.session_number}}
        payload = redact_report(payload, self.args.api_key_resolved)
        try:
            save_checkpoint(self.args.checkpoint, payload,
                            allow_replace=self.checkpoint_written or self.args.force)
        except CheckpointError as exc:
            raise SpiderError(safe_detail(exc)) from None
        self.checkpoint_written = True

    def restore_checkpoint(self, state: dict[str, Any]) -> None:
        """Restore data only; URLs are always rebuilt from the retained query."""
        try:
            def count(value, nullable=False):
                if nullable and value is None:
                    return None
                if type(value) is not int or value < 0:
                    raise ValueError
                return value
            def text(value, maximum=100000):
                if not isinstance(value, str) or not value or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
                    raise ValueError
                return value
            cache = state["cache"]
            if not isinstance(cache, list):
                raise ValueError
            for item in cache:
                if not isinstance(item, dict) or item.get("facet") not in SUPPORTED_FACETS:
                    raise ValueError
                query, facet = text(item["query"]), item["facet"]
                validate_scope_query(query)
                if (query, facet) in self.cache or not isinstance(item["rows"], list):
                    raise ValueError
                rows = [FacetRow(text(row["value"], 512), count(row["count"], True), text(row["label"], 2000)) for row in item["rows"]]
                problems = item["warnings"]
                if not isinstance(problems, list) or not all(isinstance(w, str) for w in problems) or type(item["explicit_empty"]) is not bool:
                    raise ValueError
                self.cache[(query, facet)] = FacetPage(facet, rows, count(item["total"], True), problems, item["explicit_empty"])
            candidates = state["candidates"]
            if not isinstance(candidates, list):
                raise ValueError
            for value in candidates:
                address = parse_ip(text(value, 47))
                if address is None:
                    raise ValueError
                self.accept_ip(address)
            progress = state["api_progress"]
            if not isinstance(progress, dict) or (self.args.mode == "html" and progress):
                raise ValueError
            for query, saved in progress.items():
                text(query)
                if not isinstance(saved, dict) or not isinstance(saved["counts"], dict):
                    raise ValueError
                total = count(saved["first_total"])
                next_page, planned = count(saved["next_page"]), count(saved["target_pages"])
                if next_page < 1 or next_page > planned + 1 or planned != max(1, (total + 99) // 100):
                    raise ValueError
                received = count(saved["received"])
                for ip, amount in saved["counts"].items():
                    if parse_ip(text(ip, 47)) is None or count(amount) < 1:
                        raise ValueError
                if sum(saved["counts"].values()) > received:
                    raise ValueError
                if not isinstance(saved["known_ids"], list) or not all(isinstance(i, str) for i in saved["known_ids"]):
                    raise ValueError
                self.api_progress[query] = saved
            self.previous_requests = count(state["requests_total"])
            self.session_number = count(state["session_number"]) + 1
            self.not_before_utc = state["not_before_utc"]
            if self.not_before_utc is not None and (type(self.not_before_utc) not in (int, float) or not math.isfinite(self.not_before_utc) or self.not_before_utc < 0):
                raise ValueError
            if type(state["wait_unbounded"]) is not bool:
                raise ValueError
            self.wait_unbounded = state["wait_unbounded"]
            self.pending_request = state["pending_request"]
            if self.pending_request is not None and not isinstance(self.pending_request, dict):
                raise ValueError
            hashes = state["output_hashes"]
            allowed_paths = {str(p.absolute()) for p in (self.args.output, self.args.report_path) if p}
            if not isinstance(hashes, dict) or any(path not in allowed_paths or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) for path, digest in hashes.items()):
                raise ValueError
            self.output_hashes = hashes
            problems = state["warnings"]
            if not isinstance(problems, list) or any(not isinstance(w, dict) or any(not isinstance(w.get(k), str) for k in ("code", "message", "query", "facet")) for w in problems):
                raise ValueError
            self.report["warnings"] = list(problems)
        except (KeyError, TypeError, ValueError, SpiderError, OverflowError):
            raise SpiderError("[CHECKPOINT_STATE] Invalid cached pages, IPs or progress; no request was sent.") from None
        self.report["resume"] = {"checkpoint": str(self.args.checkpoint), "session_number": self.session_number,
                                 "previous_requests": self.previous_requests, "cached_pages": len(self.cache),
                                 "previous_unique_ips": len(self.accepted)}

    def capture_output_hashes(self) -> None:
        for path in (self.args.output, self.args.report_path):
            if path is not None:
                self.output_hashes[str(path.absolute())] = file_sha256(path)

    def _remaining_server_wait(self) -> float:
        if self.wait_unbounded:
            raise PauseRequested("[RATE_LIMIT_WAIT_LIMIT] The server supplied an excessively long wait; checkpoint retained. No early retry was sent.")
        return max(0.0, self.not_before_utc - self.wall_clock()) if self.not_before_utc is not None else 0.0

    def _pause_for_user(self, reason: str, event: dict[str, Any]) -> None:
        event["decision"] = "paused"
        self.checkpoint("paused")
        message = ("Paused after HTTP 429. " + safe_detail(reason) + "\n"
                   "Resolve the connection issue before continuing. The script does not change or detect your IP.\n"
                   "Any remaining server Retry-After waiting time will still be honored.")
        if self.args.checkpoint:
            message += "\nCheckpoint: " + str(self.args.checkpoint)
        try:
            proceed = self.continue_prompt(message)
        except SessionControlError as exc:
            raise PauseRequested("[PAUSED] " + safe_detail(exc)) from None
        if not proceed:
            hint = "Saved progress; continue later with --resume." if self.args.checkpoint else "Stopped by user; use --checkpoint to enable later resume."
            raise PauseRequested("[PAUSED] " + hint)
        self.report["manual_continuations"] += 1
        event["decision"] = "continued_by_user"

    def _network_fetch(self, url: str) -> str:
        function = fetch_html_curl if self.args.transport == "curl" else fetch_html
        if self.current_user_agent is not None:
            return function(url, self.args.timeout, ca_bundle=self.args.ca_bundle,
                            user_agent=self.current_user_agent)
        return function(url, self.args.timeout, ca_bundle=self.args.ca_bundle)

    def progress(self, text: str) -> None:
        if not self.args.quiet:
            print(text, file=sys.stderr, flush=True)

    def warning(self, code: str, message: str, query: str, facet: str) -> None:
        self.report["warnings"].append({"code": code, "message": message, "facet": facet, "query": query})
        print(f"Warning [{code}] {safe_detail(message)} | facet={facet}", file=sys.stderr, flush=True)

    def _request_with_rate_limits(self, operation: Callable[[], Any], template: dict[str, Any],
                                  label: str, counter: str | None = None) -> tuple[Any, dict[str, Any]]:
        """Preserve request scope through automatic retries and explicit pauses."""
        retry_number = 0
        manual_wait_allowed = False
        while True:
            if self.report["requests_attempted"] >= self.args.max_requests:
                self.checkpoint("request_limit")
                raise SpiderError(f"[REQUEST_LIMIT] Reached --max-requests={self.args.max_requests}; use the checkpoint to continue in a new run.")
            # A wall-clock deadline survives process exit. Pressing Enter or
            # restarting cannot shorten a server-requested waiting period.
            pending_wait = self._remaining_server_wait()
            if pending_wait > 0:
                remaining_budget = max(0.0, self.args.max_retry_wait -
                                       (self.report["retry_wait_seconds"] - self._retry_budget_baseline))
                if pending_wait > remaining_budget and not manual_wait_allowed:
                    if self.args.on_rate_limit != "pause":
                        raise SpiderError("[RATE_LIMIT_WAIT_LIMIT] Saved server waiting time exceeds this run's remaining retry budget; no early request sent.")
                    event = {"decision": "saved_wait_exceeds_budget", "planned_wait_seconds": pending_wait,
                             "query": template["query"], "facet": template["facet"]}
                    self.report["rate_limit_events"].append(event)
                    self._pause_for_user("The saved waiting time exceeds the automatic budget.", event)
                    manual_wait_allowed = True
                self.progress(f"Waiting {pending_wait:g}s before resuming the saved request (Ctrl+C to stop).")
                self.sleeper(pending_wait)
                self.report["retry_wait_seconds"] += pending_wait
            self.not_before_utc = None
            if manual_wait_allowed:
                # Explicit continuation starts a new automatic waiting cycle.
                self._retry_budget_baseline = self.report["retry_wait_seconds"]
                manual_wait_allowed = False
            if self.last_finished is not None:
                delay = self.args.delay - (self.clock() - self.last_finished)
                if delay > 0:
                    self.sleeper(delay)
            if self.agent_pool is not None:
                self.current_user_agent = self.agent_pool.next()
                if hasattr(self, "client"):
                    self.client.user_agent = self.current_user_agent
            effective_agent = self.current_user_agent or (API_DEFAULT_USER_AGENT if self.args.mode == "api" else USER_AGENT)
            self.pending_request = dict(template)
            entry = {**template, "number": self.report["requests_attempted"] + 1,
                     "retry_number": retry_number, "user_agent": effective_agent, "status": "requesting"}
            self.report["pages"].append(entry)
            self.report["requests_attempted"] += 1
            if counter:
                self.report[counter] += 1
            retry_label = f" retry={retry_number}" if retry_number else ""
            self.progress(f"[{entry['number']}/{self.args.max_requests}] {label}{retry_label} | {safe_detail(entry['query'])}")
            if self.args.debug:
                self.progress("    User-Agent: " + safe_detail(effective_agent))
            failure = None
            try:
                result = operation()
            except KeyboardInterrupt:
                entry.update(status="interrupted", error="KeyboardInterrupt")
                raise
            except (SpiderError, ShodanAPIError, OSError) as exc:
                failure = exc
                entry.update(status="failed", error=safe_detail(exc))
            finally:
                self.last_finished = self.clock()
            if failure is None:
                entry["status"] = "received"
                self.pending_request = None
                self.wait_unbounded = False
                return result, entry
            if isinstance(failure, ShodanAPIError):
                failure = SpiderError(safe_detail(failure), http_status=failure.http_status,
                                      retry_after=failure.retry_after)
            if getattr(failure, "http_status", None) != 429:
                self.checkpoint("failed")
                raise failure

            entry["status"] = "rate_limited"
            server_wait = getattr(failure, "retry_after", None)
            if server_wait is not None and (not isinstance(server_wait, (int, float)) or
                                            isinstance(server_wait, bool) or math.isnan(server_wait) or server_wait < 0):
                server_wait = None
            wait = max(self.args.delay, self.args.retry_base_delay * (2 ** retry_number), server_wait or 0.0)
            finite_server_wait = server_wait is not None and math.isfinite(server_wait)
            self.wait_unbounded = not math.isfinite(wait)
            self.not_before_utc = self.wall_clock() + wait if math.isfinite(wait) else None
            event = {"request_number": entry["number"], "query": entry["query"], "facet": entry["facet"],
                     "retry_number": retry_number, "retry_after_seconds": server_wait if finite_server_wait else None,
                     "retry_after_exceeds_supported_range": server_wait is not None and not finite_server_wait,
                     "planned_wait_seconds": wait if math.isfinite(wait) else None,
                     "waited_seconds": 0.0, "decision": "pending"}
            self.report["rate_limit_events"].append(event)
            self.checkpoint("rate_limited")
            if self.report["requests_attempted"] >= self.args.max_requests:
                event["decision"] = "request_limit_reached"
                raise SpiderError(f"[REQUEST_LIMIT] HTTP 429 received and --max-requests={self.args.max_requests} reached; no retry sent.",
                                  http_status=429, retry_after=server_wait)
            remaining = max(0.0, self.args.max_retry_wait -
                            (self.report["retry_wait_seconds"] - self._retry_budget_baseline))
            problem = None
            if retry_number >= self.args.rate_limit_retries:
                event["decision"] = "retry_limit_reached"
                problem = safe_detail(failure) + f" Additional retry limit {self.args.rate_limit_retries} reached."
            elif not math.isfinite(wait) or wait > remaining:
                event["decision"] = "wait_budget_exceeded"
                needed = f"{wait:g} seconds" if math.isfinite(wait) else "a wait beyond the supported range"
                problem = f"[RATE_LIMIT_WAIT_LIMIT] HTTP 429 requires {needed}; remaining retry wait budget is {remaining:g} seconds. No earlier retry was sent."
            if problem is not None:
                if self.args.on_rate_limit == "pause" and not self.wait_unbounded:
                    self._pause_for_user(problem, event)
                    retry_number = 0
                    manual_wait_allowed = True
                    continue
                raise SpiderError(problem, http_status=429, retry_after=server_wait)
            event["decision"] = "waiting"
            self.progress(f"HTTP 429: waiting {wait:g}s before retry {retry_number + 1}/{self.args.rate_limit_retries} of the same request (Ctrl+C to stop).")
            started = self.clock()
            try:
                self.sleeper(wait)
            except KeyboardInterrupt:
                elapsed = min(wait, max(0.0, self.clock() - started))
                event.update(decision="interrupted", waited_seconds=elapsed)
                self.report["retry_wait_seconds"] += elapsed
                entry.update(status="interrupted", error="KeyboardInterrupt during rate-limit wait")
                raise
            self.not_before_utc = None
            event.update(decision="retried", waited_seconds=wait)
            self.report["retry_wait_seconds"] += wait
            retry_number += 1

    def inspect_coverage(self, page: FacetPage, entry: dict[str, Any], expected: int | None,
                         limit: int | None = FACET_LIMIT) -> None:
        query, facet = entry["query"], page.facet
        for warning in page.warnings:
            self.warning("PARSER_WARNING", warning, query, facet)
        counts_known = all(row.count is not None for row in page.rows)
        total_count = sum(row.count for row in page.rows if row.count is not None) if counts_known else None
        entry.update({"rows": [{"value": row.value, "label": row.label, "count": row.count} for row in page.rows],
                      "row_count": len(page.rows), "displayed_total": page.total,
                      "sum_row_counts": total_count, "parent_expected_count": expected})
        if page.total is None:
            self.warning("TOTAL_UNKNOWN", "Page total was not recognized; coverage cannot be checked against it.", query, facet)
        if not counts_known:
            self.warning("COUNTS_UNKNOWN", "Some row counts were unavailable; coverage cannot be fully assessed.", query, facet)
        if total_count is not None and page.total is not None and total_count != page.total:
            entry["displayed_total_minus_rows"] = page.total - total_count
            self.warning("DISPLAYED_COUNT_MISMATCH", f"Displayed total={page.total}, sum of row counts={total_count}; missing buckets, missing field values or changing data may be involved.", query, facet)
        if expected is not None and total_count is not None and expected != total_count:
            entry["parent_count_minus_rows"] = expected - total_count
            self.warning("PARENT_COUNT_MISMATCH", f"Parent count={expected}, child sum of row counts={total_count}; these snapshots do not account for the same number of records.", query, facet)
        if limit is not None and len(page.rows) >= limit:
            self.warning("FACET_LIMIT_REACHED", f"This {facet} page contains {len(page.rows)} rows; a top-{limit} limit may hide more buckets, even if totals match.", query, facet)

    def read_page(self, query: str, facet: str, expected: int | None = None) -> FacetPage:
        key = (query, facet)
        if key in self.cache:
            self.report["cache_hits"] += 1
            return self.cache[key]
        url = build_url(query, facet)
        html, entry = self._request_with_rate_limits(lambda: self.fetcher(url),
                    {"query": query, "facet": facet, "url": url}, facet.upper())
        self.report["pages_read"] += 1
        try:
            page = parse_facet_html(html, facet, query=query,
                                    allow_missing_facet=self.args.strategy == "priority" and facet in SPLIT_FACETS)
        except FacetParseError as exc:
            entry.update(status="failed", error=safe_detail(exc))
            raise SpiderError(f"[HTML_PARSE] {safe_detail(exc)}") from None
        except (SpiderError, OSError, KeyboardInterrupt) as exc:
            entry.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", error=safe_detail(exc) or "KeyboardInterrupt")
            raise
        entry["status"] = "parsed"
        self.inspect_coverage(page, entry, expected)
        self.cache[key] = page
        self.checkpoint("running")
        return page

    def branch(self, query: str, field: str, row: FacetRow) -> str | None:
        try:
            return narrow_query(query, field, row.value)
        except ScopeConflict as exc:
            self.warning("SCOPE_CONFLICT", str(exc), query, field)
            return None

    def collect_ips(self, page: FacetPage) -> None:
        self.report["visited"]["ip_leaves"] += 1
        for row in page.rows:
            address = parse_ip(row.value)
            if address is None:
                continue  # The parser normally already rejects invalid IP rows.
            self.accept_ip(address)
        self.progress(f"    Unique IPs collected: {len(self.accepted)}")

    def accept_ip(self, address: IP) -> None:
        self.candidates.add(address)
        if self.args.ip_version != "all" and address.version != int(self.args.ip_version):
            return
        if self.args.network is not None and address not in self.args.network:
            return
        if not self.args.include_non_global and not public_unicast(address):
            return
        self.accepted.add(address)

    def priority_seed(self, query: str, count: int | None,
                      path: tuple[tuple[str, str], ...], extra_used: tuple[str, ...] = ()) -> PlanBranch:
        # An exact positive singleton cannot usefully subdivide itself. OR
        # lists and exclusions can still be narrowed by a returned bucket.
        fixed = {field for field, entries in scope_filters(query).items()
                 if any(not negative and len(values) == 1 for _, _, values, negative in entries)}
        return PlanBranch(query, count, tuple(sorted(fixed | {"country", "city"} | set(extra_used))), path)

    def run_priority(self) -> None:
        """Discover subdivisions first, then use one global extraction queue."""
        self.report["planning_stage"] = "discovering"
        self.report["plan"] = None
        initial_requests = self.report["requests_attempted"]
        base = self.args.effective_query
        countries = self.read_page(base, "country")
        seeds: list[PlanBranch] = []
        for country in countries.rows:
            if country.count == 0:
                continue
            cq = self.branch(base, "country", country)
            if cq is None:
                continue
            self.report["visited"]["country"] += 1
            cities = self.read_page(cq, "city", country.count)
            for city in cities.rows:
                if city.count == 0:
                    continue
                cityq = self.branch(cq, "city", city)
                if cityq is None:
                    continue
                self.report["visited"]["city"] += 1
                path = (("country", country.value), ("city", city.value))
                if self.args.always_asn:
                    asns = self.read_page(cityq, "asn", city.count)
                    added = 0
                    for asn in asns.rows:
                        if asn.count == 0:
                            continue
                        asnq = self.branch(cityq, "asn", asn)
                        if asnq is not None:
                            self.report["visited"]["asn"] += 1
                            seeds.append(self.priority_seed(asnq, asn.count, path + (("asn", asn.value),), ("asn",)))
                            added += 1
                    if not added and asns.total != 0:
                        seeds.append(self.priority_seed(cityq, city.count, path, ("asn",)))
                else:
                    seeds.append(self.priority_seed(cityq, city.count, path))
        self.report["planning_stage"] = "partitioning"
        planner = PriorityPlanner(self.read_page, self.branch, split_facets=self.args.split_facets,
                                  leaf_limit=FACET_LIMIT, max_nodes=self.args.max_plan_nodes)
        try:
            plan = planner.plan(seeds)
        except PlannerError as exc:
            raise SpiderError(str(exc)) from None
        self.report["plan"] = plan.to_dict()
        self.report["plan"]["discovery_requests_this_run"] = self.report["requests_attempted"] - initial_requests
        self.report["plan"]["completed_leaves"] = 0
        self.report["plan"]["extraction_requests_this_run"] = 0
        self.report["planning_stage"] = "extracting"
        # Count selected split buckets, rather than speculative facet probes.
        chosen_paths = set()
        for leaf in plan.ordered:
            for index, (field, value) in enumerate(leaf.path):
                if field in SPLIT_FACETS and not (self.args.always_asn and field == "asn"):
                    chosen_paths.add(leaf.path[:index + 1])
        for path in chosen_paths:
            self.report["visited"][path[-1][0]] += 1
        for leaf in plan.fallback:
            self.warning("UNRESOLVED_BRANCH", "No eligible <=100 partition was found (" +
                         str(leaf.fallback_reason) + "); extracting this fallback after all ready branches. "
                         "HTML results may be truncated.", leaf.query, "ip")
        self.progress(f"[PLAN] Ready branches: {len(plan.ready)}; unresolved fallbacks: {len(plan.fallback)}. "
                      "Extracting ready branches globally from largest to smallest.")
        self.checkpoint("planned")
        extraction_start = self.report["requests_attempted"]
        for index, leaf in enumerate(plan.ordered):
            planned = self.report["plan"]["extraction_order"][index]
            planned["cached"] = (leaf.query, "ip") in self.cache
            planned["status"] = "extracting"
            before = len(self.accepted)
            self.progress(f"[EXTRACT {index + 1}/{len(plan.ordered)}] expected_records={leaf.count} | "
                          + safe_detail(leaf.query))
            try:
                page = self.read_page(leaf.query, "ip", leaf.count)
            except (SpiderError, OSError, KeyboardInterrupt) as exc:
                planned.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else
                               "paused" if isinstance(exc, PauseRequested) else "failed",
                               new_unique_ips=len(self.accepted) - before)
                raise
            finally:
                self.report["plan"]["extraction_requests_this_run"] = self.report["requests_attempted"] - extraction_start
            self.collect_ips(page)
            planned.update(status="completed", new_unique_ips=len(self.accepted) - before)
            self.report["plan"]["completed_leaves"] += 1
            self.checkpoint("collecting")
        self.report["planning_stage"] = "completed"

    def run(self) -> dict[str, Any]:
        if self.args.from_html is not None:
            with self.args.from_html.open("rb") as stream:
                body = stream.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise SpiderError("[RESPONSE_SIZE] Saved HTML exceeds 8 MiB.")
            try:
                page = parse_facet_html(body.decode("utf-8-sig", errors="replace"), "ip")
            except FacetParseError as exc:
                raise SpiderError(f"[HTML_PARSE] {safe_detail(exc)}") from None
            self.report["pages_read"] = 1
            entry = {"number": 1, "query": "", "facet": "ip", "status": "parsed", "local_path": str(self.args.from_html)}
            self.report["pages"].append(entry)
            self.inspect_coverage(page, entry, None)
            self.collect_ips(page)
        elif self.args.strategy == "priority":
            self.run_priority()
        else:
            base = self.args.effective_query
            countries = self.read_page(base, "country")
            for country in countries.rows:
                cq = self.branch(base, "country", country)
                if cq is None:
                    continue
                self.report["visited"]["country"] += 1
                cities = self.read_page(cq, "city", country.count)
                for city in cities.rows:
                    cityq = self.branch(cq, "city", city)
                    if cityq is None:
                        continue
                    self.report["visited"]["city"] += 1
                    if self.args.always_asn or city.count is None or city.count > FACET_LIMIT:
                        asns = self.read_page(cityq, "asn", city.count)
                        for asn in asns.rows:
                            asnq = self.branch(cityq, "asn", asn)
                            if asnq is None:
                                continue
                            self.report["visited"]["asn"] += 1
                            self.collect_ips(self.read_page(asnq, "ip", asn.count))
                    else:
                        self.collect_ips(self.read_page(cityq, "ip", city.count))
        self.report["traversal_completed"] = True
        return self.finish("finished_with_warnings" if self.report["warnings"] else "finished")

    def finish(self, status: str, error: str | None = None) -> dict[str, Any]:
        self.report.update({"status": status, "finished_at_utc": utc_now(), "error": error,
                            "unique_candidates": len(self.candidates),
                            "unique_candidates_filtered": len(self.candidates) - len(self.accepted),
                            "unique_ip_count": len(self.accepted),
                            "ips": [str(ip) for ip in sorted(self.accepted, key=lambda ip: (ip.version, int(ip)))]})
        self.report["coverage_assessment"] = (
            "traversal_unfinished" if not self.report["traversal_completed"] else
            "warnings_present" if self.report["warnings"] else "no_detected_gaps_not_a_complete_export_guarantee"
        )
        self.report = redact_report(self.report, getattr(self.args, "api_key_resolved", None))
        return self.report


def api_integer(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SpiderError(f"[API_SCHEMA] {field} must be a nonnegative integer.")
    return value


def parse_api_facet(payload: dict[str, Any], facet: str) -> FacetPage:
    if facet not in SUPPORTED_FACETS - {"ip"}:
        raise SpiderError("[API_SCHEMA] Unsupported count facet.")
    total = api_integer(payload.get("total"), "total")
    facets = payload.get("facets", {})
    if not isinstance(facets, dict):
        raise SpiderError("[API_SCHEMA] facets must be an object.")
    raw_rows = facets.get(facet, [])
    if not isinstance(raw_rows, list):
        raise SpiderError("[API_SCHEMA] The requested facet must be a list.")
    rows: list[FacetRow] = []
    problems: list[str] = []
    seen = set()
    if facet not in facets and total:
        problems.append("The API did not return the requested facet; records may lack this field or the facet is unavailable.")
    for raw in raw_rows:
        if not isinstance(raw, dict):
            raise SpiderError("[API_SCHEMA] Every facet row must be an object.")
        count = api_integer(raw.get("count"), "facet count")
        value = raw.get("value")
        if facet in ("asn", "port") and isinstance(value, int) and not isinstance(value, bool):
            value = str(value)
        if not isinstance(value, str) or not value.strip():
            problems.append("A facet bucket had no usable value and was skipped.")
            continue
        value = value.strip()
        if len(value) > 500 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            problems.append("A facet bucket contained an invalid value and was skipped.")
            continue
        if facet == "country":
            if not re.fullmatch(r"[A-Za-z]{2}", value):
                problems.append("A country bucket lacked a two-letter code and was skipped.")
                continue
            value = value.upper()
        elif facet == "asn" and not re.fullmatch(r"(?:[Aa][Ss])?[0-9]{1,10}", value):
            problems.append("An ASN bucket was invalid and was skipped.")
            continue
        elif facet == "port":
            if not re.fullmatch(r"[0-9]{1,5}", value) or not 0 <= int(value) <= 65535:
                problems.append("A port bucket was invalid and was skipped.")
                continue
            value = str(int(value))
        if value in seen:
            problems.append("A duplicate facet bucket was visited once; counts were not added.")
            continue
        seen.add(value)
        rows.append(FacetRow(value=value, count=count, label=value))
    if total == 0 and rows:
        raise SpiderError("[API_SCHEMA] Facet rows were returned with total=0.")
    return FacetPage(facet=facet, rows=rows, total=total,
                     warnings=list(dict.fromkeys(problems)), explicit_empty=total == 0 and not rows)


class ApiCrawler(Crawler):
    """Official count facets for the tree; paginated search for every IP leaf."""
    def __init__(self, args: argparse.Namespace, client: Any = None,
                 clock: Callable[[], float] = time.monotonic, sleeper: Callable[[float], None] = time.sleep,
                 continue_prompt: Callable[[str], bool] | None = None, wall_clock: Callable[[], float] = time.time):
        super().__init__(args, clock=clock, sleeper=sleeper, continue_prompt=continue_prompt, wall_clock=wall_clock)
        if not args.api_key_resolved:
            raise SpiderError("[API_KEY] Supply --api-key, or set SHODAN_API_KEY.")
        _REGISTERED_SECRETS.add(args.api_key_resolved)
        self.client = client or ShodanAPIClient(args.api_key_resolved, transport=args.transport,
                                               timeout=args.timeout, ca_bundle=args.ca_bundle,
                                               user_agent=args.user_agent)
        self.report.update(source="shodan-api", api_count_requests=0, api_search_requests=0, api_leaves=[])
        self.report["settings"].update(requires_api_key=True, api_key_source=args.api_key_source,
                                        api_facet_limit=args.api_facet_limit, api_page_size=100,
                                        user_agent=args.user_agent or API_DEFAULT_USER_AGENT)
        self.report["coverage_note"] = "Official API facets may omit buckets/missing fields. IP leaves paginate by banner records, 100 per page. Permission, credits, changing data and request limits still apply."

    def request_api(self, path: str, params: dict[str, Any], facet: str) -> tuple[dict[str, Any], dict[str, Any]]:
        template = {"query": params["query"], "facet": facet, "api_endpoint": path, "api_page": params.get("page"),
                 "url": "https://api.shodan.io" + path + "?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)}
        counter = "api_search_requests" if path.endswith("/search") else "api_count_requests"
        page_label = f" page={params['page']}" if "page" in params else ""
        payload, entry = self._request_with_rate_limits(lambda: self.client.request(path, params),
                            template, f"API {facet.upper()}{page_label}", counter=counter)
        try:
            if not isinstance(payload, dict):
                raise SpiderError("[API_SCHEMA] Expected a JSON object.")
            if payload.get("error"):
                raise SpiderError("[API_ERROR] " + safe_detail(payload["error"]))
            self.report["pages_read"] += 1
            entry["status"] = "received"
            return payload, entry
        except (ShodanAPIError, SpiderError, OSError) as exc:
            message = safe_detail(exc)
            entry.update(status="failed", error=message)
            raise SpiderError(message) from None
        except KeyboardInterrupt:
            entry.update(status="interrupted", error="KeyboardInterrupt")
            raise

    def read_page(self, query: str, facet: str, expected: int | None = None) -> FacetPage:
        cache_key = (query, facet)
        if cache_key in self.cache:
            self.report["cache_hits"] += 1
            return self.cache[cache_key]
        if facet == "ip":
            page = self.read_ip_pages(query, expected)
        else:
            payload, entry = self.request_api("/shodan/host/count", {
                "query": query, "facets": f"{facet}:{self.args.api_facet_limit}"}, facet)
            try:
                page = parse_api_facet(payload, facet)
                entry.update(status="parsed", api_total=page.total)
                self.inspect_coverage(page, entry, expected, limit=self.args.api_facet_limit)
            except SpiderError as exc:
                entry.update(status="failed", error=safe_detail(exc))
                raise
        self.cache[cache_key] = page
        self.checkpoint("running")
        return page

    def read_ip_pages(self, query: str, expected: int | None) -> FacetPage:
        saved = self.api_progress.get(query)
        counts: dict[str, int] = dict(saved["counts"]) if saved else {}
        first_total: int | None = saved["first_total"] if saved else None
        number = saved["next_page"] if saved else 1
        target_pages = saved["target_pages"] if saved else 1
        received = saved["received"] if saved else 0
        known_ids: set[str] = set(saved["known_ids"]) if saved else set()
        summary = {"query": query, "facet": "ip", "status": "running", "search_pages": number - 1,
                   "records_received": received, "parent_expected_count": expected,
                   "resumed_at_page": number if saved else None}
        if saved:
            summary.update(first_total=first_total, planned_search_pages=target_pages)
        self.report["api_leaves"].append(summary)
        try:
            while number <= target_pages:
                payload, entry = self.request_api("/shodan/host/search", {
                    "query": query, "page": number, "minify": "true"}, "ip")
                try:
                    total = api_integer(payload.get("total"), "total")
                    records = payload.get("matches")
                    if not isinstance(records, list) or len(records) > 100:
                        raise SpiderError("[API_SCHEMA] matches must be a list of at most 100 records per page.")
                    if any(not isinstance(row, dict) for row in records):
                        raise SpiderError("[API_SCHEMA] Every search match must be an object.")
                    if total == 0 and records:
                        raise SpiderError("[API_SCHEMA] Search matches were returned with total=0.")
                    if first_total is None:
                        first_total = total
                        target_pages = max(1, (total + 99) // 100)
                        summary.update(first_total=first_total, planned_search_pages=target_pages)
                    elif total != first_total:
                        self.warning("API_TOTAL_CHANGED", f"Search total changed from {first_total} to {total} during pagination; original page count is retained.", query, "ip")
                    entry.update(status="parsed", api_total=total, records_received=len(records))
                    summary["search_pages"] += 1
                    if not records and (number > 1 or total > 0):
                        raise SpiderError("[API_EMPTY_PAGE] An empty page arrived before expected results were collected; traversal stopped.")
                    received += len(records)
                    summary["records_received"] = received
                    invalid = 0
                    repeated_ids = 0
                    for row in records:
                        value = row.get("ip_str")
                        address = parse_ip(value) if isinstance(value, str) else None
                        if address is None:
                            invalid += 1
                            continue
                        self.accept_ip(address)  # Preserve each page immediately for --save-partial.
                        text = str(address)
                        counts[text] = counts.get(text, 0) + 1
                        metadata = row.get("_shodan")
                        identity = metadata.get("id") if isinstance(metadata, dict) else None
                        if isinstance(identity, str) and identity:
                            repeated_ids += int(identity in known_ids)
                            known_ids.add(identity)
                    if invalid:
                        self.warning("API_INVALID_IP", f"Skipped {invalid} search records without a valid IP address.", query, "ip")
                    if repeated_ids:
                        self.warning("API_REPEATED_BANNER", f"Observed {repeated_ids} repeated banner IDs; changing/repeated pages can reduce coverage.", query, "ip")
                    if len(records) < 100 and number < target_pages:
                        self.warning("API_SHORT_PAGE", f"Page {number} returned {len(records)} records before the planned last page; continuing with the next page.", query, "ip")
                    entry["unique_ips_collected_so_far"] = len(self.accepted)
                    self.progress(f"    API records received in leaf: {received}; unique IPs collected: {len(self.accepted)}")
                except SpiderError as exc:
                    entry.update(status="failed", error=safe_detail(exc))
                    raise
                number += 1
                self.api_progress[query] = {"counts": dict(counts), "first_total": first_total,
                                            "next_page": number, "target_pages": target_pages,
                                            "received": received, "known_ids": sorted(known_ids)}
                self.checkpoint("running")
            page = FacetPage(facet="ip", rows=[FacetRow(value=ip, count=count, label=ip) for ip, count in counts.items()],
                             total=first_total, warnings=[], explicit_empty=first_total == 0)
            summary["status"] = "finished"
            self.inspect_coverage(page, summary, expected, limit=None)
            self.api_progress.pop(query, None)
            return page
        except (SpiderError, KeyboardInterrupt) as exc:
            summary.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed",
                           error=safe_detail(exc) or "KeyboardInterrupt", unique_ips_in_leaf=len(counts))
            raise


def render_output(report: dict[str, Any], format_name: str) -> str:
    if format_name == "json":
        return json.dumps({"version": VERSION, "query": report["original_query"], "status": report["status"],
                           "complete_export": False, "unique_ip_count": report["unique_ip_count"],
                           "ips": report["ips"]}, ensure_ascii=False, indent=2) + "\n"
    if format_name == "csv":
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["ip", "version"])
        writer.writerows((ip, ipaddress.ip_address(ip).version) for ip in report["ips"])
        return stream.getvalue()
    return "".join(ip + "\n" for ip in report["ips"])


def preflight_output(path: Path | None, force: bool) -> None:
    if path is None:
        return
    if not path.parent.is_dir():
        raise SpiderError(f"[OUTPUT] Directory does not exist: {safe_detail(path.parent)}")
    if path.is_symlink():
        raise SpiderError(f"[OUTPUT] Refusing symbolic-link output: {safe_detail(path)}")
    if os.path.lexists(path):
        if not path.is_file():
            raise SpiderError(f"[OUTPUT] Not a regular file: {safe_detail(path)}")
        if not force:
            raise SpiderError(f"[OUTPUT] File exists: {safe_detail(path)}. Choose another name or add --force.")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def preflight(args: argparse.Namespace) -> None:
    related = [path.absolute() for path in (args.output, args.report_path, args.checkpoint) if path is not None]
    if args.checkpoint is not None:
        related.append(Path(str(args.checkpoint) + ".lock").absolute())
    if len({str(p.resolve()) for p in related}) != len(related):
        raise SpiderError("[CHECKPOINT_PATH] Output, report, checkpoint and checkpoint lock must be different files.")
    if args.checkpoint is not None:
        preflight_output(args.checkpoint, args.force or args.resume is not None)
    if args.resume_payload is not None and not args.force:
        hashes = args.resume_payload["state"].get("output_hashes", {})
        if not isinstance(hashes, dict):
            raise SpiderError("[CHECKPOINT_STATE] Invalid saved output ownership.")
        for path in (args.output, args.report_path):
            if path is not None and os.path.lexists(path):
                preflight_output(path, True)
                expected = hashes.get(str(path.absolute()))
                if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or file_sha256(path) != expected:
                    raise SpiderError("[RESUME_OUTPUT_CHANGED] Existing output/report is not the saved checkpoint version; choose --force only if replacement is intended.")
        args.resume_output_owned = True
    for path in (args.output, args.report_path):
        preflight_output(path, args.force or args.resume_output_owned)
    if args.from_html is not None:
        if not args.from_html.is_file():
            raise SpiderError("[INPUT] --from-html must point to a regular file.")
        for path in (args.output, args.report_path):
            if path is not None and path.resolve() == args.from_html.resolve():
                raise SpiderError("[OUTPUT] Input HTML and output/report must be different files.")
    elif args.transport == "curl" and shutil.which("curl") is None:
        raise SpiderError("[DEPENDENCY] Install curl or use --transport python.")
    if args.ca_bundle is not None and not args.ca_bundle.is_file():
        raise SpiderError("[CA_BUNDLE] Trusted CA bundle must be a regular file.")


def write_output_pair(files: list[tuple[Path, str]], force: bool) -> None:
    """Stage both files first, commit each atomically, rollback caught I/O failures.

    There is no portable two-file atomic rename. A power loss/process kill may
    interrupt the pair; the report records the output SHA-256 for verification.
    """
    staged: list[dict[str, Any]] = []
    try:
        for path, content in files:
            preflight_output(path, force)
            fd, name = tempfile.mkstemp(prefix=".shodan-stage-", dir=str(path.parent))
            item = {"target": path, "temp": Path(name), "backup": None,
                    "committed": False, "retain_backup": False}
            staged.append(item)
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            item["inode"] = os.stat(name).st_ino
        for item in staged:
            path = item["target"]
            preflight_output(path, force)
            if force and path.exists():
                fd, backup = tempfile.mkstemp(prefix=".shodan-backup-", dir=str(path.parent))
                os.close(fd)
                os.unlink(backup)
                os.link(path, backup)
                item["backup"] = Path(backup)
            if force:
                os.replace(item["temp"], path)
            else:
                os.link(item["temp"], path)
            item["committed"] = True
    except (OSError, SpiderError, KeyboardInterrupt) as exc:
        rollback_failed = []
        for item in reversed(staged):
            if not item["committed"]:
                continue
            try:
                path = item["target"]
                if path.is_symlink() or not path.exists() or path.stat().st_ino != item["inode"]:
                    raise OSError("Target changed during rollback")
                if item["backup"] is not None:
                    os.replace(item["backup"], path)
                else:
                    path.unlink()
            except OSError:
                item["retain_backup"] = True
                detail = str(item["target"])
                if item["backup"] is not None:
                    detail += " (previous contents retained at " + str(item["backup"]) + ")"
                rollback_failed.append(detail)
        if rollback_failed:
            raise SpiderError("[OUTPUT_ROLLBACK] Could not restore all files; inspect: " + ", ".join(rollback_failed)) from exc
        raise
    finally:
        for item in staged:
            for key in ("temp", "backup"):
                path = item[key]
                if path is not None and not (key == "backup" and item["retain_backup"]):
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
                    except OSError:
                        # Keep the original result/error; a private staging file
                        # is less harmful than masking it with a cleanup error.
                        pass


def save_results(args: argparse.Namespace, report: dict[str, Any]) -> None:
    report = redact_report(report, getattr(args, "api_key_resolved", None))
    output = render_output(report, args.format)
    output_path = str(args.output) if args.output else "stdout"
    if args.api_key_resolved:
        output_path = api_redact(output_path, args.api_key_resolved)
    report["output"] = {"path": output_path, "format": args.format,
                        "sha256": hashlib.sha256(output.encode("utf-8")).hexdigest()}
    if args.output is None:
        sys.stdout.write(output)
        sys.stdout.flush()
    else:
        write_output_pair([(args.output, output), (args.report_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")], args.force or args.resume_output_owned)


def run_session(args: argparse.Namespace) -> int:
    resolve_api_key(args)
    if args.debug:
        print_debug_settings(args)
    crawler = ApiCrawler(args) if args.mode == "api" else Crawler(args)
    crawler.checkpoint("starting")
    failure_code = 0
    try:
        report = crawler.run()
    except (SpiderError, OSError, KeyboardInterrupt) as exc:
        interrupted = isinstance(exc, KeyboardInterrupt)
        paused = isinstance(exc, PauseRequested)
        message = "KeyboardInterrupt: stopped by user" if interrupted else safe_detail(exc)
        status = "interrupted" if interrupted else "paused" if paused else "failed"
        report = crawler.finish(status, message)
        crawler.checkpoint(status)
        print("\n" + ("Paused: " if paused else "Error: ") + message, file=sys.stderr)
        if args.checkpoint is not None:
            print("Checkpoint saved. Resume with:\n  bash shodan_spider-v6.sh --resume " +
                  shlex.quote(str(args.checkpoint)), file=sys.stderr)
        failure_code = 130 if interrupted else 75 if paused else 3 if args.save_partial else 1
        if not args.save_partial:
            print("No new output/report saved; existing files were left unchanged. Use --save-partial to opt in to partial saving.", file=sys.stderr)
            return failure_code
        report["partial_saved"] = True
    save_results(args, report)
    if args.checkpoint is not None:
        crawler.capture_output_hashes()
        crawler.checkpoint(report["status"])
    if not args.quiet:
        print(f"Status: {report['status']}; unique IPs: {report['unique_ip_count']}; filtered: {report['unique_candidates_filtered']}; requests: {report['requests_attempted']}.", file=sys.stderr)
        if args.output is not None:
            print(f"Saved: {safe_detail(args.output)}\nReport: {safe_detail(args.report_path)}", file=sys.stderr)
    if failure_code:
        print("Partial results were saved; traversal did not finish. Read the report before using the list.", file=sys.stderr)
        return failure_code
    return 3 if report["warnings"] else 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    crawler: Crawler | None = None
    try:
        if args.dry_run:
            first_url = None if args.from_html else (
                "https://api.shodan.io/shodan/host/count?" + urllib.parse.urlencode({
                    "query": args.effective_query, "facets": f"country:{args.api_facet_limit}"})
                if args.mode == "api" else build_url(args.effective_query, "country"))
            plan = {"version": VERSION, "mode": args.mode,
                              "original_query": args.effective_query,
                              "first_url": first_url,
                              "workflow": ("country -> city -> split oversized branches -> globally descending <=100 leaves -> fallback leaves"
                                           if args.strategy == "priority" else
                                           "country -> city -> asn -> ip" if args.always_asn else
                                           "country -> city -> (asn when count >100 or unknown) -> ip"),
                              "strategy": args.strategy, "split_facets": list(args.split_facets),
                              "max_plan_nodes": args.max_plan_nodes,
                              "output": str(args.output) if args.output else "stdout",
                              "report": str(args.report_path) if args.report_path else None,
                              "transport": args.transport, "requires_api_key": args.mode == "api",
                              "api_key_source": args.api_key_source,
                              "api_facet_limit": args.api_facet_limit if args.mode == "api" else None,
                              "api_search_page_size": 100 if args.mode == "api" else None,
                              "network_requests_made": 0, "max_requests": args.max_requests,
                              "delay_seconds": args.delay, "complete_export_guaranteed": False,
                              "user_agent": args.user_agent or (API_DEFAULT_USER_AGENT if args.mode == "api" else USER_AGENT),
                              "rate_limit_retries": args.rate_limit_retries,
                              "retry_base_delay_seconds": args.retry_base_delay,
                              "max_retry_wait_seconds": args.max_retry_wait,
                              "rotate_user_agents": args.rotate_user_agents, "on_rate_limit": args.on_rate_limit,
                              "checkpoint": str(args.checkpoint) if args.checkpoint else None,
                              "resuming": args.resume is not None}
            print(json.dumps(redact_report(plan, args.api_key_resolved), ensure_ascii=False, indent=2))
            return 0
        preflight(args)
        lock = CheckpointLock(args.checkpoint) if args.checkpoint is not None else contextlib.nullcontext()
        with lock:
            if args.resume_payload is not None:
                if load_checkpoint(args.checkpoint) != args.resume_payload:
                    raise SpiderError("[CHECKPOINT_CHANGED] State changed while preparing resume; retry with the current checkpoint.")
            return run_session(args)
    except BrokenPipeError:
        try:
            with open(os.devnull, "w") as sink:
                os.dup2(sink.fileno(), sys.stdout.fileno())
        except (OSError, io.UnsupportedOperation):
            pass
        return 1
    except (SpiderError, ShodanAPIError, CheckpointError, OSError) as exc:
        print("Error: " + safe_detail(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted during preparation or output writing.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    if sys.version_info < (3, 10):
        print("Error: Python 3.10+ is required.", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(main())

SHODAN_SPIDER_V7_PYTHON
