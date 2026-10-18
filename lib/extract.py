"""Extract URLs from .eml messages, HTML, or plain text.

Everything here is offline: no DNS, no HTTP. Defanged IOC text (hxxp://,
[.] etc.) is refanged first so analysts can paste straight from a report.
"""

import email
import email.policy
import re
from html.parser import HTMLParser
from urllib.parse import unquote

# --- refanging / defanging -------------------------------------------------

_REFANG_PATTERNS = [
    (re.compile(r"(?i)\bhxxp(s?)"), lambda m: "http" + m.group(1).lower()),
    (re.compile(r"(?i)\bfxp(s?)"), lambda m: "ftp" + m.group(1).lower()),
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*://\s*\]"), "://"),
]


def refang(text: str) -> str:
    """Undo common IOC defanging (hxxps://example[.]com -> https://example.com)."""
    for pattern, repl in _REFANG_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def defang(url: str) -> str:
    """Render a URL safely for reports/chat (hxxps://host[.]tld/path)."""
    from urllib.parse import urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return url.replace("http", "hxxp", 1)

    host = parts.hostname or ""
    dhost = host.replace(".", "[.]", 1) if "." in host else host

    userinfo = ""
    port = ""
    if parts.port:
        port = f":{parts.port}"
    if "@" in parts.netloc:
        userinfo = parts.netloc.rsplit("@", 1)[0] + "@"

    scheme = parts.scheme.replace("http", "hxxp", 1)
    return urlunsplit((scheme, f"{userinfo}{dhost}{port}", parts.path, parts.query, parts.fragment))


# --- URL recognition -------------------------------------------------------

_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"']+")


def _clean(raw: str) -> str:
    """Strip trailing punctuation left over from prose matching."""
    return raw.rstrip(".,;:!?\"'<>)]}")


def _iter_urls(text: str):
    for match in _URL_RE.finditer(text):
        url = _clean(match.group(0))
        if url:
            # Some mailers HTML-encode separators in the plain-text view.
            yield unquote(url).strip()


# --- HTML ------------------------------------------------------------------

class _HrefParser(HTMLParser):
    _ATTRS = ("href", "src", "action", "data-url", "formaction", "background")

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        for attr in self._ATTRS:
            value = values.get(attr)
            if value and value.lower().startswith(("http://", "https://", "ftp://")):
                self.links.append(value.strip())


def urls_from_html(html: str):
    parser = _HrefParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # Malformed HTML still usually survives regex extraction.
        parser.links = []
    return list(parser.links) + list(_iter_urls(html))


# --- public API ------------------------------------------------------------

def urls_from_text(text: str):
    """Extract URLs from arbitrary text (already refanged by callers)."""
    return list(_iter_urls(text))


def urls_from_eml(path: str):
    """Extract URLs from an RFC822 .eml file: bodies + useful headers."""
    with open(path, "rb") as fh:
        message = email.message_from_binary_file(fh, policy=email.policy.default)

    found = []

    # Header-level URLs: unsubscribe links are a common phishing vector.
    for header in ("List-Unsubscribe", "List-Unsubscribe-Post", "Reply-To", "X-Original-URL",
                   "X-Originating-URL", "X-Forwarded-For"):
        value = message.get(header)
        if value:
            found.extend(_iter_urls(refang(str(value))))

    # Body parts.
    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            try:
                payload = part.get_payload(decode=True) or b""
                content = payload.decode(part.get_content_charset() or "utf-8", "replace")
            except Exception:
                continue
        if not isinstance(content, str):
            continue

        content = refang(content)
        if content_type == "text/html":
            found.extend(urls_from_html(content))
        else:
            found.extend(urls_from_text(content))

    return _dedupe(found)


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out
