"""Passive URL risk analysis — no network I/O.

Each check appends a signal {code, severity, detail}; severity weights
(25/12/5) sum into a 0-100 score that maps to a verdict.
"""

import ipaddress
import re
from urllib.parse import urlsplit

HIGH, MED, LOW = "high", "med", "low"
WEIGHTS = {HIGH: 25, MED: 12, LOW: 5}

MALICIOUS_AT = 40
SUSPICIOUS_AT = 15

DANGEROUS_SCHEMES = ("data", "javascript", "file", "vbscript", "jar")

DEFAULT_SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu", "cfd",
    "buzz", "click", "link", "work", "stream", "wtf", "lol", "rest", "beauty",
    "sbs", "cyou", "monster", "quest", "hair", "boats", "day", "hw",
}

DEFAULT_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly", "buff.ly",
    "cutt.ly", "cutt.us", "rebrand.ly", "t.ly", "s.id", "rb.gy", "shorturl.at",
    "bc.vc", "adf.ly", "bl.ink", "soo.gd", "v.gd", "cla.gs", "u.to", "po.st",
}

CREDENTIAL_WORDS = {
    "login", "logon", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "password", "passwd", "credential",
    "unlock", "suspend", "invoice", "wallet", "banking", "authenticate",
    "session", "reactivate", "unusual",
}

REDIRECT_PARAMS = {
    "url", "u", "redirect", "redirect_uri", "redirect_url", "next", "target",
    "dest", "destination", "continue", "return", "returnurl", "goto", "link",
    "out", "r", "redir", "checkout_url",
}

TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr",
    "com.br", "com.mx", "com.ar", "com.tr", "com.tw", "com.hk", "com.cn",
    "com.sg", "com.my", "com.pl", "com.ua", "co.in", "co.za", "com.co",
}

_RE_DIGIT_RUN = re.compile(r"\d{3,}")
_RE_OBFUSCATION = re.compile(r"(?i)%00|%0d|%0a|%09|%0d%0a")
_RE_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)


# --- helpers ---------------------------------------------------------------

def load_wordlist(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return {
                line.strip().lower()
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            }
    except OSError:
        return set()


def levenshtein(a, b, cap=4):
    """Edit distance, early-exit above `cap` (used for typosquat checks)."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        if min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]


def registrable_domain(host):
    """Approximate eTLD+1 without a PSL dependency."""
    if not host or "." not in host:
        return host or ""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    suffix = ".".join(labels[-2:])
    if suffix in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return suffix


def is_allowlisted(domain, allowlist):
    if not domain:
        return False
    domain = domain.lower()
    return any(domain == entry or domain.endswith("." + entry) for entry in allowlist)


def _sig(code, severity, detail):
    return {"code": code, "severity": severity, "detail": detail}


# --- analysis --------------------------------------------------------------

def analyze_url(url, brands=(), allowlist=(), suspicious_tlds=None, shorteners=None):
    suspicious_tlds = suspicious_tlds if suspicious_tlds is not None else DEFAULT_SUSPICIOUS_TLDS
    shorteners = shorteners if shorteners is not None else DEFAULT_SHORTENERS

    result = {
        "url": url,
        "signals": [],
        "host": "",
        "domain": "",
        "allowlisted": False,
    }
    signals = result["signals"]

    # Dangerous schemes: never fetchable, always report immediately.
    scheme_match = _RE_SCHEME.match(url)
    scheme = scheme_match.group(0).rstrip(":").lower() if scheme_match else ""
    if scheme in DANGEROUS_SCHEMES:
        signals.append(_sig("dangerous_scheme", HIGH, f"'{scheme}:' scheme executes or embeds content"))
        result.update(finalize(result, allowlist))
        return result

    if scheme not in ("http", "https", "ftp"):
        signals.append(_sig("no_scheme", MED, "relative or scheme-less URL — verify link target"))
        result.update(finalize(result, allowlist))
        return result

    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        signals.append(_sig("unparseable", MED, "URL parser rejected this URL"))
        result.update(finalize(result, allowlist))
        return result

    if not host:
        signals.append(_sig("no_host", HIGH, "URL has no resolvable host"))
        result.update(finalize(result, allowlist))
        return result

    result["host"] = host
    try:
        ipaddress.ip_address(host.strip("[]"))
        result["domain"] = host          # raw IP: the IP itself is the IOC
    except ValueError:
        result["domain"] = registrable_domain(host)
    result["allowlisted"] = is_allowlisted(result["domain"], allowlist)
    if result["allowlisted"]:
        # Still collect signals for the record, but the verdict is forced below.
        pass

    # --- host checks ---
    try:
        ipaddress.ip_address(host.strip("[]"))
        signals.append(_sig("ip_literal", HIGH, f"host is a raw IP ({host}) — no domain to validate"))
    except ValueError:
        pass

    if "@" in parts.netloc:
        signals.append(_sig("userinfo_trick", HIGH, "'@' in URL hides the real destination host"))

    if parts.port and parts.port not in (80, 443, 21):
        signals.append(_sig("odd_port", MED, f"non-standard port {parts.port}"))

    if parts.scheme == "http":
        signals.append(_sig("plain_http", LOW, "no TLS — credential theft possible if real"))

    if "." not in host:
        signals.append(_sig("single_label_host", HIGH, "single-label host (mDNS/internal name?)"))

    # Punycode / homograph.
    if any(label.startswith("xn--") for label in host.split(".")):
        detail = "punycode (xn--) label — possible homograph lookalike"
        try:
            decoded = host.encode("ascii").decode("idna")
            if any(ord(ch) > 127 for ch in decoded):
                detail = f"punycode label decodes to {decoded!r} — homograph lookalike risk"
        except Exception:
            pass
        signals.append(_sig("punycode", HIGH, detail))

    # Typosquatting + brand-in-subdomain.
    labels = host.split(".")
    reg = result["domain"]
    reg_labels = set(reg.split("."))
    for label in labels:
        if len(label) < 4:
            continue  # skip TLDs and short labels (com/net/org never typo-match)
        for brand in brands:
            if not brand or len(brand) < 4:
                continue
            if label == brand or brand in reg_labels:
                continue
            if abs(len(label) - len(brand)) <= 2 and levenshtein(label, brand) <= 2:
                signals.append(_sig("typosquat", HIGH,
                                    f"'{label}' is {levenshtein(label, brand)} edit(s) from brand '{brand}'"))
                break

    for brand in brands:
        if brand and brand in labels and brand not in reg_labels and brand not in reg.split("-"):
            signals.append(_sig("brand_subdomain", HIGH,
                                f"brand '{brand}' appears only as a subdomain; real domain is '{reg}'"))
            break

    # --- domain / TLD checks ---
    tld = labels[-1] if labels else ""
    if tld in suspicious_tlds:
        signals.append(_sig("suspicious_tld", MED, f"TLD .{tld} is frequently abused"))

    if result["domain"] in shorteners:
        signals.append(_sig("shortener", MED, "URL shortener hides the final destination"))

    if len(labels) > 5:
        signals.append(_sig("deep_subdomains", MED, f"{len(labels) - 2} subdomain levels — evasion/redirect churn"))

    for label in labels:
        if label.count("-") >= 3:
            signals.append(_sig("hyphen_heavy", LOW, f"label '{label}' has {label.count('-')} hyphens"))
            break

    for label in labels:
        if len(label) >= 5 and _RE_DIGIT_RUN.search(label):
            signals.append(_sig("digit_run", LOW, f"label '{label}' contains a 3+ digit run"))
            break

    # --- path / query checks ---
    full = url.lower()
    path_words = {word for word in CREDENTIAL_WORDS if word in full}
    if path_words:
        signals.append(_sig("credential_lure", MED,
                            f"credential-themed terms in URL: {', '.join(sorted(path_words))}"))

    from urllib.parse import parse_qs
    query = parse_qs(parts.query, keep_blank_values=True)
    overlap = set(query) & REDIRECT_PARAMS
    if overlap:
        signals.append(_sig("redirect_param", MED,
                            f"open-redirect style param: {', '.join(sorted(overlap))}"))

    if url.count("%") >= 8:
        signals.append(_sig("encoding_heavy", MED, "heavy percent-encoding — likely obfuscation"))
    if _RE_OBFUSCATION.search(url):
        signals.append(_sig("ctrl_encoding", HIGH, "percent-encoded control chars (%00/%0d/%0a)"))

    if len(url) > 200:
        signals.append(_sig("very_long", LOW, f"{len(url)} chars — long URLs hide the real host"))

    result.update(finalize(result, allowlist))
    return result


def finalize(result, allowlist=()):
    """Compute score + verdict from accumulated signals (call after enrichment)."""
    if result.get("allowlisted"):
        return {"score": 0, "verdict": "ALLOWLISTED"}
    score = min(100, sum(WEIGHTS[s["severity"]] for s in result["signals"]))
    if score >= MALICIOUS_AT:
        verdict = "LIKELY MALICIOUS"
    elif score >= SUSPICIOUS_AT:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"
    return {"score": score, "verdict": verdict}
