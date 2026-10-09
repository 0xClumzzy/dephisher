"""Optional network enrichment (opt-in via --enrich).

Safety rails:
  * only http/https targets
  * private/loopback/link-local/reserved addresses are refused (SSRF guard)
  * bounded redirect hops, short timeouts, no body downloads
  * VirusTotal lookups only when VT_API_KEY is set
"""

import ipaddress
import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from analyze import HIGH, LOW, MED, _sig

USER_AGENT = "phish-defend/1.0 (+SOC phishing triage; passive analysis)"
TIMEOUT = 6
MAX_HOPS = 6
RDAP_NEW_DOMAIN_DAYS = 180

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface redirects as HTTPError so we can record each hop ourselves."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class EnrichmentError(Exception):
    pass


def _guard_host(host):
    """Resolve a host and refuse anything that isn't a public address."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise EnrichmentError(f"DNS resolution failed: {exc}") from exc

    addresses = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if not ip.is_global:
            raise EnrichmentError(f"refusing non-public address {ip} for '{host}' (SSRF guard)")
        addresses.append(str(ip))
    if not addresses:
        raise EnrichmentError(f"no addresses for '{host}'")
    return sorted(set(addresses))


def _get(url, timeout=TIMEOUT, no_redirect=True):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    opener = _OPENER if no_redirect else urllib.request.build_opener()
    return opener.open(request, timeout=timeout)


def dns_lookup(host):
    """Return (ips, signal|None)."""
    try:
        return _guard_host(host), None
    except EnrichmentError as exc:
        message = str(exc)
        if "DNS resolution failed" in message or "no addresses" in message:
            return [], _sig("dead_dns", MED, f"host no longer resolves ({host})")
        # Private-address refusal is a *positive* signal on an attacker URL.
        return [], _sig("internal_target", HIGH, message)


def follow_chain(url, max_hops=MAX_HOPS):
    """Follow redirects, recording the chain. Returns (chain, final_url, signals)."""
    chain, signals = [], []
    current = url

    for _hop in range(max_hops + 1):
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https"):
            signals.append(_sig("scheme_change", MED, f"redirect ends in non-HTTP scheme '{parts.scheme}:'"))
            break
        if not parts.hostname:
            break
        chain.append(current)

        try:
            _guard_host(parts.hostname)
        except EnrichmentError as exc:
            signals.append(_sig("redirect_internal", HIGH,
                                f"redirect points inside the network: {exc}"))
            break

        try:
            response = _get(current)
            status, location = response.status, response.headers.get("Location")
            response.close()
        except urllib.error.HTTPError as exc:
            status, location = exc.code, exc.headers.get("Location")
            exc.close()
        except ssl.SSLError:
            signals.append(_sig("tls_error", MED, f"TLS handshake failed at hop {_hop + 1} ({parts.hostname})"))
            break
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            signals.append(_sig("unreachable", MED, f"hop {_hop + 1} failed: {exc}"))
            break

        if status in (301, 302, 303, 307, 308) and location:
            current = urljoin(current, location)
            continue
        break

    if len(chain) >= 3:
        signals.append(_sig("redirect_chain", MED, f"{len(chain)}-hop redirect chain"))
    return chain, (chain[-1] if chain else url), signals


def rdap_age(domain):
    """Registration age in days via public RDAP bootstrap. Returns (days, signal|None)."""
    try:
        with _get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT, no_redirect=False) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except Exception as exc:
        return None, _sig("rdap_failed", LOW, f"RDAP lookup failed: {exc}")

    for event in data.get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            try:
                stamp = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                continue
            days = max(0, (datetime.now(timezone.utc) - stamp).days)
            if days <= RDAP_NEW_DOMAIN_DAYS:
                return days, _sig("new_domain", MED,
                                  f"domain registered {days} day(s) ago (< {RDAP_NEW_DOMAIN_DAYS})")
            return days, None
    return None, None


def virustotal_lookup(domain):
    """Query VirusTotal for a domain. Returns signal or None (needs VT_API_KEY)."""
    api_key = os.environ.get("VT_API_KEY")
    if not api_key or not domain:
        return None
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": api_key, "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        if malicious > 0:
            return _sig("vt_flagged", HIGH, f"VirusTotal: {malicious} engine(s) flag this domain")
    except Exception:
        return _sig("vt_failed", LOW, "VirusTotal lookup failed (rate limit or bad key)")
    return None


def enrich(result):
    """Append network-derived signals to an analyze_url() result (in place)."""
    host = result.get("host") or ""
    if not host:
        return result

    ips, signal = dns_lookup(host)
    if signal:
        result["signals"].append(signal)
    result["ips"] = ips

    chain, final_url, chain_signals = follow_chain(result["url"])
    result["chain"] = chain
    result["final_url"] = final_url
    result["signals"].extend(chain_signals)

    days, age_signal = rdap_age(result["domain"])
    result["age_days"] = days
    if age_signal:
        result["signals"].append(age_signal)

    vt_signal = virustotal_lookup(result["domain"])
    if vt_signal:
        result["signals"].append(vt_signal)

    return result
