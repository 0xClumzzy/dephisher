#!/usr/bin/env python3
"""dephisher  SOC phishing URL triage kit.

Offline by default; pass --enrich to allow bounded network lookups
(DNS, redirect chain, RDAP age, optional VirusTotal).

Exit codes: 0 = benign/allowlisted only, 1 = suspicious present,
            2 = likely malicious present, 127 = environment error.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))

import analyze   # noqa: E402
import enrich    # noqa: E402
import extract   # noqa: E402
import report    # noqa: E402

CONFIG_DIR = os.path.join(HERE, "config")

EXIT_OK, EXIT_SUSPICIOUS, EXIT_MALICIOUS = 0, 1, 2


def _default(name):
    return os.path.join(CONFIG_DIR, name)


def collect_urls(sources, raw_urls):
    """Yield (url, source_label) from files/stdin/inline URLs."""
    for raw in raw_urls or []:
        for url in extract.urls_from_text(extract.refang(raw)):
            yield url, "--url"

    for source in sources or ["-"]:
        if source == "-":
            text = sys.stdin.read()
            urls = extract.urls_from_text(extract.refang(text))
            label = "<stdin>"
        elif source.startswith(("http://", "https://", "hxxp://", "hxxps://")):
            for url in extract.urls_from_text(extract.refang(source)):
                yield url, "--url"
            continue
        else:
            try:
                urls = extract.urls_from_eml(source)
                label = source
            except OSError as exc:
                print(f"dephisher: cannot read {source}: {exc}", file=sys.stderr)
                continue
            if not urls:
                # Fall back to plain-text extraction (non-email files).
                try:
                    with open(source, encoding="utf-8", errors="replace") as fh:
                        urls = extract.urls_from_text(extract.refang(fh.read()))
                except OSError:
                    urls = []
        for url in urls:
            yield url, label


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="dephisher",
        description="Triage URLs extracted from reported phishing emails.",
    )
    parser.add_argument("files", nargs="*",
                        help=".eml files or text files with URLs (default: stdin)")
    parser.add_argument("-u", "--url", action="append", metavar="URL",
                        help="analyze a single URL (repeatable)")
    parser.add_argument("--enrich", action="store_true",
                        help="allow network lookups (DNS, redirect chain, RDAP, VT if keyed)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--csv", metavar="PATH", help="write defanged IOC CSV to PATH")
    parser.add_argument("--brands", default=_default("brands.txt"),
                        help="brand wordlist for typosquat checks")
    parser.add_argument("--allowlist", default=_default("allowlist.txt"),
                        help="trusted domains (findings forced to ALLOWLISTED)")
    parser.add_argument("--tlds", default=_default("suspicious_tlds.txt"),
                        help="abused-TLD wordlist")
    parser.add_argument("--shorteners", default=_default("shorteners.txt"),
                        help="URL-shortener wordlist")
    args = parser.parse_args(argv)

    if not args.files and not args.url:
        args.files = ["-"]

    brands = analyze.load_wordlist(args.brands)
    allowlist = analyze.load_wordlist(args.allowlist)
    suspicious_tlds = analyze.load_wordlist(args.tlds) or set(analyze.DEFAULT_SUSPICIOUS_TLDS)
    shorteners = analyze.load_wordlist(args.shorteners) or set(analyze.DEFAULT_SHORTENERS)

    results, seen = [], set()
    for url, source in collect_urls(args.files, args.url):
        key = url.lower()
        if key in seen:
            continue
        seen.add(key)

        result = analyze.analyze_url(
            url,
            brands=brands,
            allowlist=allowlist,
            suspicious_tlds=suspicious_tlds,
            shorteners=shorteners,
        )
        result["source"] = source
        if args.enrich:
            try:
                enrich.enrich(result)
            except Exception as exc:  # enrichment must never abort a triage run
                result["signals"].append(analyze._sig("enrich_error", analyze.LOW,
                                                      f"enrichment failed: {exc}"))
        result.update(analyze.finalize(result, allowlist))
        results.append(result)

    if not results:
        print("dephisher: no URLs found in input", file=sys.stderr)
        return EXIT_OK

    if args.json:
        report.dump_json(results)
    else:
        report.render(results)

    if args.csv:
        report.write_csv(results, args.csv)
        if not args.json:
            print(f"\n IOC CSV written: {args.csv}")

    if any(r["verdict"] == "LIKELY MALICIOUS" for r in results):
        return EXIT_MALICIOUS
    if any(r["verdict"] == "SUSPICIOUS" for r in results):
        return EXIT_SUSPICIOUS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
