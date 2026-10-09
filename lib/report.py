"""Rendering: terminal report, JSON dump, IOC CSV export."""

import csv
import json
import sys

from extract import defang

MARKS = {
    "LIKELY MALICIOUS": "[!!]",
    "SUSPICIOUS": " [!]",
    "BENIGN": " [-]",
    "ALLOWLISTED": " [=]",
}

SEV_ORDER = {"high": 0, "med": 1, "low": 2}


def _signals_text(result):
    lines = []
    for signal in sorted(result["signals"], key=lambda s: SEV_ORDER.get(s["severity"], 3)):
        lines.append(f"       [{signal['severity'].upper():4}] {signal['code']}: {signal['detail']}")
    if not lines:
        lines.append("       (no risk signals)")
    return lines


def render(results, out=sys.stdout):
    width = 74
    print("=" * width, file=out)
    print(" phish-defend — phishing URL triage report", file=out)
    print("=" * width, file=out)

    for i, result in enumerate(results, 1):
        mark = MARKS.get(result["verdict"], " [?]")
        print(f"\n{mark} #{i}  score {result['score']:>3}  {result['verdict']}", file=out)
        print(f"      url    : {defang(result['url'])}", file=out)
        if result.get("host"):
            print(f"      host   : {result['host']}", file=out)
        print(f"      domain : {result.get('domain') or '-'}", file=out)
        if result.get("source"):
            print(f"      source : {result['source']}", file=out)
        if result.get("age_days") is not None:
            print(f"      age    : {result['age_days']} day(s) since registration", file=out)
        if result.get("ips"):
            print(f"      ip(s)  : {', '.join(result['ips'])}", file=out)
        if result.get("chain") and len(result["chain"]) > 1:
            print("      chain  :", file=out)
            for hop_no, hop in enumerate(result["chain"], 1):
                print(f"        {hop_no}. {defang(hop)}", file=out)
            if result.get("final_url") and result["final_url"] != result["chain"][-1]:
                print(f"        -> {defang(result['final_url'])}", file=out)
        print("      signals:", file=out)
        for line in _signals_text(result):
            print(line, file=out)

    # Summary
    counts = {"LIKELY MALICIOUS": 0, "SUSPICIOUS": 0, "BENIGN": 0, "ALLOWLISTED": 0}
    for result in results:
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
    print("\n" + "-" * width, file=out)
    print(f" summary: {counts['LIKELY MALICIOUS']} malicious, {counts['SUSPICIOUS']} suspicious, "
          f"{counts['BENIGN']} benign, {counts['ALLOWLISTED']} allowlisted "
          f"({len(results)} URL(s))", file=out)


def write_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["defanged_url", "host", "domain", "score", "verdict",
                         "signals", "source"])
        for result in results:
            writer.writerow([
                defang(result["url"]),
                result.get("host", ""),
                result.get("domain", ""),
                result["score"],
                result["verdict"],
                "; ".join(f"{s['code']}({s['severity']})" for s in result["signals"]),
                result.get("source", ""),
            ])


def dump_json(results, out=sys.stdout):
    payload = []
    for result in results:
        item = dict(result)
        item["defanged_url"] = defang(result["url"])
        payload.append(item)
    json.dump(payload, out, indent=2)
    out.write("\n")
