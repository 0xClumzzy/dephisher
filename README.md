# dephisher,  phishing URL triage kit

A lightweight SOC tool for triaging URLs extracted from reported phishing
emails. Bash entry point, Python standard library only.

## What it does

1. **Extract** - pulls URLs out of `.eml` files (HTML `href`s, plain-text
   bodies, `List-Unsubscribe` and other headers). Refangs defanged IOCs
   (`hxxps://…[.]…`) automatically so you can paste from reports.
2. **Analyze** (fully offline) — scores each URL 0–100 on risk signals:
   typosquat/homograph vs. brand list, brand-in-subdomain tricks, IP-literal
   hosts, `@` userinfo tricks, suspicious TLDs, URL shorteners, credential-lure
   wording, open-redirect params, percent-encoding obfuscation, odd ports,
   plain HTTP, deep subdomain chains, punycode.
3. **Report**  terminal verdict, JSON, and a defanged IOC CSV ready for your
   SIEM / MISP / case notes.

Network enrichment is **opt-in** (`--enrich`): DNS resolution, bounded
redirect-chain following (max 6 hops), RDAP domain-age, and VirusTotal
(only if `VT_API_KEY` is set). A guard refuses to touch private/loopback/
link-local addresses, so a malicious link can't pivot into your network.

## Usage

```bash
# Analyst drops in a reported email:
./phishdefend reported-phish.eml

# Single URL (paste from anywhere - defanged input is fine):
./phishdefend -u "hxxps://paypa1[.]verify-account[.]top/login"

# From stdin (pipe anything):
cat report.txt | ./phishdefend

# With network enrichment + IOC export:
./phishdefend reported-phish.eml --enrich --csv iocs.csv

# Machine-readable output:
./phishdefend reported-phish.eml --json
```

Try it on the bundled sample: `./phishdefend samples/suspicious.eml`

### Exit codes (for automation)

| Code | Meaning |
|------|---------|
| 0    | all URLs benign / allowlisted |
| 1    | at least one SUSPICIOUS URL |
| 2    | at least one LIKELY MALICIOUS URL |

## Scoring

Signals carry weights: **high = 25, med = 12, low = 5** (capped at 100).

| Score | Verdict |
|-------|---------|
| 0–14  | BENIGN |
| 15–39 | SUSPICIOUS |
| 40+   | LIKELY MALICIOUS |

Domains in `config/allowlist.txt` are always `ALLOWLISTED` (score 0) — put
your corporate domains there to kill noise.

## Configuration (all plain-text, one entry per line)

| File | Purpose |
|------|---------|
| `config/brands.txt`     | brands for typosquat/subdomain checks — **add your org's brand and the services your staff use** |
| `config/allowlist.txt`  | trusted domains, verdict forced to ALLOWLISTED |
| `config/suspicious_tlds.txt` | abused TLDs |
| `config/shorteners.txt` | URL shorteners |

Override any of them with `--brands`, `--allowlist`, `--tlds`, `--shorteners`.

## Layout

```
dephisher/
├── phishdefend        # bash entry point (env checks, then exec)
├── run.py             # CLI orchestration
├── lib/
│   ├── extract.py     # .eml/HTML/text URL extraction, refang/defang
│   ├── analyze.py     # offline risk signals + scoring
│   ├── enrich.py      # opt-in DNS / redirect / RDAP / VirusTotal
│   └── report.py      # terminal, JSON, IOC CSV rendering
├── config/            # wordlists
├── samples/           # sample .eml for testing
└── README.md
```

## Suggested SOC workflow

1. Reported email lands in the queue → save as `.eml`.
2. `./phishdefend msg.eml --enrich --csv case-4471-iocs.csv`
3. Verdict ≥ SUSPICIOUS → check exit code `2`, pull the defanged IOCs from
   the CSV into your blocklist / MISP.
4. Allowlist false positives in `config/allowlist.txt`.
5. Optional: pipe the CSV into your existing IOC ingestion pipeline
   (it's plain CSV — no vendor lock-in).

## Extending

- **Reputation**: `lib/enrich.py` → add `urlhaus_lookup()` / `phishtank` next
  to `virustotal_lookup()`; append a signal and the score updates automatically.
- **Unshortening**: `follow_chain()` already resolves shorteners when
  `--enrich` is on.
- **New signals**: add a check in `analyze_url()` that appends
  `_sig(code, HIGH|MED|LOW, "detail")` — weights and verdicts take care of
  themselves.

## Safety notes

- Default run is **offline**: it never touches the network.
- With `--enrich`, only the URLs you submitted are requested, over
  http/https, with timeouts and a hard hop limit; private/reserved addresses
  are refused (SSRF guard).
- Use against emails and URLs you are authorized to analyze.

MIT-style: use freely for defensive security work.
