# CVEStratix — research edition

CVEStratix is a Python-based cybersecurity research tool designed to identify exposed TCP services, fingerprint software and web applications, and research potentially relevant CVEs using NVD data.

It combines Nmap-based service discovery with HTTP inspection and application fingerprinting to improve identification when standard service detection is incomplete or uncertain. CVEStratix also provides CVE severity information, applicability evidence, mitigation guidance, and research commands while clearly distinguishing potential matches from confirmed vulnerabilities.

Current capabilities include full or custom TCP scanning, OpenSSH and web-service fingerprinting, OWASP Juice Shop detection, NVD CVE candidate research, confidence-aware results, HTTP security-header inspection, and TXT/JSON/XML reporting.

CVEStratix is intended for authorized security research, lab environments, vulnerability assessment, and defensive security testing.

One IP → open TCP services → candidate CVEs → manual research commands → mitigation suggestions.
This is a research assistant, not proof of exploitability. Only assess systems you may test.

## Kali setup

Requires Python 3.10+ and Nmap. No root is required by the default TCP connect scan.

```bash
sudo apt update
sudo apt install -y nmap python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py --version
python main.py
```

Enter one IP when prompted, or run `python main.py 192.168.56.20`.
By default **all TCP ports 1–65535** are scanned. Progress is printed by Nmap.
There is no profile menu or firewall-analysis mode. UDP and hidden/internal services are not scanned.
Service probes are active traffic and may affect fragile services; this is not a passive scan.

## What you get

- Open ports, protocol, service name, product, version, extra banner evidence and CPEs.
- HTTP title, status, redirect location and selected header observations when HTTP is identified.
- All NVD pages for each supported detected application CPE/version (or product/version keyword fallback).
  No publication-year filter and no default finding-count truncation.
- CVE publication/modified dates, full English description, CVSS/vector, CWEs and supported explanations.
- Explicit version evidence, mismatches excluded, unresolved cases clearly labeled.
- Service-check commands even if no CVE matches; CVE-specific SearchSploit reference-search commands.
- Vendor-advisory links when NVD tags them, mitigation suggestions and validation reminders.
- Timestamped TXT/JSON reports and original Nmap XML in `reports/`.
- Rate pacing, retries, pagination, and explicit partial-result/failure notices.

Commands for other tools are **printed, never executed**. The script itself invokes Nmap and makes
NVD/HTTP requests. SearchSploit and WhatWeb are optional; install them separately if desired.
No guessed Nuclei templates or exploit execution is included.

## Accuracy boundaries — read before interpreting findings

NVD is one source, not guaranteed coverage of every CVE ever published. Complete retrieval means
the API's relevant query pages were retrieved, not that every vulnerability on the target was found.
Keywords can miss CVEs or return irrelevant records. Missing product/version evidence skips lookup
instead of inventing matches. CVE ID year and publication year can differ; use the publication field.

Simple application CPEs and numeric version ranges are checked conservatively. Complex CPE bindings,
suffix versions, update/platform constraints and full AND/OR/negation configuration trees are not
fully evaluated. `VERSION EVIDENCE FOUND` is **not HIGH confidence or confirmation**: the researcher
must verify configuration, platform, enabled modules, authentication requirements and Ubuntu backports.
Raw NVD configuration trees are retained in JSON. Other lookup statuses are KEYWORD LEAD and
APPLICABILITY UNRESOLVED. Proven simple numeric version mismatches are excluded and recorded.

Fixed versions/prerequisites are not fabricated: consult descriptions and linked vendor advisories.
The tool does not fetch and interpret every vendor page or automatically validate each CVE. Mitigation
is general guidance unless verified from an advisory. A CVSS score is not exploit confirmation.

HTTP requests do not follow redirects, send credentials, or disable TLS verification. Only up to 64 KiB
of the response body is examined. Header absence alone is not a vulnerability. Requests use timeout
limits, but a slow response can still delay work. Hostnames/virtual hosts are a future enhancement.

Full TCP scanning may take considerable time on filtered hosts. Cancel with Ctrl+C for partial reports.
Exit code 2 means incomplete/failed research, including skipped unknown-version services.

## Optional commands

```bash
# Restrict ports for a quick controlled test (not the default)
python main.py 192.168.56.20 --ports 22,80,3000

# Import a prior Nmap XML; target must match its host address
python main.py 192.168.56.20 --xml scan.xml

# Choose the output parent folder
python main.py 192.168.56.20 --output reports

# Tests do not scan targets or require network access
python -m unittest discover -s tests -v
```

Use `NVD_API_KEY` in your environment for improved API limits; never commit the key.
NVD rate limits and data changes can cause incomplete retrieval, reported explicitly. Re-run after
the service recovers. Multiple runs share no persistent cache; repeated services within a run do.

## Validation and source documentation

- https://nvd.nist.gov/developers/vulnerabilities
- https://nmap.org/book/man-port-specification.html
- https://cwe.mitre.org/data/definitions/416.html

Included tests cover pagination, partial failure, version bounds/mismatches, input validation,
IPv6 command generation, XML parsing and report generation. See TESTING.md for the release checks.
MIT license. Copyright 2026 Divanshu.


## v0.3.1 web application fingerprinting

CVEStratix now probes likely web ports even when Nmap returns an uncertain or incorrect service label. It preserves the original Nmap service value, then uses HTTP response evidence such as the page title and project attribution to identify known applications. OWASP Juice Shop is recognized from its HTTP content and reported with a confidence level and supporting evidence.
