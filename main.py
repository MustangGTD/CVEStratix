#!/usr/bin/env python3
"""CVEStratix 0.3: network evidence and candidate CVE research, not exploitation."""
from __future__ import annotations

import argparse
import html
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

import requests
from rich.console import Console
from rich.table import Table
from rich.text import Text

VERSION = '0.3.1'
API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
console = Console(record=True, highlight=False)
CWE = {
    'CWE-416': ('Use After Free', 'Memory is accessed after being released; this can cause crashes, disclosure, or code execution. Patch the affected component.'),
    'CWE-22': ('Path Traversal', 'Paths may escape the intended directory. Apply the vendor fix and restrict filesystem access.'),
    'CWE-79': ('Cross-site scripting', 'Untrusted content may execute in a browser. Use contextual output encoding and vendor fixes.'),
    'CWE-89': ('SQL Injection', 'Input may alter database queries. Use parameterized queries and least-privilege database accounts.'),
    'CWE-78': ('OS Command Injection', 'Input may influence shell commands. Avoid shell invocation and apply vendor fixes.'),
    'CWE-787': ('Out-of-bounds Write', 'Writes exceed a memory buffer. Corruption or crashes may result; apply the vendor patch.'),
    'CWE-125': ('Out-of-bounds Read', 'Reads exceed a memory buffer. Disclosure or crashes may result; apply the vendor patch.'),
    'CWE-287': ('Improper Authentication', 'Identity checks may be bypassed. Review the exact advisory and apply the fix.'),
    'CWE-444': ('HTTP Request Smuggling', 'HTTP components may disagree on request boundaries. Patch and align proxy/backend parsing.'),
    'CWE-918': ('SSRF', 'Server-side requests may reach unintended destinations. Validate destinations and restrict egress.'),
}


def say(value='', style=None):
    # Remote banners and descriptions are data, never Rich markup or terminal controls.
    value = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', str(value))
    value = ''.join(c for c in value if c in '\n\t' or ord(c) >= 32)
    console.print(Text(value, style=style or ''))


def ip(value):
    try:
        address = ipaddress.ip_address(value)
        if address.is_multicast or address.is_unspecified or '%' in value:
            raise ValueError()
        return str(address)
    except ValueError:
        raise argparse.ArgumentTypeError('Enter one unicast IPv4 or IPv6 address.') from None


def ports(value):
    if not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', value):
        raise argparse.ArgumentTypeError('Use 22,80,3000 or 1-65535.')
    for part in value.split(','):
        bounds = [int(x) for x in part.split('-')]
        if not all(1 <= x <= 65535 for x in bounds) or bounds[0] > bounds[-1]:
            raise argparse.ArgumentTypeError('Invalid port range.')
    return value


def parse_scan(raw, target):
    if '<!ENTITY' in raw:
        raise ValueError('XML entities are not supported.')
    root = ET.fromstring(raw)
    result = []
    for host in root.findall('host'):
        addresses = [a.get('addr') for a in host.findall('address')]
        if target not in addresses:
            continue
        for p in host.findall('./ports/port'):
            state = p.find('state')
            if state is None or state.get('state') != 'open':
                continue
            node = p.find('service')
            a = node.attrib if node is not None else {}
            result.append(dict(port=int(p.get('portid')), protocol=p.get('protocol'),
                               service=a.get('name', 'unknown'), product=a.get('product', ''),
                               version=a.get('version', ''), extra=a.get('extrainfo', ''),
                               tunnel=a.get('tunnel', ''), reason=state.get('reason', ''),
                               cpes=[c.text for c in p.findall('./service/cpe') if c.text]))
    return result


def scan(target, selected, folder):
    if not shutil.which('nmap'):
        raise RuntimeError('Nmap missing: sudo apt install nmap')
    cmd = ['nmap', '-sT', '-Pn', '-n', '-sV', '--reason', '-T3',
           '--stats-every', '15s', '-p', selected, '-oX', str(folder / 'scan.xml')]
    if ':' in target:
        cmd.append('-6')
    cmd.append(target)
    say('1/3 Scan and fingerprint: ' + shlex.join(cmd), 'cyan')
    say('TCP only. Full scans can take a long time. Ctrl+C cancels; Nmap progress follows.')
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for line in process.stdout:
            say(line.rstrip())
        if process.wait():
            raise RuntimeError('Nmap failed. See progress above; scan is not complete.')
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return parse_scan((folder / 'scan.xml').read_text(), target)


def normalize_cpe(value):
    # Handle simple URI bindings; refuse complex escaping/packed extensions rather than guess.
    if value.startswith('cpe:2.3:'):
        parts = value.split(':')[2:]
    elif value.startswith('cpe:/'):
        parts = [unquote(x) or '*' for x in value[5:].split(':')]
        if len(parts) > 7:
            return None
        parts += ['*'] * (11 - len(parts))
    else:
        return None
    if len(parts) != 11 or any(not re.fullmatch(r'[A-Za-z0-9_.+*?-]+', x) for x in parts):
        return None
    return parts


def query_for(service):
    for value in service['cpes']:
        fields = normalize_cpe(value)
        if fields and fields[0] == 'a' and fields[3] not in ('*', '-'):
            return {'virtualMatchString': 'cpe:2.3:' + ':'.join(fields)}, fields
    if service['product'] and service['version']:
        return {'keywordSearch': service['product'] + ' ' + service['version']}, None
    return None, None


class NVD:
    def __init__(self):
        self.session = requests.Session()
        self.key = os.getenv('NVD_API_KEY')
        self.headers = {'User-Agent': 'CVEStratix/' + VERSION}
        if self.key:
            self.headers['apiKey'] = self.key
        self.last = 0.0

    def page(self, params):
        for attempt in range(3):
            time.sleep(max(0, (0.7 if self.key else 6.2) - (time.monotonic() - self.last)))
            self.last = time.monotonic()
            try:
                response = self.session.get(API, params=params, headers=self.headers, timeout=30)
                if response.status_code == 429 or response.status_code >= 500:
                    time.sleep(2 ** attempt)
                    continue
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload.get('vulnerabilities'), list) or 'totalResults' not in payload:
                    raise ValueError('Unexpected NVD response schema')
                return payload
            except requests.HTTPError:
                raise
            except (requests.RequestException, ValueError):
                if attempt == 2:
                    raise
        raise RuntimeError('NVD rate limit or server failure after three attempts')

    def fetch(self, query):
        records, seen, index, total = [], set(), 0, None
        try:
            while True:
                page = self.page(dict(query, resultsPerPage=2000, startIndex=index))
                total = int(page['totalResults'])
                batch = page['vulnerabilities']
                if not batch and index < total:
                    raise ValueError('Empty page before advertised total')
                new = 0
                for item in batch:
                    record = item.get('cve', {})
                    identity = record.get('id')
                    if identity and identity not in seen:
                        records.append(record)
                        seen.add(identity)
                        new += 1
                index += len(batch)
                say(f'  NVD records retrieved: {len(records)} / {total}')
                if index >= total:
                    return records, {'complete': True, 'total': total, 'retrieved': len(records)}
                if not new:
                    raise ValueError('Repeated page; pagination stopped')
        except (requests.RequestException, ValueError, RuntimeError) as exc:
            return records, {'complete': False, 'total': total, 'retrieved': len(records),
                             'error': type(exc).__name__ + ': ' + str(exc)}


def walk_matches(value):
    if isinstance(value, dict):
        for match in value.get('cpeMatch', []):
            yield match
        for key, item in value.items():
            if key != 'cpeMatch':
                yield from walk_matches(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_matches(item)


def numeric_version(value):
    if not re.fullmatch(r'\d+(?:\.\d+)*', value):
        return None
    return tuple(int(x) for x in value.split('.'))


def range_check(version, match):
    v = numeric_version(version)
    if v is None:
        return None
    for key in ('versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'):
        if key not in match:
            continue
        bound = numeric_version(match[key])
        if bound is None:
            return None
        width = max(len(v), len(bound))
        a, b = v + (0,) * (width-len(v)), bound + (0,) * (width-len(bound))
        if ((key == 'versionStartIncluding' and a < b) or
            (key == 'versionStartExcluding' and a <= b) or
            (key == 'versionEndIncluding' and a > b) or
            (key == 'versionEndExcluding' and a >= b)):
            return False
    return True


def applicability(record, fields):
    if not fields:
        return 'KEYWORD LEAD', ['Product/version text search only; affected versions not established.']
    evidence, decisions = [], []
    for match in walk_matches(record.get('configurations', [])):
        p = normalize_cpe(match.get('criteria', ''))
        if not p or p[:3] != fields[:3] or not match.get('vulnerable', False):
            continue
        ranges = {k: v for k, v in match.items() if k.startswith('version')}
        evidence.append({'criteria': match['criteria'], **ranges})
        if p[3] not in ('*', '-'):
            decisions.append(p[3] == fields[3] if p[4:] == ['*'] * 7 else None)
        elif ranges:
            decisions.append(range_check(fields[3], match) if p[4:] == ['*'] * 7 else None)
        else:
            decisions.append(None)
    if True in decisions:
        return 'VERSION EVIDENCE FOUND', evidence
    if decisions and all(x is False for x in decisions):
        return 'VERSION MISMATCH', evidence
    return 'APPLICABILITY UNRESOLVED', evidence or ['No comparable affected application CPE found.']


WEB_PORTS = {80, 81, 443, 3000, 3001, 4000, 5000, 5173, 8000, 8008, 8080, 8081, 8443, 8888, 9000}


def web_candidate(service):
    name = (service.get('service') or '').lower()
    product = (service.get('product') or '').lower()
    # Nmap can misclassify web applications on development ports (for example, ppp? on 3000).
    # Probe likely web ports and weak/unknown fingerprints, but preserve Nmap's original evidence.
    return ('http' in name or service.get('port') in WEB_PORTS or
            (not product and name in {'unknown', 'ppp', 'tcpwrapped'}))


def web_url(target, service):
    host = '[' + target + ']' if ':' in target else target
    name = (service.get('service') or '').lower()
    tls = service.get('tunnel') == 'ssl' or 'https' in name or service.get('port') in (443, 8443)
    return f'{"https" if tls else "http"}://{host}:{service["port"]}/'


def identify_web_application(title, body, headers):
    text = (title or '') + '\n' + body
    low = text.lower()
    evidence = []

    if 'owasp juice shop' in low:
        if title and 'owasp juice shop' in title.lower():
            evidence.append('HTML title contains "OWASP Juice Shop"')
        if 'bjoern kimminich' in low or 'juice shop contributors' in low:
            evidence.append('Page source contains Juice Shop project attribution')
        return {
            'application': 'OWASP Juice Shop',
            'vendor': 'OWASP / Juice Shop project',
            'confidence': 'HIGH',
            'method': 'HTTP content fingerprint',
            'evidence': evidence or ['HTTP body contains "OWASP Juice Shop"'],
        }

    server = headers.get('Server') if headers else None
    powered = headers.get('X-Powered-By') if headers else None
    if title:
        evidence.append('HTML title: ' + title[:160])
    if server:
        evidence.append('Server header: ' + server[:160])
    if powered:
        evidence.append('X-Powered-By header: ' + powered[:160])
    if evidence:
        return {
            'application': None,
            'vendor': None,
            'confidence': 'LOW',
            'method': 'Generic HTTP evidence',
            'evidence': evidence,
        }
    return None


def commands(target, service):
    p = service['port']
    ipv6 = ['-6'] if ':' in target else []
    results = [{'purpose': 'Recheck the service fingerprint; sends active probes.',
                'command': shlex.join(['nmap', *ipv6, '-sV', '-p', str(p), target])}]
    if web_candidate(service):
        url = web_url(target, service)
        results += [{'purpose': 'Inspect HTTP response headers; does not validate the CVE.',
                     'command': shlex.join(['curl', '--max-time', '15', '-I', url])},
                    {'purpose': 'Fingerprint web technologies (optional tool; active requests).',
                     'command': shlex.join(['whatweb', url])}]
    if service['service'] == 'ssh':
        results.append({'purpose': 'Inspect SSH algorithms and host keys; does not prove a CVE.',
                        'command': shlex.join(['nmap', *ipv6, '-p', str(p), '--script',
                                              'ssh2-enum-algos,ssh-hostkey', target])})
    return results


def web_evidence(target, service):
    if not web_candidate(service):
        return None
    url = web_url(target, service)
    try:
        # Do not follow redirects out of the selected target. Verify HTTPS certificates.
        with requests.get(url, timeout=(5, 10), allow_redirects=False, stream=True) as r:
            data = bytearray()
            deadline = time.monotonic() + 15
            for chunk in r.iter_content(4096):
                data.extend(chunk)
                if len(data) >= 65536 or time.monotonic() > deadline:
                    break
            body = bytes(data[:65536]).decode(r.encoding or 'utf-8', errors='replace')
            title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
            title = html.unescape(title_match[1].strip()) if title_match else None
            names = ['Server', 'X-Powered-By', 'Content-Security-Policy', 'X-Frame-Options',
                     'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy']
            if url.startswith('https:'):
                names.append('Strict-Transport-Security')
            headers = {k: r.headers.get(k) for k in names}
            fingerprint = identify_web_application(title, body, headers)
            return dict(url=url, status=r.status_code, redirect=r.headers.get('Location'),
                        title=title, headers=headers, fingerprint=fingerprint,
                        note='Missing headers are observations, not confirmed vulnerabilities. CSP frame-ancestors can replace X-Frame-Options.')
    except requests.RequestException as exc:
        return {'url': url, 'error': str(exc)}


def enrich_service_from_web(service):
    web = service.get('web')
    fp = web.get('fingerprint') if isinstance(web, dict) else None
    if not fp or not fp.get('application'):
        return
    service['nmap_service'] = service.get('service')
    service['detected_application'] = fp['application']
    service['detection_confidence'] = fp['confidence']
    service['detection_method'] = fp['method']
    service['detection_evidence'] = fp['evidence']
    # Promote an uncertain/non-HTTP Nmap label to HTTP for downstream web tooling,
    # while retaining nmap_service so the raw scanner result remains auditable.
    if 'http' not in (service.get('service') or '').lower():
        service['service'] = 'http'
    if not service.get('product'):
        service['product'] = fp['application']


def finding(record, fields):
    status, evidence = applicability(record, fields)
    score, severity, vector = None, 'UNKNOWN', ''
    for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        metrics = record.get('metrics', {}).get(key, [])
        if metrics:
            metric = next((x for x in metrics if x.get('type') == 'Primary'), metrics[0])
            data = metric.get('cvssData', {})
            score, severity = data.get('baseScore'), data.get('baseSeverity', metric.get('baseSeverity', 'UNKNOWN'))
            vector = data.get('vectorString', '')
            break
    weaknesses = sorted({x['value'] for w in record.get('weaknesses', [])
                         for x in w.get('description', []) if x.get('lang') == 'en'})
    refs = record.get('references', [])
    advisories = [x['url'] for x in refs if 'Vendor Advisory' in x.get('tags', [])]
    identity = record['id']
    return dict(id=identity, published=record.get('published'), modified=record.get('lastModified'),
                description=next((x['value'] for x in record.get('descriptions', []) if x.get('lang') == 'en'), 'Not supplied'),
                score=score, severity=severity, vector=vector, status=status, evidence=evidence,
                weaknesses=weaknesses, explanations=[CWE[x] for x in weaknesses if x in CWE],
                prerequisites='Review description, CVSS vector and vendor advisory. Configuration AND/OR conditions, platform, modules and backports are not verified.',
                fixed_version='Not independently verified; consult the vendor advisory. A range boundary is not necessarily a patched release.',
                vendor_advisories=advisories, references=[x['url'] for x in refs if x.get('url')],
                configurations=record.get('configurations', []),
                commands=[{'purpose': 'Search local public research references; does not execute exploits. Optional SearchSploit required.',
                           'command': shlex.join(['searchsploit', '--cve', identity.removeprefix('CVE-')])}],
                mitigation=['Apply the vendor-supported security update after verifying product and package revision.',
                            'Disable the affected feature if the advisory supports that workaround.',
                            'Restrict service access to necessary sources; this does not replace patching.',
                            'Recheck the package version and validate the fix; a banner alone is insufficient.'])


def print_finding(item):
    say('\n' + item['id'] + ' | ' + item['severity'] + ' | CVSS ' + str(item['score']), 'bold magenta')
    for label in ('published', 'modified', 'status', 'description', 'vector', 'weaknesses', 'evidence',
                  'explanations', 'prerequisites', 'fixed_version', 'vendor_advisories', 'mitigation'):
        say(label.replace('_', ' ').title() + ': ' + str(item[label]))
    say('NVD: https://nvd.nist.gov/vuln/detail/' + item['id'])
    for c in item['commands']:
        say(c['purpose'] + '\n  ' + c['command'], 'cyan')


def banner():
    art = r'''
 ██████╗██╗   ██╗███████╗███████╗████████╗██████╗  █████╗ ████████╗██╗██╗  ██╗
██╔════╝██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗╚══██╔══╝██║╚██╗██╔╝
██║     ██║   ██║█████╗  ███████╗   ██║   ██████╔╝███████║   ██║   ██║ ╚███╔╝ 
██║     ╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   ██╔══██╗██╔══██║   ██║   ██║ ██╔██╗ 
╚██████╗ ╚████╔╝ ███████╗███████║   ██║   ██║  ██║██║  ██║   ██║   ██║██╔╝ ██╗
 ╚═════╝  ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝
'''
    say(art, 'bold bright_blue')
    say('                 CVE RESEARCH & SERVICE FINGERPRINTING TOOL', 'bold cyan')
    say(f'                       v{VERSION} • Research Edition', 'cyan')
    say('      Service discovery • Web evidence • NVD candidate CVE research', 'dim')
    say('      Potential matches are not confirmed vulnerabilities.', 'yellow')
    say('      Scan only systems you own or are explicitly authorized to assess.\n', 'yellow')


def main():
    banner()
    parser = argparse.ArgumentParser(description='One IP → TCP services → CVE research. No automatic exploitation.')
    parser.add_argument('target', nargs='?', type=ip)
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--ports', type=ports, default='1-65535', help='Default: every TCP port, 1-65535')
    parser.add_argument('--output', type=Path, default=Path('reports'))
    parser.add_argument('--xml', type=Path, help='Import Nmap XML instead of live scanning (still queries NVD)')
    args = parser.parse_args()
    target = args.target or ip(input('Target IP: ').strip())
    now = datetime.now(timezone.utc)
    folder = args.output / (target.replace(':', '_') + '-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    folder.mkdir(parents=True, exist_ok=False)
    report = dict(version=VERSION, target=target, started=now.isoformat(), tcp_ports=args.ports,
                  scope='NVD candidates for detected application fingerprints, all publication years; not all CVEs ever published or UDP/internal services.',
                  complete=False, services=[], errors=[])
    client = NVD()
    try:
        services = parse_scan(args.xml.read_text(), target) if args.xml else scan(target, args.ports, folder)

        # HTTP/application enrichment runs before the table so uncertain Nmap labels can be
        # clarified using direct response evidence (while preserving nmap_service).
        for s in services:
            s['web'] = web_evidence(target, s)
            enrich_service_from_web(s)

        table = Table(title='Observed open TCP services')
        for name in ('Port', 'Service', 'Product / Application', 'Version', 'Confidence', 'Extra evidence'):
            table.add_column(name)
        for s in services:
            evidence = s.get('extra', '')
            if s.get('nmap_service') and s['nmap_service'] != s['service']:
                evidence = (evidence + '; ' if evidence else '') + 'Nmap originally: ' + s['nmap_service'] + '?'
            table.add_row(*[Text(str(v)) for v in (
                s['port'], s['service'], s['product'], s['version'],
                s.get('detection_confidence', ''), evidence)])
        console.print(table)
        if not services:
            say('No open services observed. This is not proof the host is offline or secure.')
        cache = {}
        for s in services:
            report['services'].append(s)
            app = s.get('detected_application')
            label = app or (s['product'] + (' ' + s['version'] if s['version'] else '')).strip() or s['service']
            say(f'\n2/3 Researching {s["port"]}/tcp {label}', 'green')
            s['commands'] = commands(target, s)
            for c in s['commands']:
                say(c['purpose'] + '\n  ' + c['command'], 'cyan')
            if s['web']:
                say('Web observations: ' + json.dumps(s['web'], ensure_ascii=False))
            query, fields = query_for(s)
            s['query'] = query
            if query is None:
                s['lookup'] = {'complete': False, 'status': 'SKIPPED: reliable product/version unavailable'}
                say(s['lookup']['status'], 'yellow')
                continue
            key = json.dumps(query, sort_keys=True)
            if key not in cache:
                cache[key] = client.fetch(query)
            records, s['lookup'] = cache[key]
            s['findings'], s['excluded'] = [], []
            for record in records:
                if record.get('vulnStatus') == 'Rejected':
                    s['excluded'].append({'id': record['id'], 'reason': 'Rejected CVE record'})
                    continue
                item = finding(record, fields)
                if item['status'] == 'VERSION MISMATCH':
                    s['excluded'].append({'id': item['id'], 'reason': item['status'], 'evidence': item['evidence']})
                else:
                    s['findings'].append(item)
            s['findings'].sort(key=lambda x: x['score'] if x['score'] is not None else -1, reverse=True)
            for item in s['findings']:
                print_finding(item)
            say(f'Candidates: {len(s["findings"])}; excluded: {len(s["excluded"])}; lookup: {s["lookup"]}')
            if not s['findings']:
                say('No candidates returned after filtering; not a clean bill of health.')
        report['complete'] = all(s.get('lookup', {}).get('complete', False) for s in services)
    except KeyboardInterrupt:
        report['errors'].append('Interrupted by user; partial results only.')
    except (OSError, ValueError, ET.ParseError, RuntimeError, requests.RequestException) as exc:
        report['errors'].append(str(exc))
    finally:
        client.session.close()
        report['finished'] = datetime.now(timezone.utc).isoformat()
        for error in report['errors']:
            say(error, 'red')
        say('3/3 Saving evidence. Research complete: ' + str(report['complete']))
        (folder / 'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
        (folder / 'report.txt').write_text(console.export_text(), encoding='utf-8')
        say('Saved: ' + str(folder.resolve()), 'green')
    return 0 if report['complete'] else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (argparse.ArgumentTypeError, OSError, EOFError) as exc:
        say(str(exc), 'red')
        sys.exit(2)
