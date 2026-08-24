#!/usr/bin/env python3
"""Parse DMARC aggregate (rua) reports — .xml / .zip / .gz — into a readable summary.

Groups traffic by source IP, classifies each as your server / legitimate
forwarder / spoofer, and flags anything blocked by policy. Pure standard
library, cross-platform (Windows, macOS, Linux).

Usage:
    python parse_dmarc.py <file-or-folder> [<more> ...] [--known-ip 1.2.3.4]

Examples:
    python parse_dmarc.py ~/Downloads
    python parse_dmarc.py report.zip another.xml.gz --known-ip 185.60.168.164
"""
import sys
import os
import glob
import gzip
import zipfile
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from collections import defaultdict


def iter_report_files(paths):
    """Expand paths (files or folders) into individual report file paths."""
    exts = ('.xml', '.gz', '.zip')
    for p in paths:
        if os.path.isdir(p):
            for e in exts:
                yield from glob.glob(os.path.join(p, '*' + e))
        elif p.lower().endswith(exts):
            yield p


def iter_xml_bytes(path):
    """Yield raw XML bytes from a report file (.xml, .gz, or .zip of xml)."""
    low = path.lower()
    try:
        if low.endswith('.gz'):
            with gzip.open(path, 'rb') as f:
                yield f.read()
        elif low.endswith('.zip'):
            with zipfile.ZipFile(path) as z:
                for n in z.namelist():
                    if n.lower().endswith('.xml'):
                        yield z.read(n)
        elif low.endswith('.xml'):
            with open(path, 'rb') as f:
                yield f.read()
    except (OSError, zipfile.BadZipFile) as e:
        print("  ! could not read %s: %s" % (os.path.basename(path), e), file=sys.stderr)


def parse_report(xml_bytes):
    """Parse one report's XML into a list of per-record dicts."""
    root = ET.fromstring(xml_bytes)
    org = root.findtext('report_metadata/org_name', '?')
    begin = root.findtext('report_metadata/date_range/begin')
    day = (datetime.fromtimestamp(int(begin), timezone.utc).strftime('%Y-%m-%d')
           if begin else '?')
    policy = root.findtext('policy_published/p', '?')
    rows = []
    for rec in root.findall('record'):
        dkim_doms = [(d.findtext('domain', ''), d.findtext('result', ''))
                     for d in rec.findall('auth_results/dkim')]
        rows.append(dict(
            day=day, org=org, policy=policy,
            ip=rec.findtext('row/source_ip', '?'),
            count=int(rec.findtext('row/count', '0') or 0),
            dkim=rec.findtext('row/policy_evaluated/dkim', '?'),
            spf=rec.findtext('row/policy_evaluated/spf', '?'),
            disp=rec.findtext('row/policy_evaluated/disposition', '?'),
            hfrom=rec.findtext('identifiers/header_from', '?'),
            spf_dom=rec.findtext('auth_results/spf/domain', ''),
            dkim_doms=dkim_doms,
        ))
    return rows


def classify(ip, rows, known_ip):
    """Label an IP based on its aggregate DKIM/SPF results."""
    any_dkim_pass = any(r['dkim'] == 'pass' for r in rows)
    all_fail = all(r['dkim'] != 'pass' and r['spf'] != 'pass' for r in rows)
    blocked = any(r['disp'] in ('quarantine', 'reject') for r in rows)
    if known_ip and ip == known_ip:
        return 'YOUR SERVER'
    if all_fail and blocked:
        return 'SPOOFER (blocked by policy)'
    if all_fail:
        return 'SPOOFER / unauthenticated'
    if any_dkim_pass:
        return 'legitimate (DKIM signed) - forwarder/partner/service'
    return 'review'


def main():
    ap = argparse.ArgumentParser(description='Summarize DMARC aggregate reports.')
    ap.add_argument('paths', nargs='+', help='report files or folders (.xml/.zip/.gz)')
    ap.add_argument('--known-ip', help='your legitimate sending server IP')
    args = ap.parse_args()

    all_rows = []
    files = sorted(set(iter_report_files(args.paths)))
    for path in files:
        for xml_bytes in iter_xml_bytes(path):
            try:
                all_rows.extend(parse_report(xml_bytes))
            except ET.ParseError as e:
                print("  ! bad XML in %s: %s" % (os.path.basename(path), e),
                      file=sys.stderr)

    if not all_rows:
        print('No DMARC records found. Check the paths.')
        return 1

    policies = sorted({r['policy'] for r in all_rows})
    days = sorted({r['day'] for r in all_rows})
    total = sum(r['count'] for r in all_rows)
    print('=' * 72)
    print('DMARC REPORT SUMMARY')
    print('  files parsed : %d   records: %d   messages: %d'
          % (len(files), len(all_rows), total))
    print('  date range   : %s .. %s' % (days[0], days[-1]))
    print('  policy seen  : %s' % ', '.join(policies))
    print('=' * 72)

    # Per-day table
    print('\n%-11s %-18s %-16s %5s %-5s %-5s %-11s' %
          ('DAY', 'REPORTER', 'SOURCE IP', 'MSGS', 'DKIM', 'SPF', 'DISPOSITION'))
    print('-' * 72)
    for r in sorted(all_rows, key=lambda r: (r['day'], r['ip'])):
        rep = r['org'].replace('.com', '').replace('enterprise.protection.', '')[:16]
        print('%-11s %-18s %-16s %5d %-5s %-5s %-11s' %
              (r['day'], rep, r['ip'], r['count'], r['dkim'], r['spf'], r['disp']))

    # Per-IP verdict
    by_ip = defaultdict(list)
    for r in all_rows:
        by_ip[r['ip']].append(r)
    print('\n' + '=' * 72)
    print('SOURCES (verdict per IP)')
    print('=' * 72)
    for ip, rows in sorted(by_ip.items(), key=lambda kv: -sum(r['count'] for r in kv[1])):
        msgs = sum(r['count'] for r in rows)
        verdict = classify(ip, rows, args.known_ip)
        flag = '[!]' if verdict.startswith('SPOOFER') else ('[OK]' if verdict == 'YOUR SERVER' else '[-]')
        print('%s %-16s %4d msgs   %s' % (flag, ip, msgs, verdict))
        if verdict.startswith('SPOOFER') or verdict == 'review':
            doms = {d for r in rows for d, _ in r['dkim_doms'] if d} | {r['spf_dom'] for r in rows if r['spf_dom']}
            if doms:
                print('     envelope/DKIM domains: %s' % ', '.join(sorted(doms)))

    spoofers = [ip for ip, rows in by_ip.items()
                if classify(ip, rows, args.known_ip).startswith('SPOOFER')]
    print('\n' + '-' * 72)
    if spoofers:
        print('[!] %d spoofing source(s): %s' % (len(spoofers), ', '.join(spoofers)))
        print('    If disposition shows quarantine/reject, DMARC already blocked them.')
    else:
        print('[OK] No spoofing sources found. All traffic authenticated or recognized.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
