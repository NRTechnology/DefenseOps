#!/usr/bin/env python3
"""Normalize ModSecurity Concurrent audit transactions into DefenseOps JSONL events."""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
import re
import socket
import sqlite3
import sys
from pathlib import Path

MARKER_RE = re.compile(r'^---[A-Za-z0-9]+---([A-Z])--\s*$', re.M)
ATTR_RE = re.compile(r'\[(\w+) "((?:\\.|[^"\\])*)"\]')
REQUEST_RE = re.compile(r'^([A-Z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?$')
SENSITIVE_RE = re.compile(r'(?i)(password|passwd|token|secret|authorization|session(?:id)?|api[_-]?key)([=: ]+)([^&\s,;]+)')
COOKIE_VALUE_RE = re.compile(r'(?i)(cookie(?:s)?[^=]*=)[^;\s]+')


def unquote(value: str) -> str:
    return value.replace(r'\"', '"').replace(r'\\', '\\')


def parse_sections(raw: str) -> dict[str, str]:
    parts = MARKER_RE.split(raw)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}


def attrs(line: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for key, value in ATTR_RE.findall(line):
        result.setdefault(key, []).append(unquote(value))
    return result


def first(values: dict[str, list[str]], key: str, default=None):
    items = values.get(key) or []
    return items[0] if items else default


def sanitize(value: str | None) -> str | None:
    if value is None:
        return None
    value = SENSITIVE_RE.sub(lambda m: f'{m.group(1)}{m.group(2)}[REDACTED]', value)
    value = COOKIE_VALUE_RE.sub(r'\1[REDACTED]', value)
    return value[:2048]


def source_for(rule_file: str, tags: list[str]) -> str:
    normalized = rule_file.lower()
    lower_tags = {t.lower() for t in tags}
    if '/opt/brebes-waf/rules/' in normalized or 'brebes-waf' in lower_tags:
        return 'Brebes-WAF'
    if '/modsecurity-crs/' in normalized or 'owasp_crs' in lower_tags or 'owasp-crs' in lower_tags:
        return 'OWASP_CRS'
    return 'unknown'


def parse_audit(path: Path, hostname: str) -> list[dict]:
    raw = path.read_text(encoding='utf-8', errors='replace')
    # A transaction is complete only after its terminal Z boundary.
    if not re.search(r'(?m)^---[A-Za-z0-9]+---Z--\s*$', raw):
        return []
    sections = parse_sections(raw)
    a = (sections.get('A') or '').strip().splitlines()
    if not a:
        return []
    am = re.match(r'^\[(.+?)\]\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)', a[0].strip())
    if not am:
        return []
    date_text, txid, client_ip, client_port, server_ip, server_port = am.groups()
    try:
        timestamp = dt.datetime.strptime(date_text, '%d/%b/%Y:%H:%M:%S %z').isoformat()
    except ValueError:
        timestamp = date_text

    b_lines = (sections.get('B') or '').splitlines()
    method = uri = None
    request_line = next((line.strip() for line in b_lines if REQUEST_RE.match(line.strip())), '')
    rm = REQUEST_RE.match(request_line)
    if rm:
        method, uri = rm.groups()
    headers: dict[str, str] = {}
    for line in b_lines:
        if ':' in line and not line.startswith((' ', '\t')):
            key, value = line.split(':', 1)
            if key.lower() in {'host', 'user-agent', 'referer'}:
                headers[key.lower()] = value.strip()

    status_match = re.search(r'(?m)^HTTP/\S+\s+(\d{3})', sections.get('F') or '')
    status = int(status_match.group(1)) if status_match else None
    host = headers.get('host')
    scheme = 'https' if server_port == '443' else ('http' if server_port == '80' else None)
    h_lines = [line.strip() for line in (sections.get('H') or '').splitlines() if line.strip().startswith('ModSecurity:')]
    events = []
    for line in h_lines:
        meta = attrs(line)
        rule_id = first(meta, 'id')
        if not rule_id:
            continue
        denied = bool(re.match(r'^ModSecurity:\s*Access denied\b', line, re.I))
        warning = bool(re.match(r'^ModSecurity:\s*Warning\b', line, re.I))
        if denied:
            event_type, action, disruptive = 'waf_block', 'Access denied', True
        elif warning:
            event_type, action, disruptive = 'waf_detection', 'Warning', False
        else:
            event_type, action, disruptive = 'waf_detection', 'Detection', False
        tags = meta.get('tag', [])
        rule_file = first(meta, 'file', '')
        phase_match = re.search(r'\(phase\s+(\d+)\)', line, re.I)
        phase = int(phase_match.group(1)) if phase_match else None
        severity = first(meta, 'severity')
        try:
            severity = int(severity) if severity is not None else None
        except ValueError:
            pass
        waf = {
            'engine': 'ModSecurity', 'rule_id': rule_id,
            'rule_message': first(meta, 'msg', ''),
            'rule_source': source_for(rule_file, tags),
            'rule_file': rule_file or None, 'action': action,
            'disruptive_action': disruptive, 'severity': severity,
            'phase': phase, 'tags': tags,
        }
        if first(meta, 'ver'):
            waf['rule_version'] = first(meta, 'ver')
        event = {
            'integration': 'brebes-waf', 'event_type': event_type,
            'timestamp': timestamp, 'hostname': hostname,
            'transaction_id': first(meta, 'unique_id', txid),
            'client': {'ip': client_ip},
            'request': {'method': method, 'scheme': scheme, 'domain': host,
                        'uri': first(meta, 'uri', uri), 'http_status': status},
            'waf': waf,
        }
        if headers.get('user-agent'):
            event['client']['user_agent'] = sanitize(headers['user-agent'])
        if headers.get('referer'):
            event['client']['referer'] = sanitize(headers['referer'])
        if server_ip:
            event['waf']['server_ip'] = server_ip
        matched_var = re.search(r'against variable `([^`]+)`', line)
        matched_data = first(meta, 'data')
        if matched_var or matched_data:
            context = {}
            if matched_var:
                context['matched_variable'] = matched_var.group(1)
            if matched_data:
                context['matched_data'] = sanitize(matched_data)
            event['attack_context'] = context
        events.append(event)
    return events


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='/var/log/nginx/modsecurity', help='Concurrent audit storage root')
    ap.add_argument('--output', default='/var/log/defenseops/modsecurity-events.json')
    ap.add_argument('--state', default='/var/lib/defenseops/modsecurity-state.sqlite3')
    ap.add_argument('--baseline', type=float, default=None, help='Ignore files older than this Unix timestamp')
    ap.add_argument('--once', action='store_true', help='Run one scan and exit (default behavior)')
    args = ap.parse_args()
    root, output, state = Path(args.root), Path(args.output), Path(args.state)
    if not root.is_dir():
        print(f'[WARN] audit root not found: {root}', file=sys.stderr)
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    state.parent.mkdir(parents=True, exist_ok=True)
    hostname = socket.gethostname()
    conn = sqlite3.connect(state)
    conn.execute('CREATE TABLE IF NOT EXISTS processed (txid TEXT NOT NULL, rule_id TEXT NOT NULL, PRIMARY KEY(txid, rule_id))')
    conn.commit()
    added = 0
    with output.open('a', encoding='utf-8') as out:
        for path in sorted(p for p in root.rglob('*') if p.is_file()):
            try:
                stat = path.stat()
                if args.baseline is not None and stat.st_mtime < args.baseline:
                    continue
                if stat.st_size < 20:
                    continue
                events = parse_audit(path, hostname)
                for event in events:
                    txid = str(event.get('transaction_id', ''))
                    rule_id = str(event['waf']['rule_id'])
                    try:
                        cur = conn.execute('INSERT OR IGNORE INTO processed(txid, rule_id) VALUES (?, ?)', (txid, rule_id))
                        if cur.rowcount == 0:
                            continue
                        out.write(json.dumps(event, ensure_ascii=False, separators=(',', ':')) + '\n')
                        added += 1
                    except sqlite3.Error:
                        raise
            except (OSError, UnicodeError) as exc:
                print(f'[WARN] cannot read {path}: {exc}', file=sys.stderr)
        out.flush()
        os.fsync(out.fileno())
    conn.commit()
    conn.close()
    if added:
        print(f'[INFO] appended {added} ModSecurity event(s) to {output}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
