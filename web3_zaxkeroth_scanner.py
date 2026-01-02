#!/usr/bin/env python3
"""Web3 by Z4X - Safe, non-destructive scanner combining passive checks.

This tool performs only read-only, passive checks:
- HTTP header inspection
- robots.txt and sitemap.xml fetch
- MX record lookup
- Local repo proto detection (no automatic network exploitation)
"""
import os
import sys
import socket
import shutil
import json
import sqlite3
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
import dns.resolver
import argparse
import time
from colorama import init as colorama_init, Fore, Style
import ssl
from datetime import datetime
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import re
import pandas as pd
import esprima
from web3 import Web3
import subprocess
from eth_utils import is_address

ASCII = r"""
    ________   _____  ____  __.
 \____    /  /  _  \ \      \ 
     /     /  /  /_\  \ /   |  \ 
    /     /_ /    |    \    |   \ 
 /_______ \\\____|__  /\____|__  /
                 \/        \/         \/ 

01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101
01001000 01101001 01100100 01100100 01100101 01101110 01000101 01111001 01100101 01110011 01010100 01100101 01100001 01101101

                             Web3 by Z4X
"""

HEADERS = {"User-Agent": "Web3-Zaxkeroth-Scanner/1.0"}

# Global report data
REPORT = {
    'target': None,
    'headers': [],
    'security_matrix': {},
    'robots': {},
    'sitemap': {},
    'mx': {},
    'proto_files': [],
    'local_session': {},
    'ssl': {},
    'wallets': {},
    'repo_wallets': [],
    'lbc': {},
    'eslint': None,
    'js_findings': [],
    'js_ast_findings': []
}

# Public ETH RPC endpoint
ETH_RPC = "https://cloudflare-eth.com"


def print_banner():
    colorama_init(autoreset=True)
    print(Fore.CYAN + ASCII + Style.RESET_ALL)


def prompt_target(prompt_text="Enter IP or Domain: example.com 127.0.0.1:443 "):
    return input(Fore.YELLOW + prompt_text + Style.RESET_ALL)


def normalize_target(raw):
    raw = raw.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    # If includes port and port 443 assume https
    if ":" in raw:
        host, port = raw.rsplit(":", 1)
        scheme = "https" if port == "443" else "http"
        return f"{scheme}://{host}:{port}"
    return f"http://{raw}"


def fetch_url(url, path="/"):
    try:
        target = url.rstrip("/") + path
        r = requests.get(target, headers=HEADERS, timeout=8)
        return r
    except Exception as e:
        print(Fore.RED + f"  [-] Request error for {url}{path}: {e}" + Style.RESET_ALL)
        return None


def check_headers(base):
    print(Fore.GREEN + f"\n[*] HTTP Header Check for {base}" + Style.RESET_ALL)
    r = fetch_url(base, "/")
    if not r:
        return
    interesting = ["Server", "X-Powered-By", "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]
    for k in interesting:
        if k in r.headers:
            print(Fore.CYAN + f"  [+] {k}: {r.headers.get(k)}" + Style.RESET_ALL)
    print(Fore.MAGENTA + f"  [i] Status: {r.status_code}, Content-Type: {r.headers.get('Content-Type')}" + Style.RESET_ALL)
    # record headers in report
    try:
        hdrs = {k: r.headers.get(k) for k in r.headers.keys()}
        REPORT['headers'].append({'base': base, 'status': r.status_code, 'content_type': r.headers.get('Content-Type'), 'headers': hdrs})
    except Exception:
        pass


def security_header_matrix(headers):
    keys = {
        'Content-Security-Policy': 'CSP',
        'X-Content-Type-Options': 'XCTO',
        'X-Frame-Options': 'XFO',
        'Referrer-Policy': 'Referrer',
        'Strict-Transport-Security': 'HSTS',
        'Permissions-Policy': 'Permissions',
        'X-XSS-Protection': 'XXP'
    }
    print(Fore.GREEN + "\n[*] HTTP Security Header Matrix" + Style.RESET_ALL)
    matrix = {}
    for k, short in keys.items():
        present = k in headers
        matrix[short] = bool(present)
        label = (Fore.CYAN + "Present" + Style.RESET_ALL) if present else (Fore.YELLOW + "Missing" + Style.RESET_ALL)
        print(f"  {short.ljust(12)} : {label}")
    return matrix


def check_ssl_cert(host, port=443):
    print(Fore.GREEN + f"\n[*] SSL Certificate Check for {host}:{port}" + Style.RESET_ALL)
    try:
        # Use pyOpenSSL to get full chain
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_timeout(5)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        conn = SSL.Connection(ctx, sock)
        conn.set_tlsext_host_name(host.encode())
        conn.connect((host, port))
        conn.setblocking(1)
        conn.do_handshake()

        chain = conn.get_peer_cert_chain()
        certs = []
        if chain:
            for c in chain:
                try:
                    cert = c.to_cryptography()
                    certs.append(cert)
                except Exception:
                    continue
        else:
            # fallback: get peer cert
            peer = conn.get_peer_certificate()
            if peer is not None:
                try:
                    cert = peer.to_cryptography()
                    certs.append(cert)
                except Exception:
                    pass

        conn.close()

        cert_list = []
        for i, cert in enumerate(certs[:10]):
            subj = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            days_left = (not_after - datetime.utcnow()).days
            print(Fore.CYAN + f"  [+] Certificate #{i+1}" + Style.RESET_ALL)
            print(f"    Subject: {subj}")
            print(f"    Issuer : {issuer}")
            print(f"    Valid  : {not_before} -> {not_after} ({days_left} days left)")
            if days_left < 0:
                print(Fore.RED + "    [!] Certificate has expired." + Style.RESET_ALL)
            elif days_left <= 30:
                print(Fore.YELLOW + "    [!] Certificate will expire within 30 days." + Style.RESET_ALL)
            cert_list.append({'subject': subj, 'issuer': issuer, 'not_before': not_before.isoformat() if hasattr(not_before, 'isoformat') else str(not_before), 'not_after': not_after.isoformat() if hasattr(not_after, 'isoformat') else str(not_after), 'days_left': days_left})

        REPORT['ssl'][f"{host}:{port}"] = cert_list

    except Exception as e:
        print(Fore.RED + f"  [-] SSL check failed: {e}" + Style.RESET_ALL)


def wallet_check(address):
    """Attempt simple BTC address balance/UTXO lookup using Blockstream public API.
    For unsupported address formats, the function will report unsupported.
    """
    print(Fore.GREEN + f"\n[*] Wallet Check: {address}" + Style.RESET_ALL)
    # Basic BTC address heuristic: 26-35 chars, starts with 1,3,bc1
    if address.startswith('1') or address.startswith('3') or address.lower().startswith('bc1'):
        try:
            url = f"https://blockstream.info/api/address/{address}"
            r = requests.get(url, headers=HEADERS, timeout=10)
            if r.status_code == 200:
                data = r.json()
                chain_txs = data.get('chain_stats', {})
                funded = chain_txs.get('funded_txo_sum')
                spent = chain_txs.get('spent_txo_sum')
                balance = funded - spent if funded is not None and spent is not None else data.get('address', {}).get('balance')
                print(Fore.CYAN + f"  [+] BTC Address found. Balance (satoshis): {balance}" + Style.RESET_ALL)
                # UTXO list (small sample)
                try:
                    utxo_url = f"https://blockstream.info/api/address/{address}/utxo"
                    u = requests.get(utxo_url, headers=HEADERS, timeout=10)
                    if u.status_code == 200:
                        utxos = u.json()
                        print(f"  [i] UTXO count: {len(utxos)} (showing up to 5):")
                        for utxo in utxos[:5]:
                            print(f"    - txid: {utxo.get('txid')} vout:{utxo.get('vout')} value:{utxo.get('value')}")
                except Exception:
                    pass
                REPORT['wallets'][address] = {'balance': balance, 'utxos_sample': utxos[:5] if 'utxos' in locals() and isinstance(utxos, list) else []}
            else:
                print(Fore.RED + f"  [-] Failed to query BTC API (status {r.status_code})" + Style.RESET_ALL)
                REPORT['wallets'][address] = {'error': f'status_{r.status_code}'}
        except Exception as e:
            print(Fore.RED + f"  [-] Error querying BTC API: {e}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "  [-] Wallet format not recognized or unsupported by the built-in checker." + Style.RESET_ALL)
        REPORT['wallets'][address] = {'error': 'unsupported_format'}


def eth_wallet_check(address):
    """Check an Ethereum address balance via public RPC provider."""
    print(Fore.GREEN + f"\n[*] ETH Wallet Check: {address}" + Style.RESET_ALL)
    try:
        w3 = Web3(Web3.HTTPProvider(ETH_RPC))
        if not is_address(address):
            print(Fore.RED + "  [-] Invalid ETH address format." + Style.RESET_ALL)
            REPORT['wallets'][address] = {'error': 'invalid_eth_address'}
            return
        balance_wei = w3.eth.get_balance(address)
        balance_eth = w3.fromWei(balance_wei, 'ether')
        print(Fore.CYAN + f"  [+] ETH Balance: {balance_eth} ETH" + Style.RESET_ALL)
        REPORT['wallets'][address] = {'chain': 'ETH', 'balance': float(balance_eth)}
    except Exception as e:
        print(Fore.RED + f"  [-] ETH check failed: {e}" + Style.RESET_ALL)
        REPORT['wallets'][address] = {'error': str(e)}


def scan_repo_for_wallets(root_dir='.'):
    print(Fore.GREEN + "\n[*] Scanning repository for wallet addresses (BTC/ETH)" + Style.RESET_ALL)
    btc_pattern = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
    eth_pattern = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    found = set()
    for dirpath, dirs, files in os.walk(root_dir):
        for f in files:
            if f.endswith(('.js', '.py', '.txt', '.md')):
                path = os.path.join(dirpath, f)
                try:
                    with open(path, 'r', errors='ignore') as fh:
                        txt = fh.read()
                    for m in btc_pattern.findall(txt):
                        found.add(m)
                    for m in eth_pattern.findall(txt):
                        found.add(m)
                except Exception:
                    continue
    if not found:
        print(Fore.CYAN + "  [i] No wallet-like addresses found in repo." + Style.RESET_ALL)
        REPORT['repo_wallets'] = []
    else:
        REPORT['repo_wallets'] = sorted(found)
        for addr in sorted(found):
            if addr.lower().startswith('0x'):
                print(Fore.YELLOW + f"  [!] Found ETH address: {addr} - performing quick check..." + Style.RESET_ALL)
                eth_wallet_check(addr)
            else:
                print(Fore.YELLOW + f"  [!] Found BTC address: {addr} - performing quick check..." + Style.RESET_ALL)
                wallet_check(addr)


def run_eslint(root_dir='.'):
    """Run ESLint via npx if available and capture JSON output into REPORT['eslint']."""
    print(Fore.GREEN + "\n[*] Running ESLint (if npx available)" + Style.RESET_ALL)
    npx = shutil.which('npx')
    if not npx:
        msg = 'npx not found; skip ESLint run'
        print(Fore.YELLOW + f"  [-] {msg}" + Style.RESET_ALL)
        REPORT['eslint'] = {'error': msg}
        return
    try:
        proc = subprocess.run([npx, 'eslint', '--format', 'json', root_dir], capture_output=True, text=True, timeout=60)
        if proc.returncode == 0 or proc.returncode == 1:
            out = proc.stdout.strip()
            try:
                parsed = json.loads(out) if out else []
                REPORT['eslint'] = parsed
                print(Fore.CYAN + f"  [+] ESLint completed; results captured ({len(parsed)} files)." + Style.RESET_ALL)
            except Exception as e:
                REPORT['eslint'] = {'error': f'parse_failed: {e}', 'raw': out}
        else:
            REPORT['eslint'] = {'error': f'eslint_failed_returncode_{proc.returncode}', 'stderr': proc.stderr}
            print(Fore.RED + f"  [-] ESLint invocation failed (code {proc.returncode})" + Style.RESET_ALL)
    except Exception as e:
        REPORT['eslint'] = {'error': str(e)}
        print(Fore.RED + f"  [-] ESLint run failed: {e}" + Style.RESET_ALL)


def audit_csv(file_path):
    print(Fore.GREEN + f"\n[*] Auditing centralized ledger CSV: {file_path}" + Style.RESET_ALL)
    try:
        df = pd.read_csv(file_path)
        # Ensure amount is numeric
        if 'amount' in df.columns:
            df['amount'] = pd.to_numeric(df['amount'], errors='coerce').fillna(0)
        else:
            df['amount'] = 0
        total_expected = float(df[df.get('type') == 'receive']['amount'].sum())
        print(Fore.CYAN + f"  [AUDIT] Expected Balance from Centralized Ledger: {total_expected:.6f} LBC" + Style.RESET_ALL)
        REPORT['lbc']['expected'] = total_expected
        return total_expected
    except Exception as e:
        print(Fore.RED + f"  [-] CSV audit failed: {e}" + Style.RESET_ALL)
        REPORT['lbc']['expected_error'] = str(e)
        return None


def check_sdk_balance():
    print(Fore.GREEN + "\n[*] Checking local LBRY SDK balance via HTTP RPC" + Style.RESET_ALL)
    payload = {"method": "account_balance", "params": {}}
    try:
        response = requests.post("http://localhost:5279", json=payload, timeout=5).json()
        actual_bal_str = response.get('result', {}).get('total', "0.0")
        actual_balance = float(actual_bal_str)
        print(Fore.CYAN + f"  [SDK] Actual On-Chain Balance via LBRY SDK: {actual_balance:.6f} LBC" + Style.RESET_ALL)
        REPORT['lbc']['actual'] = actual_balance
        return actual_balance
    except Exception as e:
        print(Fore.RED + f"  [-] Could not connect to LBRY SDK: {e}" + Style.RESET_ALL)
        REPORT['lbc']['actual_error'] = str(e)
        return None


def js_lint_scan(root_dir='.'):
    print(Fore.GREEN + "\n[*] JavaScript Static Scan (Telemetry & Unsafe DOM usage)" + Style.RESET_ALL)
    keywords = ['sentry', 'SENTRY_DSN', 'snowplow', 'snap', 'linkedin', 'gtag', 'gtm', 'mixpanel', 'cookie', 'navigator.sendBeacon']
    unsafe_patterns = ['innerHTML', 'document.write', 'eval(', 'new Function(', 'innerText =', 'outerHTML']
    findings = []
    for dirpath, dirs, files in os.walk(root_dir):
        for f in files:
            if f.endswith('.js'):
                path = os.path.join(dirpath, f)
                try:
                    with open(path, 'r', errors='ignore') as fh:
                        txt = fh.read()
                    lower = txt.lower()
                    matched = [k for k in keywords if k in lower]
                    unsafe = [p for p in unsafe_patterns if p in txt]
                    if matched or unsafe:
                        findings.append((path, matched, unsafe))
                except Exception:
                    continue
    if not findings:
        print(Fore.CYAN + "  [i] No telemetry keys or unsafe DOM patterns found in .js files." + Style.RESET_ALL)
        REPORT['js_findings'] = []
    else:
        report_list = []
        for path, matched, unsafe in findings:
            print(Fore.YELLOW + f"  [!] File: {path}" + Style.RESET_ALL)
            if matched:
                print(f"    - Telemetry keywords: {', '.join(matched)}")
            if unsafe:
                print(f"    - Unsafe DOM patterns: {', '.join(unsafe)}")
            report_list.append({'file': path, 'telemetry': matched, 'unsafe_dom': unsafe})
        REPORT['js_findings'] = report_list


def js_ast_scan(root_dir='.'):
    """Parse JS files with an AST and flag risky constructs with locations."""
    print(Fore.GREEN + "\n[*] JavaScript AST Scan (eval, innerHTML, sendBeacon, Function ctor, telemetry DSNs)" + Style.RESET_ALL)
    findings = []
    telemetry_regex = re.compile(r"(sentry|sentry_dsn|sentry_dsn=|dsn=|snowplow|mixpanel|gtm|gtag|linkedin|snap|sentry.io)", re.IGNORECASE)

    def walk(node, filename):
        if not hasattr(node, 'type'):
            return
        t = node.type
        loc = getattr(node, 'loc', None)
        lineno = loc.start.line if loc and hasattr(loc, 'start') else None

        # Detect eval calls
        if t == 'CallExpression' and getattr(node.callee, 'type', None) == 'Identifier' and getattr(node.callee, 'name', '') == 'eval':
            findings.append((filename, lineno, 'eval() call'))

        # document.write or document.writeln
        if t == 'CallExpression' and getattr(node.callee, 'type', None) == 'MemberExpression':
            obj = node.callee.object
            prop = node.callee.property
            if getattr(obj, 'type', '') == 'Identifier' and getattr(obj, 'name', '') == 'document' and getattr(prop, 'name', '') in ('write', 'writeln'):
                findings.append((filename, lineno, 'document.write/writeln'))

        # navigator.sendBeacon
        if t == 'CallExpression' and getattr(node.callee, 'type', None) == 'MemberExpression':
            obj = node.callee.object
            prop = node.callee.property
            if getattr(obj, 'type', '') == 'Identifier' and getattr(obj, 'name', '') == 'navigator' and getattr(prop, 'name', '') == 'sendBeacon':
                findings.append((filename, lineno, 'navigator.sendBeacon'))

        # Function constructor usage: new Function(...) or Function(...)
        if (t == 'NewExpression' and getattr(node.callee, 'type', None) == 'Identifier' and getattr(node.callee, 'name', '') == 'Function') or (
            t == 'CallExpression' and getattr(node.callee, 'type', None) == 'Identifier' and getattr(node.callee, 'name', '') == 'Function'):
            findings.append((filename, lineno, 'Function constructor usage'))

        # Assignments to innerHTML/outerHTML
        if t == 'AssignmentExpression' and getattr(node.left, 'type', None) == 'MemberExpression':
            prop = node.left.property
            if getattr(prop, 'name', '') in ('innerHTML', 'outerHTML'):
                findings.append((filename, lineno, f"Assignment to {prop.name}"))

        # String literals containing telemetry DSNs
        if t == 'Literal' and isinstance(getattr(node, 'value', None), str):
            if telemetry_regex.search(node.value):
                findings.append((filename, lineno, f"Telemetry string literal: {node.value[:80]}"))

        # Recurse into child nodes
        for child_name, child in node.__dict__.items():
            if child_name in ('loc', 'range'):
                continue
            if isinstance(child, list):
                for it in child:
                    if hasattr(it, 'type'):
                        walk(it, filename)
            elif hasattr(child, 'type'):
                walk(child, filename)

    for dirpath, dirs, files in os.walk(root_dir):
        for f in files:
            if f.endswith('.js'):
                path = os.path.join(dirpath, f)
                try:
                    with open(path, 'r', errors='ignore') as fh:
                        src = fh.read()
                    tree = esprima.parseScript(src, loc=True, tolerant=True)
                    walk(tree, path)
                except Exception:
                    continue

    if not findings:
        print(Fore.CYAN + "  [i] No AST-level risky constructs found in .js files." + Style.RESET_ALL)
        REPORT['js_ast_findings'] = []
    else:
        report = []
        for fn, ln, msg in findings:
            print(Fore.YELLOW + f"  [!] {fn}:{ln} -> {msg}" + Style.RESET_ALL)
            report.append({'file': fn, 'line': ln, 'message': msg})
        REPORT['js_ast_findings'] = report


def save_report(path):
    try:
        # Ensure datetime objects are serializable
        def _convert(o):
            if hasattr(o, 'isoformat'):
                return o.isoformat()
            return str(o)

        REPORT['generated_at'] = datetime.utcnow().isoformat()
        with open(path, 'w') as f:
            json.dump(REPORT, f, default=_convert, indent=2)
        print(Fore.CYAN + f"\n[+] Report saved to {path}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Failed to save report: {e}" + Style.RESET_ALL)


def check_robots_sitemap(base):
    print(f"\n[*] robots.txt and sitemap.xml for {base}")
    r_robots = fetch_url(base, "/robots.txt")
    robots_data = {'status': getattr(r_robots, 'status_code', None), 'disallows': []}
    if r_robots and r_robots.status_code == 200:
        print("  [+] robots.txt accessible")
        lines = [l.strip() for l in r_robots.text.splitlines() if l.strip()]
        disallows = [l for l in lines if l.lower().startswith("disallow:")]
        robots_data['disallows'] = disallows
        if disallows:
            print("    [!] Disallow entries:")
            for d in disallows[:10]:
                print(f"      - {d}")
    else:
        print(f"  [-] robots.txt not available (status {getattr(r_robots, 'status_code', 'N/A')})")

    r_sitemap = fetch_url(base, "/sitemap.xml")
    sitemap_data = {'status': getattr(r_sitemap, 'status_code', None), 'locs': []}
    if r_sitemap and r_sitemap.status_code == 200:
        print("  [+] sitemap.xml accessible")
        try:
            soup = BeautifulSoup(r_sitemap.text, "xml")
            locs = [loc.text for loc in soup.find_all('loc')]
            sitemap_data['locs'] = locs
            print(f"    [i] Sitemap contains {len(locs)} URL entries (showing up to 5):")
            for loc in locs[:5]:
                print(f"      - {loc}")
        except Exception:
            print("    [!] Could not parse sitemap.xml")
    else:
        print(f"  [-] sitemap.xml not available (status {getattr(r_sitemap, 'status_code', 'N/A')})")

    REPORT['robots'][base] = robots_data
    REPORT['sitemap'][base] = sitemap_data


def check_mx(domain):
    print(Fore.GREEN + f"\n[*] MX Record Lookup for {domain}" + Style.RESET_ALL)
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_hosts = []
        for rdata in answers:
            host = str(rdata.exchange).rstrip('.')
            mx_hosts.append(host)
            print(Fore.CYAN + f"  [+] MX: {host} (prio {rdata.preference})" + Style.RESET_ALL)

        # Advisory: if MX host is different domain, note third-party provider
        advisories = []
        for mx in mx_hosts:
            if mx and mx != domain and not mx.endswith(domain):
                msg = f"MX host {mx} is external to {domain}. If an attacker registers or controls {mx}, they could intercept mail for this domain."
                advisories.append(msg)
                print(Fore.YELLOW + f"  [!] Advisory: {msg}" + Style.RESET_ALL)

        REPORT['mx'][domain] = {'mx_hosts': mx_hosts, 'advisories': advisories}

    except dns.resolver.NXDOMAIN:
        msg = "Domain does not exist (NXDOMAIN). If available, an attacker could register it and intercept emails."
        print(Fore.RED + f"  [!] {msg}" + Style.RESET_ALL)
        REPORT['mx'][domain] = {'mx_hosts': [], 'advisories': [msg]}
    except Exception as e:
        print(Fore.RED + f"  [-] MX lookup failed: {e}" + Style.RESET_ALL)
        REPORT['mx'][domain] = {'error': str(e)}


def find_proto(root_dir="."):
    print("\n[*] Searching for .proto files in repo (no network actions)")
    found = []
    for dirpath, dirs, files in os.walk(root_dir):
        for f in files:
            if f.endswith('.proto'):
                found.append(os.path.join(dirpath, f))
    if found:
        for p in found:
            print(f"  [+] Found: {p}")
        print("  [i] To compile .proto into Python stubs install grpcio-tools and run:\n       python3 -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. <proto-file>")
        REPORT['proto_files'] = found
    else:
        print("  [-] No .proto files found in workspace")


def try_local_cookie_read():
    # Non-invasive: check for session_validated.json created by other tools
    print("\n[*] Checking for local session files")
    sess = "session_validated.json"
    if os.path.exists(sess):
        try:
            with open(sess, 'r') as f:
                data = json.load(f)
            print(f"  [+] {sess} found: {len(data)} cookies (names shown up to 10):")
            for i, k in enumerate(list(data.keys())[:10]):
                print(f"    - {k}")
        except Exception as e:
            print(f"  [-] Could not read {sess}: {e}")
    else:
        print(f"  [-] {sess} not found in cwd")
    REPORT['local_session'] = {'found': os.path.exists(sess), 'count': len(data) if os.path.exists(sess) else 0}


def main():
    parser = argparse.ArgumentParser(description='Web3 by Z4X - Safe passive scanner')
    parser.add_argument('--target', '-t', help='Target IP or domain (example.com or 127.0.0.1:443)')
    parser.add_argument('--pause', '-p', type=float, default=1.5, help='Seconds to pause between phases')
    parser.add_argument('--toolkit', '-k', nargs='*', choices=['ssl', 'headers', 'proto', 'mx', 'all'], help='Advanced toolkit features to run')
    parser.add_argument('--lbc-csv', dest='lbc_csv', help='Path to centralized ledger CSV for LBRY audit')
    parser.add_argument('--lbc-sdk', dest='lbc_sdk', action='store_true', help='Attempt to query local LBRY SDK for on-chain balance')
    parser.add_argument('--output', '-o', dest='output', default='web3_scan_report.json', help='Path to JSON output report')
    parser.add_argument('--eslint', dest='eslint', action='store_true', help='Run ESLint via npx (if available)')
    args = parser.parse_args()

    print_banner()

    if args.target:
        raw = args.target
    else:
        raw = prompt_target()

    if not raw:
        print("No target provided. Exiting.")
        sys.exit(0)

    base = normalize_target(raw)
    parsed = urlparse(base)
    host = parsed.hostname or raw

    pause = getattr(args, 'pause', 1.5)

    print(Fore.MAGENTA + f"\n[>] Scanning target: {base} (host: {host})" + Style.RESET_ALL)

    print(Fore.YELLOW + "\n[~] HTTP Header check is loading..." + Style.RESET_ALL)
    time.sleep(pause)
    r = fetch_url(base, "/")
    if r:
        check_headers(base)
        security_header_matrix(r.headers)
        # SSL check as part of main scan: attempt on port 443 for domains
        if any(c.isalpha() for c in host):
            print(Fore.YELLOW + "\n[~] SSL certificate analysis is loading (port 443)..." + Style.RESET_ALL)
            time.sleep(pause)
            check_ssl_cert(host, port=443)
    else:
        print(Fore.RED + "  [-] Could not fetch root page for headers." + Style.RESET_ALL)

    print(Fore.YELLOW + "\n[~] Checking robots.txt and sitemap.xml..." + Style.RESET_ALL)
    time.sleep(pause)
    check_robots_sitemap(base)

    # Try MX only if looks like a domain
    if any(c.isalpha() for c in host):
        print(Fore.YELLOW + "\n[~] MX lookup is loading..." + Style.RESET_ALL)
        time.sleep(pause)
        check_mx(host)
    else:
        print(Fore.YELLOW + "\n[*] Skipping MX lookup (target looks like IP)" + Style.RESET_ALL)

    print(Fore.YELLOW + "\n[~] Searching workspace for .proto files..." + Style.RESET_ALL)
    time.sleep(pause)
    find_proto('.')

    print(Fore.YELLOW + "\n[~] Checking for local session files..." + Style.RESET_ALL)
    time.sleep(pause)
    try_local_cookie_read()

    # Wallet checker prompt (optional)
    print(Fore.YELLOW + "\n[~] Optional: wallet balance/UTXO check available." + Style.RESET_ALL)
    wallet = input(Fore.YELLOW + "Enter CoinEx/BitTorrent wallet (or q to skip): " + Style.RESET_ALL).strip()
    if wallet and wallet.lower() != 'q':
        try:
            wallet_check(wallet)
        except Exception as e:
            print(Fore.RED + f"  [-] Wallet check failed: {e}" + Style.RESET_ALL)
    # Scan repo for addresses
    time.sleep(0.5)
    scan_repo_for_wallets('.')
    # Optional LBRY audit via CLI flags
    if getattr(args, 'lbc_csv', None):
        audit_csv(args.lbc_csv)
    if getattr(args, 'lbc_sdk', False):
        check_sdk_balance()

    # Toolkit: optional advanced checks
    if args.toolkit:
        tools = args.toolkit
        if 'all' in tools:
            tools = ['ssl', 'headers', 'proto', 'mx']
        print(Fore.GREEN + "\n[*] Running toolkit features: " + ", ".join(tools) + Style.RESET_ALL)
        for t in tools:
            time.sleep(pause)
            if t == 'ssl':
                print(Fore.YELLOW + "\n[~] SSL certificate info (toolkit)" + Style.RESET_ALL)
                try:
                    ctx = ssl.create_default_context()
                    with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                        s.settimeout(5)
                        s.connect((host, 443))
                        cert = s.getpeercert()
                    print(Fore.CYAN + f"  [+] Subject: {cert.get('subject')}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"  [+] Issuer: {cert.get('issuer')}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"  [+] NotBefore/NotAfter: {cert.get('notBefore')}/{cert.get('notAfter')}" + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"  [-] SSL toolkit failed: {e}" + Style.RESET_ALL)
            elif t == 'headers':
                print(Fore.YELLOW + "\n[~] Re-running header matrix (toolkit)" + Style.RESET_ALL)
                r2 = fetch_url(base, "/")
                if r2:
                    security_header_matrix(r2.headers)
            elif t == 'proto':
                find_proto('.')
            elif t == 'mx':
                check_mx(host)

    print('\n[*] Scan complete. All checks were passive and read-only.')
    # After main scan, run JS linter scan
    time.sleep(0.5)
    js_lint_scan('.')
    js_ast_scan('.')
    # Optional ESLint run
    if getattr(args, 'eslint', False):
        run_eslint('.')

    # Save report
    out = getattr(args, 'output', 'web3_scan_report.json')
    REPORT['target'] = base
    save_report(out)


if __name__ == '__main__':
    main()
