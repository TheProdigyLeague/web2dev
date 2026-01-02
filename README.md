# Web3 by Z4X — Safe Scanner

This repository contains a small, safe, read-only scanner `web3_zaxkeroth_scanner.py` that performs passive reconnaissance checks only:

- HTTP header inspection
- robots.txt and sitemap.xml fetch and parsing
- MX record lookup (DNS)
- Local search for `.proto` files (no network compilation)
- Non-invasive check for a local `session_validated.json` file

Legal: Use this tool only on systems you own or have explicit permission to test. The author and contributors are not responsible for misuse.

Quick start

1. Install dependencies (recommended inside a virtualenv):

```bash
python3 -m pip install -r requirements.txt
```

2. Run the scanner and enter a target when prompted:

```bash
python3 ./web3_zaxkeroth_scanner.py
# then type: example.com  or  127.0.0.1:443
```

Notes

- The scanner is intentionally conservative and non-destructive. It does not attempt exploits, password guessing, or intrusive scans.
- To compile `.proto` files into Python stubs locally, install `grpcio-tools` and run the suggested `protoc` command shown by the tool.

Current version
---------------

- **Version:** 2026.3
- **Release date:** 2026-01-01
- **Notable additions:** Z4K banner, multi-chain wallet checks (BTC/ETH), AST-based JS linting, optional ESLint integration, LBRY ledger audit support, SSL chain parsing with cryptography.

Changelog (high-level)
----------------------

2025-11-01 — Initial development
- Created a minimal passive scanner with header checks, robots/sitemap parsing, and MX lookups.

2025-12-03 — UX and tooling
- Added colored console output, staged progress messages, CLI flags, and repo proto search.

2025-12-15 — Wallet & ledger support
- Implemented BTC wallet quick-checks via public API and CSV-ledger audit for LBRY credits.

2025-12-22 — SSL and JS analysis
- Upgraded SSL parsing to pyOpenSSL + cryptography to parse full certificate chains and expiration warnings.
- Added JS static keyword scanning and AST-based analysis via `esprima`.

2026-01-01 — Z4X release
- Replaced ASCII banner with the Z4K banner and binary block.
- Added `web3` support, ETH RPC endpoint configuration (`https://cloudflare-eth.com`) and `eth_wallet_check`.
- Added optional `--eslint` integration and local ESLint helper; placed dependency files under `node_modules` when installed.

Repository layout updates
------------------------

- `AKAM-GHost/` — contains the `gH*` helper scripts (moved/copied for organization).
- `NET-CF/` — contains `gateway` related files (`gateway.proto`, `gateway.py`, compiled stubs).

Usage reminders
---------------

- Use this tool only on systems you own or are authorized to test.
- ESLint integration requires Node.js and `npm` — install dependencies with `npm install` in the repository root before using `--eslint`.

