#!/bin/bash

echo "[*] Initializing Zaxkeroth Audit Environment..."

# 1. Install missing XML parser for sitemap audit
echo "[*] Installing XML parser for BeautifulSoup..."
pip install lxml --quiet

# 2. Automated Proto Compilation
echo "[*] Locating and compiling .proto files..."
# This finds gateway.proto regardless of whether it's in the current or parent dir
PROTO_FILE=$(find . -name "gateway.proto" | head -n 1)

if [ -f "$PROTO_FILE" ]; then
    PROTO_DIR=$(dirname "$PROTO_FILE")
    python3 -m grpc_tools.protoc --proto_path="$PROTO_DIR" --python_out="$PROTO_DIR" --grpc_python_out="$PROTO_DIR" "$PROTO_FILE"
    echo "[+] Compiled: $PROTO_FILE"
else
    echo "[!] ERROR: gateway.proto not found. Please ensure it exists in the project tree."
fi

# 3. Targeted Directory Fuzzer
# This uses the sensitive paths found in your robots.txt audit
TARGET="https://www.turbotax.com"
SENSITIVE_PATHS=("/dev/" "/api/" "/devgruntconsole/" "/ci/" "/qa/" "/testing/" "/images/email/auth/" "/site-performance/")

echo "[*] Starting Targeted Sensitive Path Scan on $TARGET..."

for path in "${SENSITIVE_PATHS[@]}"; do
    # Using -I to just fetch headers and check status codes
    STATUS=$(curl -o /dev/null -s -w "%{http_code}" "$TARGET$path")
    
    if [ "$STATUS" == "200" ]; then
        echo "[!!!] VULNERABILITY FOUND: $path is PUBLICLY ACCESSIBLE (Status: 200)"
    elif [ "$STATUS" == "403" ]; then
        echo "[-] Blocked: $path (Status: 403 Forbidden)"
    elif [ "$STATUS" == "429" ]; then
        echo "[!] RATE LIMITED: Akamai has flagged the probe at $path (Status: 429)"
    else
        echo "[.] Checked: $path (Status: $STATUS)"
    fi
done

echo "[*] Audit Automation Complete."
