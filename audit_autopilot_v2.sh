#!/bin/bash

echo "[*] Initializing Zaxkeroth Audit Environment V2..."

# 1. Automated Proto Compilation (Aggressive Search)
echo "[*] Searching for gateway.proto in all subdirectories..."
PROTO_FILE=$(find ~ -name "gateway.proto" 2>/dev/null | head -n 1)

if [ -f "$PROTO_FILE" ]; then
    PROTO_DIR=$(dirname "$PROTO_FILE")
    python3 -m grpc_tools.protoc --proto_path="$PROTO_DIR" --python_out="$PROTO_DIR" --grpc_python_out="$PROTO_DIR" "$PROTO_FILE"
    echo "[+] SUCCESS: Compiled $PROTO_FILE into stubs."
else
    echo "[!] CRITICAL: gateway.proto still not found in your home directory."
fi

# 2. Redirect-Aware Targeted Scan
TARGET="https://www.turbotax.com"
SENSITIVE_PATHS=("/dev/" "/api/" "/devgruntconsole/" "/ci/" "/qa/" "/testing/" "/images/email/auth/" "/site-performance/")

echo "[*] Probing redirects for Zaxkeroth analysis..."

for path in "${SENSITIVE_PATHS[@]}"; do
    # -L follows redirects, -w reports the final URL reached
    FINAL_URL=$(curl -Ls -o /dev/null -w "%{url_effective}" "$TARGET$path")
    STATUS=$(curl -o /dev/null -s -w "%{http_code}" "$TARGET$path")
    
    if [[ "$FINAL_URL" == *"$TARGET"* && "$FINAL_URL" != "$TARGET$path" ]]; then
        echo "[!] CLOAKING DETECTED: $path redirects to $FINAL_URL (Status: $STATUS)"
    elif [ "$STATUS" == "200" ]; then
        echo "[!!!] VULNERABILITY: $path is DIRECTLY ACCESSIBLE (Status: 200)"
    else
        echo "[-] Path $path is shielded (Status: $STATUS)"
    fi
done

echo "[*] V2 Audit Complete."
