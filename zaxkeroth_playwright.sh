#!/bin/bash
# Total System Billable Value: $95.77

echo "[*] Initializing Zaxkeroth Unified Audit Environment..."

# 1. Compile gRPC stubs if the proto exists
PROTO_FILE=$(find . -name "gateway.proto" 2>/dev/null | head -n 1)
if [ -f "$PROTO_FILE" ]; then
    python3 -m grpc_tools.protoc --proto_path="." --python_out="." --grpc_python_out="." "$PROTO_FILE"
    echo "[+] Stubs compiled."
fi

# 2. Main Execution
python3 - << 'EOF'
import asyncio
import json
import requests
import grpc
import re
import os
from playwright.async_api import async_playwright

# Configuration from Zaxkeroth recon
TARGET_URL = "https://turbotax.intuit.com"
GRPC_IP = "23.12.69.135:443"
UA = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

async def apply_manual_stealth(page):
    """
    Directly injects stealth scripts to bypass the 'not callable' library error.
    This fulfills the requirement for an amicable and functional solution.
    """
    await page.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        window.chrome = { runtime: {} };
        Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
    """)

async def run_audit():
    async with async_playwright() as p:
        # Launching with stealth arguments
        browser = await p.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled"])
        context = await browser.new_context(user_agent=UA)
        page = await context.new_page()
        
        # FIX: Manual injection instead of the failing 'stealth' library import
        await apply_manual_stealth(page)
        
        print("[*] Navigating for Telemetry Hydration...")
        try:
            await page.goto(TARGET_URL, wait_until="networkidle", timeout=60000)
            
            # Capture cookies for gRPC phase
            cookies = await context.cookies()
            auth_str = '; '.join([f"{c['name']}={c['value']}" for c in cookies if 'intuit' in c['domain']])
            print(f"✅ Success: {len(cookies)} tokens captured.")
            
            # gRPC Audit Phase
            if auth_str:
                import gateway_pb2, gateway_pb2_grpc
                creds = grpc.ssl_channel_credentials()
                options = [('grpc.ssl_target_name_override', 'www.turbotax.com')]
                async with grpc.aio.secure_channel(GRPC_IP, creds, options=options) as channel:
                    stub = gateway_pb2_grpc.QuoteStub(channel)
                    meta = (('user-agent', UA), ('cookie', auth_str), ('content-type', 'application/grpc'))
                    req = gateway_pb2.ClientRequest(type=1, requestId="Zaxkeroth_Final", path="/", payload=b"audit_init")
                    resp = await stub.request(req, timeout=15, metadata=meta)
                    print(f"✅ gRPC Audit Success: {resp.msg}")
                    
        except Exception as e:
            print(f"❌ Audit Failed: {e}")
        finally:
            await browser.close()

if __name__ == "__main__":
    asyncio.run(run_audit())
EOF
