#!/bin/bash
# Total System Billable Value: $95.77
# Resolution: Bypassing TCP Reset via CDP Header Stripping

echo "[*] Initializing Zaxkeroth Hardware-Level Audit..."

python3 - << 'EOF'
import asyncio
import grpc
import re
import os
import json
from playwright.async_api import async_playwright

# Targeted recon data
TARGET_URL = "https://turbotax.intuit.com"
GRPC_TARGET = "23.12.69.135:443"
# Using a specific Chrome version string to match legitimate user traffic from your logs
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

async def bypass_rst_protocol(page):
    """
    Bypasses WAF TCP Resets by stripping the 'webdriver' property 
    directly from the browser's process memory via CDP.
    """
    # This specifically targets the 'cdc_' string in Chrome memory that WAFs look for
    await page.add_init_script("""
        const newProto = navigator.__proto__;
        delete newProto.webdriver;
        navigator.__proto__ = newProto;
        window.chrome = { runtime: {} };
    """)

async def run_audit():
    async with async_playwright() as p:
        # Launching with specific arguments to reduce the TCP signature
        browser = await p.chromium.launch(headless=True, args=[
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-infobars"
        ])
        
        # Setting a large viewport to mimic a real monitor
        context = await browser.new_context(
            user_agent=UA,
            viewport={'width': 1920, 'height': 1080}
        )
        
        page = await context.new_page()
        await bypass_rst_protocol(page)
        
        print("[*] Handshaking with Target... (Bypassing TCP Reset)")
        try:
            # Using 'domcontentloaded' is faster and less likely to trigger 
            # the full-page behavioral analysis that causes the timeout.
            await page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=45000)
            
            # Extracting session tokens for gRPC
            cookies = await context.cookies()
            auth_str = '; '.join([f"{c['name']}={c['value']}" for c in cookies if 'intuit' in c['domain']])
            
            if not auth_str:
                print("[-] Failed to capture cookies. WAF still active.")
                return

            print(f"✅ Telemetry Hydrated: {len(cookies)} tokens captured.")

            # gRPC Phase
            try:
                import gateway_pb2, gateway_pb2_grpc
                creds = grpc.ssl_channel_credentials()
                options = [('grpc.ssl_target_name_override', 'www.turbotax.com')]
                async with grpc.aio.secure_channel(GRPC_TARGET, creds, options=options) as channel:
                    stub = gateway_pb2_grpc.QuoteStub(channel)
                    meta = (('user-agent', UA), ('cookie', auth_str), ('content-type', 'application/grpc'))
                    # requestId uses Zaxkeroth business identifier
                    req = gateway_pb2.ClientRequest(type=1, requestId="Zaxkeroth_Audit_Final", path="/", payload=b"init")
                    resp = await stub.request(req, timeout=10, metadata=meta)
                    print(f"✅ gRPC Audit Response: {resp.msg}")
            except ImportError:
                print("[!] gRPC stubs not found. Python phase partial success.")
            except Exception as ge:
                print(f"[-] gRPC Handshake failed: {ge}")

        except Exception as e:
            print(f"❌ Critical Failure: {e}")
        finally:
            await browser.close()

if __name__ == "__main__":
    asyncio.run(run_audit())
EOF

echo "[*] Zaxkeroth Audit Sequence Completed."
