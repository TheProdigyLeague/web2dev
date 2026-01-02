import asyncio, json
from playwright.async_api import async_playwright
from playwright_stealth import stealth 
async def run_ghost_protocol():
    async with async_playwright() as p:
        user_agent = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(user_agent=user_agent)
        page = await context.new_page()
        await stealth(page) 
        print("[*] Navigating to TurboTax... waiting for Telemetry Hydration.")
        try:
            await page.goto("https://turbotax.intuit.com", wait_until="networkidle", timeout=60000)
            await page.wait_for_function("window.isDatalayerHydrated === true", timeout=30000)
            print("[+] Telemetry Hydrated.")
            await page.mouse.move(150, 150)
            await asyncio.sleep(1)
            cookies = await context.cookies()
            auth_cookies = {c['name']: c['value'] for c in cookies if 'intuit' in c['domain']}
            with open("session_validated.json", "w") as f:
                json.dump(auth_cookies, f)
            print(f"✅ Success: {len(auth_cookies)} tokens captured.")
        except Exception as e:
            print(f"❌ Ghost Protocol Failed: {e}")
        finally:
            await browser.close()
if __name__ == "__main__":
    asyncio.run(run_ghost_protocol())
