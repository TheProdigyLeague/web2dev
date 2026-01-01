import cloudscraper

target_url = "https://montcalmautosales.com/xmlrpc.php"

def audit_xmlrpc():
    # Use cloudscraper to handle the 403 blocks seen in your curl attempt
    scraper = cloudscraper.create_scraper(
        browser={'browser': 'chrome', 'platform': 'windows', 'desktop': True}
    )
    
    # XML payload to list available system methods
    xml_payload = """<?xml version="1.0" encoding="utf-8"?> 
    <methodCall> 
      <methodName>system.listMethods</methodName> 
      <params></params> 
    </methodCall>"""

    print(f"[*] Testing XML-RPC introspection on {target_url}...")

    try:
        headers = {'Content-Type': 'text/xml'}
        response = scraper.post(target_url, data=xml_payload, headers=headers, timeout=15)
        
        if response.status_code == 200:
            print("[+] Success! XML-RPC is accessible.")
            print("[*] Available Methods:")
            print(response.text)
        else:
            print(f"[!] Blocked: Status {response.status_code}")
            if "Cloudflare" in response.text:
                print("[-] Cloudflare WAF intercepted the XML-RPC call.")
                
    except Exception as e:
        print(f"[X] Error: {e}")

if __name__ == "__main__":
    audit_xmlrpc()
