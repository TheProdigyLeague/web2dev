import requests
from bs4 import BeautifulSoup

target = "http://www.turbotax.com"
headers = {
    "User-Agent": "Zaxkeroth-Security-Audit/4.0"
}

def validate_findings():
    print(f"[*] Validating Zaxkeroth Audit Findings on: {target}\n")
    
    try:
        # Check for Information Leaks (X-Powered-By)
        res = requests.get(target, headers=headers, timeout=10)
        if 'X-Powered-By' in res.headers:
            print(f"[!] LEAK CONFIRMED: X-Powered-By header reveals: {res.headers['X-Powered-By']}")
        
        # Check for Insecure Form Transitions (HTTP vs HTTPS)
        soup = BeautifulSoup(res.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if action.startswith('http:'):
                print(f"[!] INSECURE TRANSITION: Form found posting to unencrypted HTTP: {action}")

        # Verify Robots.txt and Sitemap
        for path in ["/robots.txt", "/sitemap.xml"]:
            if requests.get(target + path).status_code == 200:
                print(f"[+] RECON LEAK: {path} is publicly accessible.")

    except Exception as e:
        print(f"[X] Validation Error: {e}")

if __name__ == "__main__":
    validate_findings()
