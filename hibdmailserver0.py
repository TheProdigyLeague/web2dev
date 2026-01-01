import requests
from bs4 import BeautifulSoup

def audit_recon_files(base_url):
    print(f"--- Zaxkeroth Recon Audit: {base_url} ---\n")
    
    # Files to check for information disclosure
    recon_targets = ["/robots.txt", "/sitemap.xml"]
    
    for target in recon_targets:
        url = base_url.rstrip('/') + target
        print(f"[*] Testing: {url}")
        
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                print(f" [!] FOUND: {target} is publicly accessible.")
                
                # Logic for Robots.txt analysis
                if target == "/robots.txt":
                    disallowed = [line for line in res.text.split('\n') if line.startswith('Disallow:')]
                    if disallowed:
                        print(f" [!] Potential Sensitive Paths found in Robots.txt:")
                        for path in disallowed:
                            print(f"  [>] {path.strip()}")
                
                # Logic for Sitemap analysis
                if target == "/sitemap.xml":
                    soup = BeautifulSoup(res.text, 'xml')
                    locs = soup.find_all('loc')
                    print(f" [i] Sitemap contains {len(locs)} indexed URLs.")
                    # Check for keywords that might indicate admin or dev areas
                    sensitive_keywords = ['admin', 'config', 'backup', 'dev', 'test', 'portal']
                    for loc in locs:
                        if any(key in loc.text.lower() for key in sensitive_keywords):
                            print(f"  [!] Sensitive URL found in Sitemap: {loc.text}")

            else:
                print(f" [-] {target} returned status {res.status_code}")
                
        except Exception as e:
            print(f" [!] Connection Error on {target}: {e}")

if __name__ == "__main__":
    audit_recon_files("http://www.turbotax.com")
