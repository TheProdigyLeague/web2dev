import requests

target = "https://www.turbotax.com/"
# Mimicking the browser agent found in your recon data
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
}

# Common Drupal paths that should ideally be 403 (Forbidden) or 404
paths_to_check = [
    "/core/install.php",        # Should be blocked after install
    "/CHANGELOG.txt",           # Often reveals exact version
    "/web.config",              # Info disclosure
    "/sites/default/settings.php", # Critical config (High Risk)
    "/robots.txt"               # Can reveal hidden directories
]

def check_vulnerabilities():
    print(f"[*] Starting validation on: {target}\n")
    
    for path in paths_to_check:
        url = f"{target}{path}"
        try:
            response = requests.get(url, headers=headers, timeout=5)
            status = response.status_code
            
            if status == 200:
                print(f"[!] POTENTIAL LEAK: {url} (Status: {status})")
                if "Drupal" in response.text:
                    print(f"    [+] Content confirms Drupal presence.")
            elif status == 403:
                print(f"[*] Secure: {url} (Status: 403 Forbidden)")
            else:
                print(f"[-] Not found: {url} (Status: {status})")
                
        except requests.exceptions.RequestException as e:
            print(f"[X] Error connecting to {url}: {e}")

if __name__ == "__main__":
    check_vulnerabilities()
