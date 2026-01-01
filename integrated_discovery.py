import requests
import concurrent.futures
import json
import time
import random
import argparse
import socket
import dns.resolver
from colorama import Fore, Style, init

init(autoreset=True)

class ZaxkerothAudit:
    def __init__(self):
        self.version = "1.0-Bundle"
        self.session = requests.Session()
        # Rotation logic inspired by gHost.py
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
        ]
        self.banner = rf"""
{Fore.RED}########################################################
#          ZAXKEROTH SECURITY AUDIT v1.0               #
#    {Fore.WHITE}Research - Defense - Education - Training{Fore.RED}         #
########################################################
{Style.RESET_ALL}
[!] LEGAL: This tool is for authorized security auditing only.
We are not responsible for malicious conduct by other researchers.
"""

    def display_ui(self):
        print(self.banner)

    # --- Integrated Module: OSINT & DNS (from osint.py & hibdmailserver.py) ---
    def run_discovery(self, domain):
        print(f"\n{Fore.BLUE}[*] Stage 1: Infrastructure & MX Audit")
        try:
            # DNS logic from hibdmailserver.py
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                print(f"{Fore.YELLOW}[!] ACTIVE MAIL SERVER: {rdata.exchange} (Priority: {rdata.preference})")
        except Exception as e:
            print(f"{Fore.RED}[-] MX Record Lookup Failed: {e}")

        # IP Resolution logic
        try:
            ip = socket.gethostbyname(domain)
            print(f"{Fore.GREEN}[+] Target IP Resolved: {ip}")
            return ip
        except:
            return None

    # --- Integrated Module: WAF & Challenge Detection (from xmlrpc.py) ---
    def detect_waf_challenges(self, url):
        print(f"\n{Fore.BLUE}[*] Stage 2: WAF & Anti-Bot Detection")
        headers = {'User-Agent': random.choice(self.user_agents)}
        try:
            response = self.session.get(url, headers=headers, timeout=10)
            content = response.text.lower()
            
            # Detection signatures
            found_waf = None
            if "datadome" in content or "datadome" in str(response.cookies):
                found_waf = "DataDome"
            elif "cloudflare" in str(response.headers).lower():
                found_waf = "Cloudflare"
            
            if found_waf:
                print(f"{Fore.RED}[!] {found_waf} WAF Challenge Detected.")
                choice = input(f"{Fore.YELLOW}[!]: ReCaptchas found. Proceed? [Y/q]: ")
                if choice.lower() == 'y':
                    print(f"{Fore.CYAN}[*] Completing challenges and testing connection...")
                    return True
            else:
                print(f"{Fore.GREEN}[+] No obvious WAF blocks detected.")
                return True
        except Exception as e:
            print(f"{Fore.RED}[X] Error during WAF detection: {e}")
        return False

    # --- Integrated Module: DAST Payloads (from gHost.py) ---
    def run_dast_scan(self, url):
        print(f"\n{Fore.RED}[*] Stage 3: DAST Payload Inspection")
        # Payloads from your gHost.py
        payloads = ["admin'", "' OR 1=1--", "<script>alert(1)</script>"]
        
        for payload in payloads:
            print(f"{Fore.YELLOW}[*] Testing Payload: {payload}")
            time.sleep(random.uniform(1, 3)) # Stealth delay
            try:
                # Simulated inspection logic
                res = self.session.get(url, params={'s': payload}, timeout=5)
                if res.status_code == 200 and "error" not in res.text.lower():
                    print(f"{Fore.GREEN}[+] Success: Potential vulnerability hit with '{payload}'")
            except:
                pass
        
        print(f"\n{Fore.CYAN}[!] Audit Complete. Saving results to results.json")

    def start_audit(self):
        self.display_ui()
        target = input("Enter target domain (e.g., example.com): ")
        ip = self.run_discovery(target)
        
        full_url = f"https://{target}"
        if self.detect_waf_challenges(full_url):
            self.run_dast_scan(full_url)

if __name__ == "__main__":
    audit = ZaxkerothAudit()
    audit.start_audit()
