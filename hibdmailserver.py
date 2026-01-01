import dns.resolver

def check_mx_records(domain):
    print(f"[*] Auditing MX Records for: {domain}")
    try:
        # Resolve the MX (Mail Exchange) records
        answers = dns.resolver.resolve(domain, 'MX')
        
        for rdata in answers:
            print(f"[!] ACTIVE MAIL SERVER FOUND: {rdata.exchange} (Priority: {rdata.preference})")
            print("    [ADVISORY] If you do not own this domain, an attacker can receive your AT&T reset codes.")
            
    except dns.resolver.NoAnswer:
        print("[+] Result: No MX records found. The domain is not currently configured to receive email.")
    except dns.resolver.NXDOMAIN:
        print("[!] Result: Domain does not exist (NXDOMAIN).")
        print("    [CRITICAL DEFENSE NOTE] This domain is available for registration.")
        print("    An attacker can buy this domain and set up their own MX records to hijack your account.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    check_mx_records("turbotax.com")
