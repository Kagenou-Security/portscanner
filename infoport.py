#!/usr/bin/env python3
import argparse
import socket
import sys
import re

# Colors for output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

PORT_INFO = {
    20: "FTP Data - Vulnerable to data interception if unencrypted.",
    21: "FTP Control - Prone to anonymous access or brute-force attacks.",
    22: "SSH - Weak keys/credentials; exploits like CVE-2023-48795 (Terrapin).",
    23: "Telnet - Unencrypted; susceptible to eavesdropping and MITM attacks.",
    25: "SMTP - Open relays enable spam; vulnerable to command injection.",
    53: "DNS - Cache poisoning or amplification DDoS attacks.",
    67: "DHCP Server - Can be abused for rogue DHCP attacks.",
    68: "DHCP Client - Vulnerable to spoofed DHCP responses.",
    69: "TFTP - No authentication; often abused for file exfiltration.",
    80: "HTTP - Insecure sites prone to XSS, SQLi, or unpatched server exploits.",
    110: "POP3 - Cleartext authentication; mailbox credential theft.",
    119: "NNTP - Can leak sensitive info; historically abused for spam.",
    123: "NTP - Amplification DDoS vector; time spoofing possible.",
    135: "Microsoft RPC - Target for MSBlast and DCOM exploits.",
    137: "NetBIOS Name Service - Info disclosure & SMB relay attacks.",
    138: "NetBIOS Datagram - Can be exploited in LAN attacks.",
    139: "NetBIOS Session - Basis of SMB vulnerabilities like EternalBlue.",
    143: "IMAP - Cleartext login (if not over SSL/TLS); mailbox exploits.",
    161: "SNMP - Default 'public/private' community strings are weak.",
    162: "SNMP Trap - Can be spoofed for false alerts or DoS.",
    179: "BGP - Route hijacking, MITM, prefix leaks.",
    389: "LDAP - Injection attacks; weak LDAP bind credentials.",
    443: "HTTPS - Misconfigured SSL/TLS; vulnerable ciphersuites.",
    445: "SMB - EternalBlue (CVE-2017-0144), WannaCry, credential theft.",
    465: "SMTPS - Deprecated; if weak TLS, allows downgrade attacks.",
    514: "Syslog - Cleartext; attackers may flood logs or spoof entries.",
    515: "LPD - Remote printer exploits; DoS vectors.",
    587: "SMTP Submission - Misconfigured relay allows spam abuse.",
    631: "IPP (CUPS Printing) - RCE via vulnerable print spooler services.",
    636: "LDAPS - Vulnerable if using weak certs/TLS configs.",
    873: "rsync - Anonymous modules allow data theft.",
    993: "IMAPS - SSL/TLS downgrade attacks possible.",
    995: "POP3S - SSL/TLS downgrade attacks possible.",
    1080: "SOCKS Proxy - Open proxies can be abused for anonymity.",
    1433: "MSSQL - Brute-force attacks, SQL injection via misconfig.",
    1521: "Oracle DB - Exploitable PL/SQL injection flaws.",
    2049: "NFS - Unauthenticated mounts; data exfiltration.",
    2181: "Zookeeper - No auth by default; info disclosure.",
    2375: "Docker API - RCE if exposed without TLS/auth.",
    3306: "MySQL - SQL injection; weak passwords; CVE exploits.",
    3389: "RDP - BlueKeep (CVE-2019-0708), brute-force attacks.",
    3690: "Subversion - Sensitive repo leaks if misconfigured.",
    4444: "Metasploit default payload handler; often abused by malware.",
    5000: "UPnP/Web apps - RCE if exposed to WAN.",
    5432: "PostgreSQL - SQL injection, weak passwords.",
    5900: "VNC - Brute-force, no encryption by default.",
    5985: "WinRM HTTP - Cred theft if unencrypted.",
    5986: "WinRM HTTPS - Weak TLS configs exploitable.",
    6379: "Redis - No auth by default; RCE via misused commands.",
    8000: "Alternate HTTP - Often runs vulnerable dev servers.",
    8080: "Proxy/Alt HTTP - Common for misconfigured admin panels.",
    8443: "Alt HTTPS - Often misconfigured admin services.",
    9000: "PHP-FPM / SonarQube - Remote code execution flaws.",
    9200: "Elasticsearch - Default no auth; CVE RCEs.",
    11211: "Memcached - Amplification DDoS if UDP exposed.",
    27017: "MongoDB - No auth by default (historically leaked DBs).",
    33848: "Some backdoors/trojans listen here; check unknown services."
}


def valid_host(host: str) -> bool:
    """Validate hostname or IP."""
    hostname_pattern = r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$"
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(hostname_pattern, host) or re.match(ip_pattern, host))

def check_port(host: str, port: int, timeout=1) -> str:
    """Check port status."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
        return "open" if result == 0 else "closed"
    except socket.timeout:
        return "filtered"
    except Exception:
        return "error"

def get_status_color(status: str) -> str:
    if status == "open":
        return GREEN + status + RESET
    elif status == "filtered":
        return YELLOW + status + RESET
    else:
        return RED + status + RESET

def get_vuln_desc(port: int) -> str:
    """Get vulnerability description for port."""
    return PORT_INFO.get(port, "Unknown service - Potential for unpatched vulnerabilities or misconfigurations.")

def scan_ports(host: str, start: int, end: int):
    print(f"\nScanning {host} from port {start} to {end}...\n")
    for port in range(start, end + 1):
        status = check_port(host, port)
        print(f"Port {port}: {get_status_color(status)}")
        if status == "open":
            print(f"  Vulnerability: {get_vuln_desc(port)}\n")

def interactive_mode():
    print("""
cccccccccccccccccccccccccccccccccccccccccccccc
ccccccccccccccccccccccccc__________ccccccccccc
cccccc| |ccccc| |cccccc// ________ \\ccccccccc
cccccc| |ccccc| |cccccc|| |      | ||ccccccccc
cccccc| |ccccc| |cccccc|| |Udrit | ||ccccccccc
cccccc| |ccccc| |cccccc|| |Dhakal| ||ccccccccc
cccccc| |ccccc| |cccccc|| |______| ||ccccccccc
cccccc|_________|cccccc\\__________//ccccccccc
cccccccccccccccccccccccccccccccccccccccccccccc
""")
    while True:
        host = input("Enter target host (domain or IP): ").strip()
        if valid_host(host):
            break
        print("Invalid host.\n")

    while True:
        try:
            start = int(input("Enter starting port (0-65535): "))
            if 0 <= start <= 65535:
                break
            print("Invalid port.\n")
        except ValueError:
            print("Invalid input.\n")

    while True:
        try:
            end = int(input(f"Enter ending port ({start}-65535): "))
            if start <= end <= 65535:
                break
            print("Invalid port.\n")
        except ValueError:
            print("Invalid input.\n")

    scan_ports(host, start, end)

def main():
    parser = argparse.ArgumentParser(description="Professional Port Scanner")
    parser.add_argument("host", nargs="?", help="Target host")
    parser.add_argument("start", nargs="?", type=int, help="Start port")
    parser.add_argument("end", nargs="?", type=int, help="End port")
    parser.add_argument("-v", "--version", action="store_true", help="Show version")

    args = parser.parse_args()

    if args.version:
        print("netcheck.py v1.1")
        sys.exit(0)

    if not args.host:
        interactive_mode()
    else:
        if not valid_host(args.host):
            print("Invalid host.")
            sys.exit(1)
        if args.start is None or args.end is None or not (0 <= args.start <= 65535) or not (0 <= args.end <= 65535) or args.start > args.end:
            print("Invalid port range (0-65535).")
            sys.exit(1)
        scan_ports(args.host, args.start, args.end)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")

        sys.exit(1)
