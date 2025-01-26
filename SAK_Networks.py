import socket
import subprocess
import requests
import re
import os
import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP

# Common ports and their associated services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}

# API keys (replace with your own)
MAC_VENDOR_API = "https://api.macvendors.com/"
IP_GEOLOCATION_API = "http://ip-api.com/json/"

def scan_port(ip, port):
    """Scan a specific port on the target IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return False

def port_scanner():
    """Scan a target IP for open ports."""
    target_ip = input("Enter the target IP address: ").strip()
    start_port = int(input("Enter the starting port (default: 1): ") or 1)
    end_port = int(input("Enter the ending port (default: 1024): ") or 1024)

    print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
    open_ports = []
    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            service = COMMON_PORTS.get(port, "Unknown")
            open_ports.append((port, service))
            print(f"Port {port} ({service}) is open.")
    print("Scan complete!")

def ping_sweeper():
    """Ping a range of IPs to identify live hosts."""
    base_ip = input("Enter the base IP (e.g., 192.168.1): ").strip()
    start = int(input("Enter the starting IP (e.g., 1): ").strip())
    end = int(input("Enter the ending IP (e.g., 10): ").strip())

    print(f"Pinging IPs from {base_ip}.{start} to {base_ip}.{end}...")
    for i in range(start, end + 1):
        ip = f"{base_ip}.{i}"
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", ip]
        try:
            subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            print(f"{ip} is live.")
        except subprocess.CalledProcessError:
            print(f"{ip} is not responding.")
    print("Ping sweep complete!")

def subdomain_enum():
    """Enumerate subdomains of a target domain."""
    domain = input("Enter the target domain (e.g., example.com): ").strip()
    wordlist = input("Enter the path to the wordlist file: ").strip()

    if not os.path.exists(wordlist):
        print("Wordlist file not found.")
        return

    with open(wordlist, "r") as file:
        subdomains = file.read().splitlines()

    print(f"Enumerating subdomains for {domain}...")
    for subdomain in subdomains:
        full_domain = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            print(f"{full_domain} -> {ip}")
        except socket.error:
            pass
    print("Subdomain enumeration complete!")

def whois_lookup():
    """Perform a WHOIS lookup for a domain."""
    domain = input("Enter the target domain (e.g., example.com): ").strip()
    try:
        import whois
        info = whois.whois(domain)
        print(info)
    except ImportError:
        print("Please install the 'python-whois' library: pip install python-whois")
    except Exception as e:
        print(f"Error performing WHOIS lookup: {e}")

def dns_resolver():
    """Resolve a domain name to its IP address."""
    domain = input("Enter the target domain (e.g., example.com): ").strip()
    try:
        ip = socket.gethostbyname(domain)
        print(f"{domain} resolves to {ip}")
    except socket.error:
        print(f"Could not resolve {domain}")

def http_header_checker():
    """Fetch and display HTTP headers of a website."""
    url = input("Enter the target URL (e.g., https://example.com): ").strip()
    try:
        response = requests.head(url)
        print(f"HTTP Headers for {url}:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
    except requests.RequestException as e:
        print(f"Error fetching HTTP headers: {e}")

def mac_lookup():
    """Look up the vendor of a MAC address."""
    mac = input("Enter the MAC address (e.g., 00:1A:2B:3C:4D:5E): ").strip()
    try:
        response = requests.get(f"{MAC_VENDOR_API}{mac}")
        if response.status_code == 200:
            print(f"Vendor: {response.text}")
        else:
            print("Vendor not found.")
    except requests.RequestException as e:
        print(f"Error looking up MAC address: {e}")

def geolocation_lookup():
    """Get the geolocation of an IP address."""
    ip = input("Enter the target IP address: ").strip()
    try:
        response = requests.get(f"{IP_GEOLOCATION_API}{ip}")
        data = response.json()
        if data["status"] == "success":
            print(f"Geolocation for {ip}:")
            print(f"Country: {data['country']}")
            print(f"Region: {data['regionName']}")
            print(f"City: {data['city']}")
            print(f"ISP: {data['isp']}")
        else:
            print("Geolocation lookup failed.")
    except requests.RequestException as e:
        print(f"Error looking up geolocation: {e}")

def packet_sniffer():
    """Capture and analyze network packets."""
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    try:
        sniff(filter="tcp", prn=lambda x: x.summary())
    except KeyboardInterrupt:
        print("Packet sniffing stopped.")

def main():
    print("Network & Security Toolkit")
    print("-------------------------")
    print("1. Port Scanner")
    print("2. Ping Sweeper")
    print("3. Subdomain Enumerator")
    print("4. WHOIS Lookup")
    print("5. DNS Resolver")
    print("6. HTTP Header Checker")
    print("7. MAC Address Lookup")
    print("8. Geolocation Lookup")
    print("9. Packet Sniffer")
    choice = input("Choose an option (1-9): ").strip()

    if choice == "1":
        port_scanner()
    elif choice == "2":
        ping_sweeper()
    elif choice == "3":
        subdomain_enum()
    elif choice == "4":
        whois_lookup()
    elif choice == "5":
        dns_resolver()
    elif choice == "6":
        http_header_checker()
    elif choice == "7":
        mac_lookup()
    elif choice == "8":
        geolocation_lookup()
    elif choice == "9":
        packet_sniffer()
    else:
        print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
