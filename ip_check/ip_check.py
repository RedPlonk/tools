import argparse
import uuid
import base58
import sqlite3
import subprocess
import requests
import json
import socket
import os
import logging
import ipaddress
import stun

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def generate_base58_uuid():
    return base58.b58encode(uuid.uuid4().bytes).decode('utf-8')

def is_ip_alive(ip_address):
    try:
        subprocess.run(["ping", "-c", "1", ip_address], check=True, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def resolve_hostname(hostname):
    try:
        return socket.gethostbyname_ex(hostname)[2]
    except socket.gaierror as e:
        logging.error(f"Error resolving hostname {hostname}: {e}")
        return []

def perform_api_request(url, headers):
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else None
    except requests.RequestException as e:
        logging.error(f"Error during request to {url}: {e}")
        return None

def lookup_shodan_internetdb(ip_address, api_key):
    url = f"https://internetdb.shodan.io/{ip_address}"
    headers = {"Authorization": f"Shodan {api_key}"}
    return perform_api_request(url, headers)

def lookup_virustotal(ip_address, api_key):
    if not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    return perform_api_request(url, headers)

def is_port_open(ip_address, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip_address, port))
            return True
    except (socket.timeout, socket.error):
        return False

def update_database(ip_address, uuid, is_alive, internetdb_data, virustotal_data, open_ports):
    with sqlite3.connect('ip_status.db') as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS internetdb (
                id INTEGER PRIMARY KEY,
                ip TEXT UNIQUE NOT NULL,
                uuid TEXT NOT NULL,
                alive INTEGER NOT NULL,
                internetdb_data TEXT,
                virustotal_data TEXT,
                open_ports TEXT
            )
        """)
        conn.execute("""
            INSERT INTO internetdb (ip, uuid, alive, internetdb_data, virustotal_data, open_ports)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
            uuid = excluded.uuid,
            alive = excluded.alive,
            internetdb_data = excluded.internetdb_data,
            virustotal_data = excluded.virustotal_data,
            open_ports = excluded.open_ports
        """, (ip_address, uuid, is_alive, json.dumps(internetdb_data), json.dumps(virustotal_data), json.dumps(open_ports)))

def get_public_ip():
    nat_type, external_ip, external_port = stun.get_ip_info()
    return external_ip

def process_ip(ip_address, shodan_api_key, virustotal_api_key, tcp_ping_enabled):
    uuid58 = generate_base58_uuid()
    alive = is_ip_alive(ip_address)
    
    open_ports = []
    if tcp_ping_enabled:
        ports_to_check = [21, 22, 53, 80, 443, 3389]
        open_ports = [port for port in ports_to_check if is_port_open(ip_address, port)]

    internetdb_data = lookup_shodan_internetdb(ip_address, shodan_api_key)
    virustotal_data = lookup_virustotal(ip_address, virustotal_api_key)
    update_database(ip_address, uuid58, alive, internetdb_data, virustotal_data, open_ports)

    print(f"IP: {ip_address}, Status: {'Alive' if alive else 'Not Alive'}, UUID: {uuid58}, Open Ports: {open_ports if tcp_ping_enabled else 'TCP Ping Disabled'}")
    if internetdb_data:
        print(f"InternetDB Data: {internetdb_data}")
    if virustotal_data:
        print_virustotal_data(virustotal_data)

def print_virustotal_data(virustotal_data):
    last_analysis_results = virustotal_data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
    print("\n+--------------------------+------------+-----------+")
    print("| Engine Name              | Category   | Result    |")
    print("+--------------------------+------------+-----------+")
    for engine, data in last_analysis_results.items():
        engine_name = (engine[:24] + '..') if len(engine) > 24 else engine.ljust(24)
        category = data.get('category', 'N/A').ljust(10)
        result = data.get('result', 'N/A').ljust(9)
        print(f"| {engine_name} | {category} | {result} |")
    print("+--------------------------+------------+-----------+")

def main():
    parser = argparse.ArgumentParser(description="IP/Hostname Check with Base58 UUID, Shodan InternetDB, and optional VirusTotal Lookup")
    parser.add_argument("input", help="IP address, hostname, or file containing IP addresses/hostnames to check")
    parser.add_argument("--shodan-api-key", required=True, help="Shodan API Key")
    parser.add_argument("--virustotal-api-key", help="VirusTotal API Key (optional)")
    parser.add_argument("--tcp-ping", action="store_true", help="Enable TCP ping to check open ports (default: disabled)")
    parser.add_argument("--check-public-ip", action="store_true", help="Check the reputation of the public IP with Shodan and VirusTotal (default: disabled)")
    args = parser.parse_args()

    if args.check_public_ip:
        public_ip = get_public_ip()
        print(f"Public IP (via STUN): {public_ip}")
        if args.shodan_api_key:
            shodan_data = lookup_shodan_internetdb(public_ip, args.shodan_api_key)
            print(f"Shodan Data for Public IP: {shodan_data}")
        if args.virustotal_api_key:
            virustotal_data = lookup_virustotal(public_ip, args.virustotal_api_key)
            print_virustotal_data(virustotal_data)

    if os.path.isfile(args.input):
        with open(args.input) as file:
            for line in file:
                ip_or_hostname = line.strip()
                if is_valid_ip(ip_or_hostname):
                    process_ip(ip_or_hostname, args.shodan_api_key, args.virustotal_api_key, args.tcp_ping)
                else:
                    resolved_ips = resolve_hostname(ip_or_hostname)
                    for ip in resolved_ips:
                        process_ip(ip, args.shodan_api_key, args.virustotal_api_key, args.tcp_ping)
    else:
        if is_valid_ip(args.input):
            process_ip(args.input, args.shodan_api_key, args.virustotal_api_key, args.tcp_ping)
        else:
            resolved_ips = resolve_hostname(args.input)
            for ip in resolved_ips:
                process_ip(ip, args.shodan_api_key, args.virustotal_api_key, args.tcp_ping)

if __name__ == "__main__":
    main()
