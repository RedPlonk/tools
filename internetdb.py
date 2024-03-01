import argparse
import requests
import sqlite3
import socket
import uuid
import os
import textwrap
from datetime import datetime
from base58 import b58encode, b58decode
from prettytable import PrettyTable
import re # RegEx

def is_valid_uuid58(uuid_str):
    try:
        b58decode(uuid_str)
        return True
    except ValueError:
        return False

def generate_uuid58():
    return b58encode(uuid.uuid4().bytes).decode('utf-8')

def resolve_host_to_ip(host):
    try:
        return [ip[4][0] for ip in socket.getaddrinfo(host, None)]
    except socket.gaierror:
        print(f"Could not resolve {host}")
        exit(1)

def check_reverse_dns(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "No reverse DNS record"

def datetime_to_mjd(dt):
    return dt.toordinal() + 1721424.5 - 2400000.5

def fetch_internetdb_data(ip_address):
    response = requests.get(f"https://internetdb.shodan.io/{ip_address}")
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch data for IP: {ip_address}")
        exit(1)

def create_or_connect_database():
    conn = sqlite3.connect("internetdb_cache.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS internetdb_cache (
                        uuid TEXT PRIMARY KEY,
                        ip TEXT,
                        reverse_dns TEXT,
                        ports TEXT,
                        cpes TEXT,
                        hostnames TEXT,
                        tags TEXT,
                        vulns TEXT,
                        timestamp REAL
                      )''')
    return conn

def store_or_update_data_in_db(conn, data, hostname, ip_address, reverse_dns):
    cursor = conn.cursor()
    current_mjd = datetime_to_mjd(datetime.utcnow())
    uuid58 = generate_uuid58()

    cursor.execute('''REPLACE INTO internetdb_cache (uuid, ip, reverse_dns, ports, cpes, hostnames, tags, vulns, timestamp)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
                          uuid58,
                          ip_address,
                          reverse_dns,
                          ','.join(map(str, data.get('ports', []))),
                          ','.join(data.get('cpes', [])),
                          hostname,
                          ','.join(data.get('tags', [])),
                          ','.join(data.get('vulns', [])),
                          current_mjd
                      ))
    conn.commit()
    print(f"Data for {ip_address} stored/updated with UUID58: {uuid58}")

def wrap_text(text, width):
    return '\n'.join(textwrap.wrap(text, width))

def get_terminal_width():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80

def display_data_from_db(conn, identifier):
    cursor = conn.cursor()
    query = "SELECT uuid, ip, reverse_dns, ports, cpes, hostnames, tags, vulns, timestamp FROM internetdb_cache WHERE hostnames = ?"
    cursor.execute(query, (identifier,))
    rows = cursor.fetchall()

    if rows:
        terminal_width = get_terminal_width()
        column_width = max(20, terminal_width // 9)

        table = PrettyTable()
        table.field_names = ["UUID58", "IP", "Reverse DNS", "Ports", "CPES", "Hostnames", "Tags", "Vulns", "Timestamp"]
        for row in rows:
            row = list(row)
            row[-1] = datetime.fromordinal(int(row[-1] + 2400000.5 - 1721424.5)).strftime('%Y-%m-%d')
            wrapped_row = [wrap_text(str(col), column_width) for col in row]
            table.add_row(wrapped_row)

        print(table)
    else:
        print(f"No data found for {identifier}")

def refresh_or_fetch_data(conn, identifier, force_refresh=False):
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", identifier):
        ip_addresses = resolve_host_to_ip(identifier)
    else:
        ip_addresses = [identifier]

    for ip_address in ip_addresses:
        reverse_dns = check_reverse_dns(ip_address) if ip_address == identifier else "N/A"
        data = fetch_internetdb_data(ip_address)
        store_or_update_data_in_db(conn, data, identifier, ip_address, reverse_dns)

    display_data_from_db(conn, identifier)

def main():
    parser = argparse.ArgumentParser(description="Cache InternetDB data.")
    parser.add_argument("identifier", help="IP address, FQDN, or UUID58 to resolve, fetch, and cache data for.")
    parser.add_argument("--refresh", action="store_true", help="Force refresh the data for the given identifier.")
    args = parser.parse_args()
    
    conn = create_or_connect_database()
    refresh_or_fetch_data(conn, args.identifier, force_refresh=args.refresh)
    conn.close()

if __name__ == "__main__":
    main()
