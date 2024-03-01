import argparse
import requests
import sqlite3
import socket
import uuid
import re
import os
import textwrap
from base58 import b58encode, b58decode
from prettytable import PrettyTable

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
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Could not resolve {host}")
        exit(1)

def check_reverse_dns(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "No reverse DNS record"

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
                        vulns TEXT
                      )''')
    return conn

def store_or_update_data_in_db(conn, data, identifier, reverse_dns):
    cursor = conn.cursor()
    # Check if data for this IP/host already exists by attempting to match IP or hostnames
    cursor.execute("SELECT uuid FROM internetdb_cache WHERE ip = ? OR hostnames LIKE ?", (data['ip'], f"%{identifier}%"))
    existing_uuid = cursor.fetchone()
    
    if existing_uuid:
        uuid58 = existing_uuid[0]
    else:
        uuid58 = generate_uuid58()

    # Use REPLACE INTO to update or insert new
    cursor.execute('''REPLACE INTO internetdb_cache (uuid, ip, reverse_dns, ports, cpes, hostnames, tags, vulns)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (
                          uuid58,
                          data.get('ip', ''),
                          reverse_dns,
                          ','.join(map(str, data.get('ports', []))),
                          ','.join(data.get('cpes', [])),
                          ','.join(data.get('hostnames', [])),
                          ','.join(data.get('tags', [])),
                          ','.join(data.get('vulns', []))
                      ))
    conn.commit()
    print(f"Data stored/updated with UUID58: {uuid58}")

def wrap_text(text, width):
    """Wrap text for a given width."""
    return '\n'.join(textwrap.wrap(text, width))

def get_terminal_width():
    """Get the current terminal width to adjust table display."""
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80  # Default to 80 columns if terminal size cannot be determined

def display_data_from_db(conn, identifier, ip_address=None):
    cursor = conn.cursor()
    query = "SELECT * FROM internetdb_cache WHERE ip = ? OR hostnames LIKE ?"
    cursor.execute(query, (ip_address if ip_address else identifier, f"%{identifier}%"))
    rows = cursor.fetchall()

    if rows:
        terminal_width = get_terminal_width()
        column_width = max(20, terminal_width // 8)  # Adjust based on the number of columns

        table = PrettyTable()
        table.field_names = ["UUID58", "IP", "Reverse DNS", "Ports", "CPES", "Hostnames", "Tags", "Vulns"]
        for row in rows:
            wrapped_row = [wrap_text(str(col), column_width) for col in row]
            table.add_row(wrapped_row)

        print(table)
        return True
    return False

def refresh_or_fetch_data(conn, identifier, force_refresh=False):
    ip_address = resolve_host_to_ip(identifier) if not is_valid_uuid58(identifier) and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", identifier) else identifier
    reverse_dns = check_reverse_dns(ip_address) if not is_valid_uuid58(identifier) else "N/A"

    if not force_refresh and display_data_from_db(conn, identifier, ip_address=ip_address):
        print("Data retrieved from local cache.")
        return

    print("Fetching data from InternetDB...")
    data = fetch_internetdb_data(ip_address)
    store_or_update_data_in_db(conn, data, identifier, reverse_dns)
    display_data_from_db(conn, identifier, ip_address=ip_address)

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
