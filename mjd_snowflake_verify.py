import datetime
import argparse
import random

# Base58 encoding characters
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def generate_crc8_table(poly):
    """Generate the CRC-8 table for a given polynomial."""
    table = [0] * 256
    for byte in range(256):
        crc = byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFF
        table[byte] = crc
    return table

def base58_encode(num):
    """Encode a number in Base58."""
    encode = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        encode = BASE58_ALPHABET[remainder] + encode
    return encode

def base58_decode(s):
    """Decode a Base58-encoded string."""
    num = 0
    for char in s:
        num = num * 58 + BASE58_ALPHABET.index(char)
    return num

def find_best_poly(sample_snowflake_ids):
    """Finds the best CRC-8 polynomial based on the sample Snowflake IDs."""
    best_poly = None
    best_unique_crcs = 0

    for poly in range(256):
        generator = SnowflakeGenerator(poly)
        crc_values = set(generator.calculate_crc8(sf_id.to_bytes(8, byteorder="big")) for sf_id in sample_snowflake_ids)
        if len(crc_values) > best_unique_crcs:
            best_unique_crcs = len(crc_values)
            best_poly = poly

    return best_poly

class SnowflakeGenerator:
    def __init__(self, poly):
        self.sequence = 0
        self.last_timestamp = -1
        self.poly = poly
        self.table = generate_crc8_table(poly)

    def current_mjd(self):
        """Returns the Modified Julian Date for the current UTC time."""
        jd_ref = datetime.datetime(1858, 11, 17)
        now = datetime.datetime.utcnow()
        mjd = (now - jd_ref).days + (now.hour * 3600 + now.minute * 60 + now.second) / 86400
        return int(mjd * 86400000), mjd

    def generate_id(self):
        """Generates a custom Snowflake ID with CRC-8 checksum and polynomial prepended."""
        timestamp, mjd = self.current_mjd()
        if timestamp != self.last_timestamp:
            self.sequence = 0
            self.last_timestamp = timestamp
        else:
            self.sequence += 1
            if self.sequence >= (1 << 15):
                raise Exception("Sequence overflow. Wait for next millisecond.")

        snowflake_id = (timestamp << 15) | self.sequence
        crc = self.calculate_crc8(snowflake_id.to_bytes(8, byteorder="big"))
        shifted_id = snowflake_id << 16  # Make space for CRC-8 and polynomial
        final_id = shifted_id | (self.poly << 8) | crc
        return crc, snowflake_id, final_id, mjd

    def calculate_crc8(self, data):
        """Calculate CRC-8 for the given data using the specified table."""
        crc = 0x00
        for byte in data:
            crc = self.table[(crc ^ byte) & 0xFF]
        return crc

def extract_info_from_id(final_id):
    """Extracts the polynomial, CRC, and Snowflake ID from the final numeric ID."""
    extracted_crc = final_id & 0xFF
    extracted_poly = (final_id >> 8) & 0xFF
    snowflake_id = final_id >> 16
    return extracted_poly, extracted_crc, snowflake_id

def verify_id(final_id_base58):
    """Verifies the integrity of the final ID by comparing CRC-8 checksums."""
    final_id = base58_decode(final_id_base58)
    extracted_poly, extracted_crc, snowflake_id = extract_info_from_id(final_id)
    generator = SnowflakeGenerator(extracted_poly)
    recalculated_crc = generator.calculate_crc8(snowflake_id.to_bytes(8, byteorder="big"))

    mjd_timestamp = snowflake_id >> 47  # Adjust based on your Snowflake ID structure
    mjd = datetime.datetime(1858, 11, 17) + datetime.timedelta(days=mjd_timestamp)

    if extracted_crc == recalculated_crc:
        print(f"Verification successful: The CRC-8 checksum matches. MJD: {mjd}")
        print(f"Verified with polynomial: 0x{extracted_poly:02X}")
        return True
    else:
        print("Verification failed: The CRC-8 checksum does not match.")
        return False

def main():
    parser = argparse.ArgumentParser(description="Generate or verify a Snowflake ID with CRC-8.")
    parser.add_argument("--verify", type=str, help="Verify the specified Snowflake ID (Base58 encoded).")
    
    args = parser.parse_args()

    if args.verify:
        verify_id(args.verify)
    else:
        # Generate sample Snowflake IDs to determine the best polynomial
        sample_snowflake_ids = [random.getrandbits(48) for _ in range(1000)]
        best_poly = find_best_poly(sample_snowflake_ids)
        print(f"Using best polynomial: 0x{best_poly:02X}")

        generator = SnowflakeGenerator(best_poly)
        crc, snowflake_id, final_id, mjd = generator.generate_id()
        print(f"Snowflake ID: {snowflake_id} (MJD: {mjd})")
        print(f"Final ID with CRC-8 and poly prepended (Base58): {base58_encode(final_id)}")
        print(f"Used polynomial: 0x{best_poly:02X}")

if __name__ == "__main__":
    main()
