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

class SnowflakeGenerator:
    def __init__(self, poly):
        self.sequence = 0
        self.last_timestamp = -1
        self.table = generate_crc8_table(poly)

    def current_mjd(self):
        """Returns the Modified Julian Date for the current UTC time."""
        jd_ref = datetime.datetime(1858, 11, 17)
        now = datetime.datetime.utcnow()
        mjd = (now - jd_ref).days + (now.hour * 3600 + now.minute * 60 + now.second) / 86400
        return int(mjd * 86400000)

    def generate_id(self):
        """Generates a custom Snowflake ID, bit shifts to add CRC-8 checksum."""
        timestamp = self.current_mjd()
        if timestamp != self.last_timestamp:
            self.sequence = 0
            self.last_timestamp = timestamp
        else:
            self.sequence += 1
            if self.sequence >= (1 << 15):
                raise Exception("Sequence overflow. Wait for next millisecond.")

        # Generate the Snowflake ID without the CRC-8
        snowflake_id = (timestamp << 15) | self.sequence
        
        # Calculate CRC-8 for the Snowflake ID
        crc = self.calculate_crc8(snowflake_id.to_bytes(8, byteorder="big"))
        
        # Bit shift the Snowflake ID to the left by 8 bits to make space for CRC-8
        shifted_id = snowflake_id << 8
        
        # Append CRC-8 in the least significant bits of the shifted ID
        final_id = shifted_id | crc
        
        return crc, snowflake_id, final_id

    def calculate_crc8(self, data):
        """Calculate CRC-8 for the given data using the specified table."""
        crc = 0x00
        for byte in data:
            crc = self.table[(crc ^ byte) & 0xFF]
        return crc

def verify_id(final_id_base58, poly):
    """Verifies the integrity of the final ID by comparing CRC-8 checksums."""
    final_id = base58_decode(final_id_base58)
    generator = SnowflakeGenerator(poly)
    extracted_crc = final_id & 0xFF
    snowflake_id = final_id >> 8
    recalculated_crc = generator.calculate_crc8(snowflake_id.to_bytes(8, byteorder="big"))

    if extracted_crc == recalculated_crc:
        print("Verification successful: The CRC-8 checksum matches.")
        return True
    else:
        print("Verification failed: The CRC-8 checksum does not match.")
        return False

def find_best_poly():
    """Finds the best CRC-8 polynomial based on randomly generated Snowflake IDs."""
    best_poly = None
    best_unique_crcs = 0
    sample_snowflake_ids = [random.getrandbits(56) for _ in range(1000)]  # Adjust bit length for CRC-8

    for poly in range(256):
        generator = SnowflakeGenerator(poly)
        crc_values = set(generator.calculate_crc8(sf_id.to_bytes(8, byteorder="big")) for sf_id in sample_snowflake_ids)
        if len(crc_values) > best_unique_crcs:
            best_unique_crcs = len(crc_values)
            best_poly = poly

    print(f"Best polynomial: 0x{best_poly:02X} with {best_unique_crcs} unique CRC-8 values.")
    return best_poly

def main():
    parser = argparse.ArgumentParser(description="Generate or verify a Snowflake ID with CRC-8.")
    parser.add_argument("--verify", type=str, help="Verify the specified Snowflake ID (Base58 encoded).")
    parser.add_argument("--poly", type=lambda x: int(x, 0), help="Specify the CRC-8 polynomial in hex format.", default=0x07)
    parser.add_argument("--find-best-poly", action="store_true", help="Find the best CRC-8 polynomial for Snowflake IDs.")
    
    args = parser.parse_args()

    if args.find_best_poly:
        find_best_poly()
    elif args.verify:
        verify_id(args.verify, args.poly)
    else:
        generator = SnowflakeGenerator(args.poly)
        _, snowflake_id, final_id = generator.generate_id()
        print(f"Generated Snowflake ID: {snowflake_id}")
        print(f"Final ID with CRC-8 appended (Base58): {base58_encode(final_id)}")

if __name__ == "__main__":
    main()
