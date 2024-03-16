import datetime
import struct
import base58

def crc8_rohc(data):
    poly = 0x07  # Polynomial for CRC-8-ROHC
    crc = 0xFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
        crc &= 0xFF  # Ensure crc remains within 8 bits
    return crc

def calculate_mjd_with_decimal(year, month, day, hour, minute, second, fraction):
    if month <= 2:
        year -= 1
        month += 12
    A = year // 100
    B = 2 - A + (A // 4)
    jd = int(365.25 * (year + 4716)) + int(30.6001 * (month + 1)) + day + B - 1524.5
    mjd = jd - 2400000.5
    # Convert hour, minute, and second to fractional day
    day_fraction = (hour + minute / 60.0 + second / 3600.0) / 24.0
    return mjd + day_fraction + fraction / 1e6  # Adjust for microsecond precision

def main():
    # Calculate a Modified Julian Date (MJD) with decimal places
    current_utc_datetime = datetime.datetime.utcnow()
    current_mjd_with_decimal = calculate_mjd_with_decimal(current_utc_datetime.year, current_utc_datetime.month,
                                                          current_utc_datetime.day, current_utc_datetime.hour,
                                                          current_utc_datetime.minute, current_utc_datetime.second,
                                                          current_utc_datetime.microsecond)
    print("MJD with Decimal:", current_mjd_with_decimal)

    # Convert the MJD with decimal places to bytes
    mjd_bytes = struct.pack('>f', current_mjd_with_decimal)

    # Calculate the CRC-8-ROHC value for the MJD bytes
    crc8_rohc_value = crc8_rohc(mjd_bytes)
    print("CRC-8-ROHC Value:", crc8_rohc_value)

    # Encode the combined MJD and CRC-8-ROHC value into base58
    combined_bytes = struct.pack('>fB', current_mjd_with_decimal, crc8_rohc_value)
    combined_base58 = base58.b58encode(combined_bytes)
    print("\nCombined Base58 Value:", combined_base58.decode())

    # Decode the combined value from base58
    decoded_bytes = base58.b58decode(combined_base58)
    extracted_mjd, extracted_crc8_rohc = struct.unpack('>fB', decoded_bytes)
    print("\nExtracted CRC-8-ROHC Value:", extracted_crc8_rohc)
    print("Extracted MJD:", extracted_mjd)

    # Recalculate the CRC-8-ROHC for verification
    recalculated_crc8_rohc = crc8_rohc(struct.pack('>f', extracted_mjd))
    print("\nRecalculated CRC-8-ROHC Value:", recalculated_crc8_rohc)

    # Verify that the recalculated CRC-8-ROHC matches the extracted value
    verification_result = "Verification Passed" if recalculated_crc8_rohc == extracted_crc8_rohc else "Verification Failed"
    print("\nVerification Result:", verification_result)

if __name__ == "__main__":
    main()
