import datetime
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
    return crc & 0xFF

def calculate_mjd_with_decimal(year, month, day, hour, minute, second, fraction):
    if month <= 2:
        year -= 1
        month += 12
    A = year // 100
    B = 2 - A + (A // 4)
    jd = int(365.25 * (year + 4716)) + int(30.6001 * (month + 1)) + day + B - 1524.5
    mjd = jd - 2400000.5
    return mjd + fraction

def main():
    # Step 1: Calculate a Modified Julian Date (MJD) with decimal places
    current_utc_datetime = datetime.datetime.utcnow()
    current_mjd_fraction = current_utc_datetime.microsecond / 1e6
    current_mjd_with_decimal = calculate_mjd_with_decimal(current_utc_datetime.year, current_utc_datetime.month,
                                                        current_utc_datetime.day, current_utc_datetime.hour,
                                                        current_utc_datetime.minute, current_utc_datetime.second,
                                                        current_mjd_fraction)
    print("MJD with Decimal:", current_mjd_with_decimal)

    # Step 2: Calculate the CRC-8-ROHC value for the MJD
    mjd_bytes = int(current_mjd_with_decimal).to_bytes(3, 'big')  # Assuming MJD is represented as a 24-bit integer
    crc8_rohc_value = crc8_rohc(mjd_bytes)
    print("CRC-8-ROHC Value:", crc8_rohc_value)

    # Step 3: Convert the MJD and CRC-8-ROHC value into base58
    encoded_mjd = base58.b58encode_int(int(current_mjd_with_decimal))
    encoded_crc8_rohc = base58.b58encode_int(crc8_rohc_value)

    # Step 4: Prepend the CRC-8-ROHC value to the MJD
    combined_value = encoded_crc8_rohc + encoded_mjd
    print("\nCombined Base58 Value:", combined_value)

    # Step 5: Extract the CRC-8-ROHC value and the MJD from the combined base58 value
    extracted_crc8_rohc = base58.b58decode_int(combined_value[:2])
    extracted_mjd = base58.b58decode_int(combined_value[2:])

    print("\nExtracted CRC-8-ROHC Value:", extracted_crc8_rohc)
    print("Extracted MJD:", extracted_mjd)

    # Step 6: Calculate the CRC-8-ROHC value again for the extracted MJD
    extracted_mjd_bytes = extracted_mjd.to_bytes(3, 'big')
    recalculated_crc8_rohc = crc8_rohc(extracted_mjd_bytes)
    print("\nRecalculated CRC-8-ROHC Value:", recalculated_crc8_rohc)

    # Step 7: Verify that the calculated CRC-8-ROHC value matches the extracted CRC-8-ROHC value
    verification_result = "Verification Passed" if recalculated_crc8_rohc == extracted_crc8_rohc else "Verification Failed"
    print("\nVerification Result:", verification_result)

if __name__ == "__main__":
    main()
