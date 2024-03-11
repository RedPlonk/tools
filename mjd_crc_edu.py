import base58
from datetime import datetime

def crc8(data, poly):
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
    return crc & 0xFF

def utc_to_mjd(year, month, day):
    # Calculate Julian date
    if month <= 2:
        year -= 1
        month += 12
    A = year // 100
    B = 2 - A + (A // 4)
    jd = int(365.25 * (year + 4716)) + int(30.6001 * (month + 1)) + day + B - 1524.5

    # Calculate Modified Julian Date (MJD)
    mjd = jd - 2400000.5
    return int(mjd)

def find_best_crc_polynomial():
    best_poly = None
    min_error = float('inf')
    
    for poly in range(1, 256):  # iterate over all possible polynomials
        error = 0
        
        # Iterate over a range of MJD values
        for mjd in range(65536):  # iterate over all possible MJD values
            mjd_bytes = mjd.to_bytes(2, 'big')
            crc = crc8(mjd_bytes, poly)
            mjd_with_crc_and_poly = (mjd << 8*2) | (crc << 8) | poly  # storing both CRC-8 and polynomial
            verified_mjd_info = verify_mjd_with_crc(mjd_with_crc_and_poly) # pass the polynomial here
            if verified_mjd_info is None or verified_mjd_info[0] != mjd:
                error += 1
        
        # Update the best polynomial if this one has fewer errors
        if error < min_error:
            min_error = error
            best_poly = poly
    
    return best_poly

def append_crc_and_poly_to_mjd(mjd, best_crc_poly):
    mjd_bytes = mjd.to_bytes(2, 'big')
    crc = crc8(mjd_bytes, best_crc_poly)  # using the best polynomial
    mjd_with_crc_and_poly = (mjd << 8*2) | (crc << 8) | best_crc_poly  # storing both CRC-8 and polynomial
    return mjd_with_crc_and_poly

def verify_mjd_with_crc(mjd_with_crc_and_poly):
    mjd = mjd_with_crc_and_poly >> 16
    crc = (mjd_with_crc_and_poly >> 8) & 0xFF
    poly = mjd_with_crc_and_poly & 0xFF
    mjd_bytes = mjd.to_bytes(2, 'big')
    recalculated_crc = crc8(mjd_bytes, poly)  # using the polynomial
    if recalculated_crc == crc:
        return mjd, crc, poly
    else:
        return None

# Encode values in base58
def encode_base58(value):
    return base58.b58encode_int(value).decode('utf-8')

# Get current UTC date
current_utc_date = datetime.utcnow()

# Derive MJD from current UTC date
current_mjd = utc_to_mjd(current_utc_date.year, current_utc_date.month, current_utc_date.day)
print("Current MJD:", current_mjd)

# Find the best CRC-8 polynomial
best_crc_poly = find_best_crc_polynomial()
print("Best CRC-8 Polynomial:", hex(best_crc_poly))

# Append CRC-8 and polynomial to MJD
mjd_with_crc_and_poly = append_crc_and_poly_to_mjd(current_mjd, best_crc_poly)
print("MJD with CRC-8 and Polynomial:", mjd_with_crc_and_poly)

# Split MJD with CRC-8 and Polynomial into components
mjd = mjd_with_crc_and_poly >> 16
crc = (mjd_with_crc_and_poly >> 8) & 0xFF
poly = mjd_with_crc_and_poly & 0xFF

# Encode each component in base58
encoded_mjd = encode_base58(mjd)
encoded_crc = str(crc)  # Using string representation instead of base58
encoded_poly = encode_base58(poly)

# Display encoded values
print("\nEncoded Values:")
print("MJD:", encoded_mjd)
print("CRC-8:", encoded_crc)
print("Polynomial:", encoded_poly)

# Display combined encoded value
combined_encoded_value = encoded_mjd + encoded_crc + encoded_poly
print("\nCombined Encoded Value for Verification:", combined_encoded_value)

# Verify MJD with CRC-8 and Polynomial
verified_mjd_info = verify_mjd_with_crc(mjd_with_crc_and_poly)
if verified_mjd_info is not None:
    verified_mjd, verified_crc, verified_poly = verified_mjd_info
    print("\nVerification Result:")
    print("Verified MJD:", verified_mjd)
    print("Verified CRC-8:", verified_crc)
    print("Verified Polynomial:", hex(verified_poly))
else:
    print("Verification failed.")
