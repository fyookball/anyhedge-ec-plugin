from enum import Enum
from hashlib import sha256
 
class Base58AddressFormatVersion(Enum):
    p2pkh = 0
    p2sh20 = 5
    wif = 128
    p2pkhTestnet = 111
    p2sh20Testnet = 196
    wifTestnet = 239
    p2pkhCopayBCH = 28
    p2sh20CopayBCH = 40

def encode_base58_address_format(version, payload, sha256_function=sha256):
    checksum_bytes = 4
    content = bytes([version]) + payload
    checksum = sha256_function(sha256_function(content).digest()).digest()[:checksum_bytes]
    bin_data = flatten_bin_array([content, checksum]) 
    return base_encode(bin_data, 58)

def encode_base58_address(type, payload, sha256_function=sha256):
    type_to_version = {
        "p2pkh": Base58AddressFormatVersion.p2pkh,
        "p2pkhCopayBCH": Base58AddressFormatVersion.p2pkhCopayBCH,
        "p2pkhTestnet": Base58AddressFormatVersion.p2pkhTestnet,
        "p2sh20": Base58AddressFormatVersion.p2sh20,
        "p2sh20CopayBCH": Base58AddressFormatVersion.p2sh20CopayBCH,
        "p2sh20Testnet": Base58AddressFormatVersion.p2sh20Testnet,
    }
    return encode_base58_address_format(type_to_version[type], payload, sha256_function)

class Base58AddressError(Enum):
    unknownCharacter = "Base58Address error: address may only contain valid base58 characters."
    tooShort = "Base58Address error: address is too short to be valid."
    invalidChecksum = "Base58Address error: address has an invalid checksum."
    unknownAddressVersion = "Base58Address error: address uses an unknown address version."
    incorrectLength = "Base58Address error: the encoded payload is not the correct length (20 bytes)."

def decode_base58_address_format(address, sha256_function=sha256):
    checksum_bytes = 4 
    bin_data= base_decode(address, None, 58) 
    minimum_base58_address_length = 5
    if len(bin_data) < minimum_base58_address_length:
        return Base58AddressError.tooShort
    content = bin_data[:-checksum_bytes]
    checksum = bin_data[-checksum_bytes:]
    expected_checksum = sha256_function(sha256_function(content).digest()).digest()[:checksum_bytes]
    if not all(x == y for x, y in zip(checksum, expected_checksum)):
        return Base58AddressError.invalidChecksum
    return {
        "payload": content[1:],
        "version": content[0],
    }

def decode_base58_address(address, sha256_function=sha256):
    decoded = decode_base58_address_format(address, sha256_function)
    if isinstance(decoded, str):
        return decoded
    if decoded["version"] not in [
        Base58AddressFormatVersion.p2pkh.value,
        Base58AddressFormatVersion.p2sh20.value,
        Base58AddressFormatVersion.p2pkhTestnet.value,
        Base58AddressFormatVersion.p2sh20Testnet.value,
        Base58AddressFormatVersion.p2pkhCopayBCH.value,
        Base58AddressFormatVersion.p2sh20CopayBCH.value,
    ]:
        return Base58AddressError.unknownAddressVersion
    hash160_length = 20
    if len(decoded["payload"]) != hash160_length:
        return Base58AddressError.incorrectLength
    return decoded


__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' 

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:' 


def base_encode(v, base):
    """ encode v, which is a string of bytes, to base58."""
    assert_bytes(v)
    assert base in (58, 43)
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    power_of_base = 1
    for c in v[::-1]:
        # naive but slow variant:   long_value += (256**i) * c
        long_value += power_of_base * c
        power_of_base <<= 8
    result = bytearray()
    while long_value >= base:
        div, mod = divmod(long_value, base)
        result.append(chars[mod])
        long_value = div
    result.append(chars[long_value])
    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == 0x00:
            nPad += 1
        else:
            break
    result.extend([chars[0]] * nPad)
    result.reverse()
    return result.decode('ascii')


def base_decode(v, length, base):
    """ decode v into a string of len bytes. May raise ValueError on bad chars
    in string."""
    # assert_bytes(v)
    v = to_bytes(v, 'ascii')
    assert base in (58, 43)
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    power_of_base = 1
    for c in v[::-1]:
        digit = chars.find(bytes((c,)))
        if digit < 0:
            raise ValueError("Forbidden character '{}' for base {}".format(chr(c), base))
        # naive but slow variant:   long_value += digit * (base**i)
        long_value += digit * power_of_base
        power_of_base *= base
    result = bytearray()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result.append(mod)
        long_value = div
    result.append(long_value)
    nPad = 0
    for c in v:
        if c == chars[0]:
            nPad += 1
        else:
            break
    result.extend(b'\x00' * nPad)
    if length is not None and len(result) != length:
        return None
    result.reverse()
    return bytes(result)


def assert_bytes(*args):
    """
    porting helper, assert args type
    """
    try:
        for x in args:
            assert isinstance(x, (bytes, bytearray))
    except: 
        raise

def to_bytes(something, encoding='utf8'):
    """
    cast string to bytes() like object, but for python2 support it's bytearray copy
    """
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")


def flatten_bin_array(array):
    """
    Flattens an array of byte sequences into a single byte sequence.
    """
    # Calculate total length of all byte sequences
    total_length = sum(len(bin) for bin in array)
    # Create a bytearray with the total length
    flattened = bytearray(total_length)
    # Copy each byte sequence into the flattened array
    index = 0
    for bin in array:
        flattened[index:index + len(bin)] = bin
        index += len(bin)
    return bytes(flattened)



