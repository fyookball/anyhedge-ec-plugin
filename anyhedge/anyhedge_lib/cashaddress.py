import bech32
from enum import Enum 
from bch_opcodes import OpcodesBCH

def mask_cash_address_prefix(prefix: str) -> list:
    result = [ord(char) & 31 for char in prefix]
    return result

def cash_address_polynomial_modulo(v):
    bech32_generator_most_significant_byte = [0x98, 0x79, 0xf3, 0xae, 0x1e]
    bech32_generator_remaining_bytes = [0xf2bc8e61, 0xb76d99e2, 0x3e5fb3c4, 0x2eabe2a8, 0x4f43e470]

    most_significant_byte = 0
    lower_bytes = 1
    c = 0
    for j in range(len(v)):
        c = most_significant_byte >> 3
        most_significant_byte &= 0x07
        most_significant_byte <<= 5
        most_significant_byte |= lower_bytes >> 27
        lower_bytes &= 0x07ffffff
        lower_bytes <<= 5
        lower_bytes ^= v[j]
        for i in range(len(bech32_generator_most_significant_byte)):
            if c & (1 << i):
                most_significant_byte ^= bech32_generator_most_significant_byte[i]
                lower_bytes ^= bech32_generator_remaining_bytes[i]
    lower_bytes ^= 1
    if lower_bytes < 0:
        lower_bytes ^= 1 << 31
        lower_bytes += (1 << 30) * 2
    return most_significant_byte * (1 << 30) * 4 + lower_bytes


def decode_cash_address_format(address: str):
    parts = address.lower().split(':')
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return 0, 0, 0  # Invalid format

    prefix, payload = parts
    if not bech32.is_bech32_character_set(payload):
        return 0, 0, 0  # Invalid characters

    decoded_payload = bech32.decode_bech32(payload)
    polynomial = mask_cash_address_prefix(prefix) + [0] + decoded_payload
    if cash_address_polynomial_modulo(polynomial) != 0:
        return 0, 0, 0  # Invalid checksum

    checksum40_bit_placeholder_length = 8
    payload_contents = bech32.regroup_bits(
        allow_padding=False,
        bin=decoded_payload[:-checksum40_bit_placeholder_length],
        result_word_length=8,  # Base256 word length
        source_word_length=5   # Base32 word length
    )

    if isinstance(payload_contents, str):
        return 0, 0, 0  # Improper padding

    version = payload_contents[0]
    contents = payload_contents[1:]
    result = bytearray(contents)
    return result, prefix, version

def cash_address_to_locking_byte_code(address: str):
    
    """We take some assumptions and liberties here, skip over some of the abstract function in the js 
    implementation such as nonstandard address and tokens, and go right to calling decode_cash_address_format
    """
    payload,prefix,typeBits = decode_cash_address_format(address)
    
  
    # Assume P2PKH
    bytecode = address_contents_to_locking_bytecode(payload, LockingBytecodeType.p2pkh) 
    return bytecode, prefix, typeBits

def encode_locking_bytecode_p2pkh(public_key_hash):
    return bytes([
        118,  # OP_DUP
        169,  # OP_HASH160
        20,   # Length of the public key hash (OP_PUSHBYTES_20)
        *public_key_hash,  # Unpack the public key hash bytes
        136,  # OP_EQUALVERIFY
        172   # OP_CHECKSIG
    ])


def encode_locking_bytecode_p2sh20(p2sh20_hash):
    return bytes([
        169,  # OP_HASH160
        20,   # Length of the P2SH hash (OP_PUSHBYTES_20)
        *p2sh20_hash,  # Unpack the P2SH hash bytes
        135   # OP_EQUAL
    ])

def encode_locking_bytecode_p2sh32(p2sh32_hash):
    return bytes([
        170,  # OP_HASH256
        32,   # Length of the P2SH32 hash (OP_PUSHBYTES_32)
        *p2sh32_hash,  # Unpack the P2SH32 hash bytes
        135   # OP_EQUAL
    ])

def encode_locking_bytecode_p2pk(public_key):
    if len(public_key) == 33:  # Compressed public key
        return bytes([
            33,  # OP_PUSHBYTES_33
            *public_key,  # Unpack the public key bytes
            172  # OP_CHECKSIG
        ])
    else:  # Uncompressed public key
        return bytes([
            65,  # OP_PUSHBYTES_65
            *public_key,  # Unpack the public key bytes
            172  # OP_CHECKSIG
        ])
        
def cash_address_checksum_to_uint5_array(checksum):
    base256WordLength = 8
    result = []
    for _ in range(base256WordLength):
        result.append(checksum & 31)  # & 31 to get the last 5 bits
        checksum //= 32  # Use floor division for correct behavior
    result.reverse()
    return result


class LockingBytecodeType(Enum):
    p2pkh = "p2pkh"
    p2sh20 = "p2sh20"
    p2sh32 = "p2sh32"
    p2pk = "p2pk"

def unknown_value(type, message):
    raise ValueError(message)
    
def address_contents_to_locking_bytecode(payload, type):
    if type == LockingBytecodeType.p2pkh:
        return encode_locking_bytecode_p2pkh(payload)
    elif type == LockingBytecodeType.p2sh20:
        return encode_locking_bytecode_p2sh20(payload)
    elif type == LockingBytecodeType.p2sh32:
        return encode_locking_bytecode_p2sh32(payload)
    elif type == LockingBytecodeType.p2pk:
        return encode_locking_bytecode_p2pk(payload)
    else:
        return unknown_value(type, f"Unrecognized addressContents type: {type}")

def encode_cash_address_format(prefix: str, version: int, hash: bytes) -> str:
    # Define constants inside the function
    base32WordLength = 5
    base256WordLength = 8
    payloadSeparator = 0
    checksum40BitPlaceholder = [0] * 8  #  40-bit checksum placeholder of 8 bytes of zeros. 
 
    payload_contents = bech32.regroup_bits(bin=[version] + list(hash), source_word_length=8, result_word_length=base32WordLength, allow_padding=True)
    checksum_contents = mask_cash_address_prefix(prefix) + [payloadSeparator] + payload_contents + checksum40BitPlaceholder
    checksum = cash_address_polynomial_modulo(checksum_contents)
    payload = payload_contents + cash_address_checksum_to_uint5_array(checksum)
    
    # Construct the cash address by encoding the payload with Bech32 and prefixing it with the given prefix
    return f"{prefix}:{bech32.encode_bech32(payload)}"
     
def encode_cash_address_version_byte(type: int, bit_length: int) -> int:
    cashAddressTypeBitShift = 3
    cashAddressSizeToBit = {
        160: 0,
        192: 1,
        224: 2,
        256: 3,
        320: 4,
        384: 5,
        448: 6,
        512: 7,
        }
    if bit_length not in cashAddressSizeToBit:
        raise ValueError("Unsupported bit length")
    return (type << cashAddressTypeBitShift) | cashAddressSizeToBit[bit_length]

def is_valid_bit_length(bit_length: int) -> bool:
    cash_address_size_to_bit = {
        160: 0,
        192: 1,
        224: 2,
        256: 3,
        320: 4,
        384: 5,
        448: 6,
        512: 7,
    }
    return bit_length in cash_address_size_to_bit

def encode_cash_address(prefix: str, type: int, hash: bytes) -> str:
    bit_length = len(hash) * 8  #hash is a bytes object, and each byte is 8 bits
    if not is_valid_bit_length(bit_length): 
        raise ValueError("Unsupported hash length for cash address encoding")
    
    version_byte = encode_cash_address_version_byte(type, bit_length)
    return encode_cash_address_format(prefix, version_byte, hash)


def locking_bytecode_to_cash_address(bytecode, prefix):
         
    ADDRESS_TYPE_P2PKH = 0   
    ADDRESS_TYPE_P2SH = 1   
 
    contents = locking_bytecode_to_address_contents(bytecode) 
    if contents['type'] == "P2PKH" or contents['type'] == "p2pkh":
        return encode_cash_address(prefix, ADDRESS_TYPE_P2PKH, contents['payload'])
    if contents['type'] == "P2SH" or contents['type'] == "p2sh":
        return encode_cash_address(prefix, ADDRESS_TYPE_P2SH , contents['payload'])
    raise ValueError("Unsupported address type")



def locking_bytecode_to_address_contents(bytecode):
    # Define lengths and types
    p2pkh_length = 25
    p2sh_length = 23
    p2pk_uncompressed_length = 67
    p2pk_compressed_length = 35

    # P2PKH format
    if (len(bytecode) == p2pkh_length and
            bytecode[0] == OpcodesBCH["OP_DUP"] and
            bytecode[1] == OpcodesBCH["OP_HASH160"] and
            bytecode[2] == OpcodesBCH["OP_PUSHBYTES_20"] and
            bytecode[23] == OpcodesBCH["OP_EQUALVERIFY"] and
            bytecode[24] == OpcodesBCH["OP_CHECKSIG"]):
        start, end = 3, 23
        return {'payload': bytecode[start:end], 'type': 'p2pkh'}

    # P2SH format
    if (len(bytecode) == p2sh_length and
            bytecode[0] == OpcodesBCH["OP_HASH160"] and
            bytecode[1] == OpcodesBCH["OP_PUSHBYTES_20"] and
            bytecode[22] == OpcodesBCH["OP_EQUAL"]):
        start, end = 2, 22
        return {'payload': bytecode[start:end], 'type': 'p2sh'}

    # P2PK uncompressed format
    if (len(bytecode) == p2pk_uncompressed_length and
            bytecode[0] == OpcodesBCH["OP_PUSHBYTES_65"] and
            bytecode[66] == OpcodesBCH["OP_CHECKSIG"]):
        start, end = 1, 66
        return {'payload': bytecode[start:end], 'type': 'p2pk'}

    # P2PK compressed format
    if (len(bytecode) == p2pk_compressed_length and
            bytecode[0] == OpcodesBCH["OP_PUSHBYTES_33"] and
            bytecode[34] == OpcodesBCH["OP_CHECKSIG"]):
        start, end = 1, 34
        return {'payload': bytecode[start:end], 'type': 'p2pk'}

    # If none of the above...
    raise ValueError("bad number of bytes in the locking byte code.")
    return None


