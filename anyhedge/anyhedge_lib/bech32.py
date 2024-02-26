
import re
from typing import Union, List

# The list of 32 symbols used in Bech32 encoding.
bech32_character_set = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

# An object mapping each of the 32 symbols used in Bech32 encoding to their respective index in the character set.
bech32_character_set_index = {char: index for index, char in enumerate(bech32_character_set)}

class BitRegroupingError(Exception):
    integer_out_of_range = "An integer provided in the source array is out of the range of the specified source word length."
    has_disallowed_padding = "Encountered padding when padding was disallowed."
    requires_disallowed_padding = "Encoding requires padding while padding is disallowed."

def regroup_bits(bin: List[int], source_word_length: int, result_word_length: int, allow_padding: bool = True) -> Union[List[int], str]:
    accumulator = 0
    bits = 0
    result = []
    max_result_int = (1 << result_word_length) - 1
    for value in bin:
        if value < 0 or value >> source_word_length != 0:
            return BitRegroupingError.integer_out_of_range
        accumulator = (accumulator << source_word_length) | value
        bits += source_word_length
        while bits >= result_word_length:
            bits -= result_word_length
            result.append((accumulator >> bits) & max_result_int)
    if allow_padding:
        if bits > 0:
            result.append((accumulator << (result_word_length - bits)) & max_result_int)
    else:
        if bits >= source_word_length or ((accumulator << (result_word_length - bits)) & max_result_int) > 0:
            return BitRegroupingError.has_disallowed_padding if bits >= source_word_length else BitRegroupingError.requires_disallowed_padding
    return result

def encode_bech32(base32_integer_array: List[int]) -> str:
    return ''.join([bech32_character_set[i] for i in base32_integer_array])

def decode_bech32(valid_bech32: str) -> List[int]:
    return [bech32_character_set_index[char] for char in valid_bech32]

non_bech32_characters = re.compile('[^{}]'.format(bech32_character_set))

def is_bech32_character_set(maybe_bech32: str) -> bool:
    return not non_bech32_characters.search(maybe_bech32)

class Bech32DecodingError(Exception):
    not_bech32_character_set = "Bech32 decoding error: input contains characters outside of the Bech32 character set."

def bech32_padded_to_bin(bech32_padded: str) -> Union[bytes, str]:
    if not is_bech32_character_set(bech32_padded):
        return Bech32DecodingError.not_bech32_character_set
    result = regroup_bits(decode_bech32(bech32_padded), base32_word_length=5, result_word_length=8, allow_padding=False)
    return bytes(result) if isinstance(result, list) else result

def bin_to_bech32_padded(bytes_: bytes) -> str:
    return encode_bech32(regroup_bits(list(bytes_), source_word_length=8, result_word_length=5))

