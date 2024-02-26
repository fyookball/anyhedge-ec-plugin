from typing import List, Any
import struct 
from bch_opcodes import OpcodesBCH
import hashlib
import cashaddress

"""
Most of this file is internal functions that were translated into python from
the Cashscript, Bitauth, or Anyhedge libraries.

"""

def hex_to_bin(valid_hex: str) -> bytes:
    """
    expecting raw hex (no 0x prefix)
    """
    return bytes.fromhex(valid_hex)
 
OP_PUSHDATA1 = 0x4c  # 76 in decimal
OP_PUSHDATA2 = 0x4d  # 77 in decimal
OP_PUSHDATA4 = 0x4e  # 78 in decimal

uint8Bytes = 1
uint16Bytes = 2
uint32Bytes = 4
 
def length_bytes_for_push_opcode(opcode):
    if opcode < OP_PUSHDATA1:
        return 0
    elif opcode == OP_PUSHDATA1:
        return uint8Bytes
    elif opcode == OP_PUSHDATA2:
        return uint16Bytes
    elif opcode == OP_PUSHDATA4:
        return uint32Bytes
    else:
        raise ValueError("Invalid opcode for push operation")

def read_little_endian_number(script, index, length):
    if length not in [1, 2, 4]:
        raise ValueError("Invalid length for little endian number")

    # Extract the slice of bytes from the script
    slice_of_bytes = script[index:index + length]

    # Convert the extracted bytes to an integer using little-endian format
    return int.from_bytes(slice_of_bytes, byteorder='little')
 
def number_to_bin_uint16_le(value):
    # Convert the integer to a bytes object of length 2 in little-endian format
    return value.to_bytes(2, byteorder='little')

def number_to_bin_int32_le(value):
    # Convert the integer to a bytes object of length 4 in little-endian format
    # The method automatically handles both positive and negative values for signed integers
    return value.to_bytes(4, byteorder='little', signed=True)

 
def encode_to_bytes(value, value_type):
    if value_type in ["pubkey", "bytes"]:
        if isinstance(value, bytes):
            # Value is already bytes, return it directly
            return value
        else:
            return bytes.fromhex(value)
    elif value_type == "int":
        # Encode as little-endian
        return value.to_bytes((value.bit_length() + 7) // 8, byteorder='little', signed=True)
    else:
        raise ValueError(f"Unknown type: {value_type}")

def encode_constructor_args(contract_params, artifact_dict):
    encoded_args = []
    constructor_inputs = artifact_dict["constructorInputs"]

    for input in reversed(constructor_inputs):
        input_name = input["name"]
        input_type = input["type"]
        input_value = getattr(contract_params, input_name) 
        encoded_args.append(encode_to_bytes(input_value, input_type))
    return encoded_args


def encode_data_push(data): 
    if isinstance(data, list):
        data = bytes(data)
        
    # First, check if data is a string and needs conversion
    if isinstance(data, str):
        # Use the OpcodesBCH dictionary to convert the string to its opcode
        if data in OpcodesBCH:
            # Convert the opcode to a single byte
            data = bytes([OpcodesBCH[data]])
        else:
            # Handle the case where the string is not a recognized opcode
            raise ValueError(f"Opcode '{data}' not found in OpcodesBCH")
    # Now data is guaranteed to be bytes; proceed with the original logic

    maximum_push_byte_operation_size = 75
    push_number_opcodes = 16
    negative_one = 129
    OP_1NEGATE = 79
    maximum_push_data1_size = 255
    maximum_push_data2_size = 65535
    push_number_opcodes_offset = 80
    
    if len(data) <= maximum_push_byte_operation_size:
        if len(data) == 0:
            return bytes([0])
        elif len(data) == 1:
            if 0 < data[0] <= push_number_opcodes:
                return bytes([data[0] + push_number_opcodes_offset])  
            elif data[0] == negative_one:
                return bytes([OP_1NEGATE])
            else:
                return bytes([1]) + data
        else:
            return bytes([len(data)]) + data
    elif len(data) <= maximum_push_data1_size:
        return bytes([OP_PUSHDATA1, len(data)]) + data
    elif len(data) <= maximum_push_data2_size:
        return bytes([OP_PUSHDATA2]) + len(data).to_bytes(2, byteorder='little') + data
    else:
        return bytes([OP_PUSHDATA4]) + len(data).to_bytes(4, byteorder='little') + data


def length_bytes_for_push_opcode(opcode):
    if opcode < OP_PUSHDATA1:
        return 0
    elif opcode == OP_PUSHDATA1:
        return 1  # uint8Bytes, representing length in bytes for OP_PUSHDATA_1
    elif opcode == OP_PUSHDATA2:
        return 2  # uint16Bytes, representing length in bytes for OP_PUSHDATA_2
    else:   
        return 4  # uint32Bytes, representing length in bytes for OP_PUSHDATA_4



def get_instruction_length_bytes(instruction):
    opcode = instruction['opcode']
    expected_length = length_bytes_for_push_opcode(opcode)
    
    if expected_length == 1: 
        return bytes([len(instruction['data'])])
    elif expected_length == 2:
        return number_to_bin_uint16_le(len(instruction['data']))
    elif expected_length == 4:
        return number_to_bin_uint32_le(len(instruction['data']))
    else: 
        return bytes()  # Return an empty bytes object if nothing found

def is_push_data(push_opcode):
    return push_opcode >= OP_PUSHDATA1
    

def serialize_authentication_instruction(instruction):
    serialized = bytearray([instruction['opcode']])
    
    if 'data' in instruction:
        if is_push_data(instruction['opcode']):
            serialized.extend(get_instruction_length_bytes(instruction))
        serialized.extend(instruction['data'])
    
    return serialized



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
    
def serialize_authentication_instructions(instructions):
    # Map serialize_authentication_instruction over all instructions and flatten the result
    serialized_instructions = [serialize_authentication_instruction(instruction) for instruction in instructions]
    return flatten_bin_array(serialized_instructions)
    
introspection_op_mapping = {
    "OP_INPUTINDEX": "OP_UNKNOWN192",
    "OP_ACTIVEBYTECODE": "OP_UNKNOWN193",
    "OP_TXVERSION": "OP_UNKNOWN194",
    "OP_TXINPUTCOUNT": "OP_UNKNOWN195",
    "OP_TXOUTPUTCOUNT": "OP_UNKNOWN196",
    "OP_TXLOCKTIME": "OP_UNKNOWN197",
    "OP_UTXOVALUE": "OP_UNKNOWN198",
    "OP_UTXOBYTECODE": "OP_UNKNOWN199",
    "OP_OUTPOINTTXHASH": "OP_UNKNOWN200",
    "OP_OUTPOINTINDEX": "OP_UNKNOWN201",
    "OP_INPUTBYTECODE": "OP_UNKNOWN202",
    "OP_INPUTSEQUENCENUMBER": "OP_UNKNOWN203",
    "OP_OUTPUTVALUE": "OP_UNKNOWN204",
    "OP_OUTPUTBYTECODE": "OP_UNKNOWN205",
}



def read_authentication_instruction(script, index):
    
    opcode = script[index]
    if opcode > OP_PUSHDATA4:   
        return {'instruction': {'opcode': opcode}, 'nextIndex': index + 1}

    length_bytes = length_bytes_for_push_opcode(opcode) 

    if length_bytes != 0 and index + length_bytes >= len(script):
        slice_start = index + 1
        slice_end = slice_start + length_bytes
        return {
            'instruction': {
                'expectedLengthBytes': length_bytes,
                'length': script[slice_start:slice_end],
                'malformed': True,
                'opcode': opcode
            },
            'nextIndex': slice_end
        }

    data_bytes = opcode if length_bytes == 0 else read_little_endian_number(script, index + 1, length_bytes)
    
    data_start = index + 1 + length_bytes
    data_end = data_start + data_bytes
    instruction_data = {
        'data': script[data_start:data_end],
        'opcode': opcode
    }
    if data_end > len(script):
        instruction_data.update({
            'expectedDataBytes': data_end - data_start,
            'malformed': True
        })
         
    return {'instruction': instruction_data, 'nextIndex': data_end}


def parse_bytecode(script):
    instructions = []
    i = 0
    
    while i < len(script):
        result = read_authentication_instruction(script, i)
        instruction = result['instruction']
        next_index = result['nextIndex']
        i = next_index
        instructions.append(instruction)
    return instructions


def asm_to_bytecode(asm): 
    asm = ' '.join(asm.split())
 
    asm_tokens = asm.split(' ')
    asm_tokens = [introspection_op_mapping.get(token, token) for token in asm_tokens]

    # Convert ASM tokens to authentication instructions
    instructions = []
    for token in asm_tokens:
        if token.startswith('OP_'):
            opcode = OpcodesBCH.get(token)
            if opcode is not None:
                instructions.append({'opcode': opcode})
            else:
                raise ValueError(f"Opcode {token} not found in OpcodesBCH")
        else: 
            hexed_token = hex_to_bin(token)
            data_push = encode_data_push(hex_to_bin(token))
            instruction = parse_bytecode(data_push)[0]   
            instructions.append(instruction)
 
    bytecode = serialize_authentication_instructions(instructions)
    return bytecode

 
def bytecode_to_script(bytecode):
    instructions = parse_bytecode(bytecode)
     
    script = []
    for index, instruction in enumerate(instructions):
        # Check if 'data' is present and not empty
        if 'data' in instruction and instruction['data']:
            # Convert non-empty binary data to a list of integers, similar to Uint8Array representation
            data_list = list(instruction['data'])
            script.append(data_list)
        elif 'data' in instruction:  # Handle empty binary data
            script.append(b'')
        else:  # Handle opcode
            script.append(instruction['opcode'])
    return script



def asm_to_script(asm): 
    bytecode = asm_to_bytecode(asm)
    script = bytecode_to_script(bytecode)
    return script

def parse_bytes_as_script_number(bytes, maximum_script_number_byte_length, require_minimal_encoding=True):
    if not bytes:
        return 0

    if len(bytes) > maximum_script_number_byte_length:
        raise ValueError("Script number byte length is out of range")

    most_significant_byte = bytes[-1]
    second_most_significant_byte = bytes[-2] if len(bytes) > 1 else 0

    all_but_the_sign_bit = 127
    just_the_sign_bit = 128

    if require_minimal_encoding and \
       (most_significant_byte & all_but_the_sign_bit == 0) and \
       (len(bytes) <= 1 or (second_most_significant_byte & just_the_sign_bit == 0)):
        raise ValueError("Script number encoding does not meet the minimal encoding requirement")

    bits_per_byte = 8
    sign_flipping_byte = 0x80
    result = 0

    for byte in range(len(bytes)):
        result |= bytes[byte] << (byte * bits_per_byte)

    is_negative = (bytes[-1] & sign_flipping_byte) != 0

    if is_negative:
        mask = ~(sign_flipping_byte << ((len(bytes) - 1) * bits_per_byte))
        result = -(result & mask)
    
    return result

def big_int_to_script_number(integer):
    if integer == 0:
        return bytearray()

    bytes_list = []
    is_negative = integer < 0
    byte_states = 0xff
    bits_per_byte = 8

    remaining = -integer if is_negative else integer

    while remaining > 0:
        bytes_list.append(int(remaining & byte_states))
        remaining >>= bits_per_byte

    sign_flipping_byte = 0x80

    if bytes_list[-1] & sign_flipping_byte:
        bytes_list.append(sign_flipping_byte if is_negative else 0x00)
    elif is_negative:
        bytes_list[-1] |= sign_flipping_byte

    # Return a bytearray because it's mutable similar to how Uint8Array would be in JavaScript
    # If an immutable type is preferred, you can return bytes(bytes_list) instead
    return
    
def encode_int(integer):
    # Directly pass the integer to the big_int_to_script_number function
    return big_int_to_script_number(integer)

def decode_int(encoded_int, max_length=8):
    try: 
        result = parse_bytes_as_script_number(encoded_int, {'maximum_script_number_byte_length': max_length, 'require_minimal_encoding': True})
        return result
    except ValueError as e: 
        raise ValueError(f"Error decoding script number: {e}") from e


def script_to_bytecode(script):
    instructions = []
    for op_or_data in script:
        if isinstance(op_or_data, int):
            instructions.append({'opcode': op_or_data})
        else:
            encoded_data = encode_data_push(op_or_data)
            instruction = parse_bytecode(encoded_data)[0]
            instructions.append(instruction) 
    return serialize_authentication_instructions(instructions)

def calculate_bytesize(script):
    bytecode = script_to_bytecode(script)
    return len(bytecode)

def reverse_introspection_op_mapping(introspection_op_mapping):
    return {v: k for k, v in introspection_op_mapping.items()}
 
def is_multi_word_push(opcode):
    OP_0 = 0
    return opcode != OP_0

def format_asm_push_hex(data):
    if len(data) > 0: 
        return f"0x{data.hex()}"
    return ''

def format_missing_bytes_asm(missing):
    plural = '' if missing == 1 else 's'
    return f"[missing {missing} byte{plural}]"

def has_malformed_length(instruction):
    return 'length' in instruction
      
def disassemble_authentication_instruction(instruction):
    instruction_str = f"{OpcodesBCH[instruction['opcode']]}"
    if 'data' in instruction and is_multi_word_push(instruction['opcode']):
        data_str = format_asm_push_hex(instruction['data']) if is_push_data(instruction['opcode']) else ''
        instruction_str += f" {len(instruction['data'])} {data_str}" if is_push_data(instruction['opcode']) else f" {data_str}"
    return instruction_str
      
def disassemble_parsed_authentication_instruction(instruction):
    if authentication_instruction_is_malformed(instruction):
        ##### THIS IS SIMPLIFIED FROM THE JS VERSION. IN THE JS VERSION, WE CALL disassembleParsedAuthenticationInstructionMalformed.
        ##### WE WILL ASSUME ITS JUST NOT MALFORMED AND THROW AN ERROR IF IT IS. CAN BE IMPLEMENTED LATER.
        raise ValueError("Malformed instruction encountered.")
    else:
        return disassemble_authentication_instruction(instruction)
 
def disassemble_bytecode_bch(bytecode): 
    parsed_instructions = parse_bytecode(bytecode) 
    return disassemble_parsed_authentication_instructions(OpcodesBCH, parsed_instructions)
 

def bytecode_to_asm(bytecode):
    # Convert the bytecode to ASM format using a Python equivalent of libauth's disassembleBytecodeBCH
    asm = disassemble_bytecode_bch(bytecode)
    # Convert libauth's ASM format to another format (similar to what was mentioned for BITBOX)
    asm = re.sub(r'OP_PUSHBYTES_[^\s]+', '', asm)
    asm = re.sub(r'OP_PUSHDATA[^\s]+ [^\s]+', '', asm)
    asm = re.sub(r'(^|\s)0x', ' ', asm)
    # Replace OP_UNKNOWN... with the correct ops using reverse introspection operation mapping
    asm_tokens = asm.split(' ')
    asm = ' '.join([reverse_introspection_op_mapping.get(token, token) for token in asm_tokens])
    # Remove any duplicate whitespace
    asm = re.sub(r'\s+', ' ', asm).strip()
    return asm


def find_index(lst, test_func):
    """
    generic index finder.  finds index of the first item in a list that satisfies the test function.
    Returns the index of the first item satisfying test_func, or -1 if no item satisfies test_func.
    
    Parameters:
    - lst: List to search.
    - test_func: Function that takes an item and returns True if it satisfies the condition, False otherwise.
    """
    for i, item in enumerate(lst):
        if test_func(item):
            return i
    return -1

def find_opcode_index(script, opcode):
    # checks if an item equals the opcode
    test_func = lambda op: op == opcode
    index = find_index(script, test_func)
    return index


def remove_opcode_at_index(script, index):
    # Remove the opcode at the specified index
    if index >= 0 and index < len(script):
        del script[index]

def replace_bytecode_nop(script, OpcodesBCH):
    index = find_opcode_index(script, OpcodesBCH["OP_NOP"])
    if index < 0: 
        return script
    
    remove_opcode_at_index(script, index)
    
    old_cut = script[index]
    if isinstance(old_cut, bytes):
        old_cut = decode_int(old_cut)   
    elif old_cut == OpcodesBCH["OP_0"]:
        old_cut = 0
    elif OpcodesBCH["OP_1"] <= old_cut <= OpcodesBCH["OP_16"]:
        old_cut -= 80
    else:
        return script
    
    script[index] = encode_int(old_cut + 1)  
    bytecode_size = calculate_bytesize(script)  
    
    if bytecode_size > 252:
        script[index] = encode_int(old_cut + 3)
    return asm_to_script(script_to_asm(script))

def generate_redeem_script(base_script, encoded_args):
    combined_script = encoded_args + base_script
    retval  = replace_bytecode_nop(combined_script, OpcodesBCH)
    return retval

def address_contents_to_locking_bytecode(address_contents):
    if address_contents['type'] == 'p2pkh':
        return bytes([
            OpcodesBCH["OP_DUP"],
            OpcodesBCH["OP_HASH160"],
            OpcodesBCH["OP_PUSHBYTES_20"],
            *address_contents['payload'],
            OpcodesBCH["OP_EQUALVERIFY"],
            OpcodesBCH["OP_CHECKSIG"],
        ])
    if address_contents['type'] == 'P2SH' or address_contents['type'] == 'p2sh':
        return bytes([
            OpcodesBCH["OP_HASH160"],
            OpcodesBCH["OP_PUSHBYTES_20"],
            *address_contents['payload'],
            OpcodesBCH["OP_EQUAL"],
        ])
    if address_contents['type'] == 'p2pk':
        compressed_public_key_length = 33
        if len(address_contents['payload']) == compressed_public_key_length:
            return bytes([
                OpcodesBCH["OP_PUSHBYTES_33"],
                *address_contents['payload'],
                OpcodesBCH["OP_CHECKSIG"],
            ])
        else:
            return bytes([
                OpcodesBCH["OP_PUSHBYTES_65"],
                *address_contents['payload'],
                OpcodesBCH["OP_CHECKSIG"],
            ]) 
    return bytes(address_contents['payload'])

def hash160(data):
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    return ripemd160_hash

def script_to_locking_bytecode(script): 
    script_hash = hash160(script_to_bytecode(script))
    address_contents = {"payload": script_hash, "type": "P2SH"} 
    locking_bytecode = address_contents_to_locking_bytecode(address_contents)
    return locking_bytecode

def calculate_bytesize(script):
    bytecode = script_to_bytecode(script)
    return len(bytecode)


def count_opcodes(script): 
    OP_16_value = OpcodesBCH["OP_16"]
    filtered_opcodes = [op for op in script if isinstance(op, int) and op > OP_16_value]
    return len(filtered_opcodes)

def script_to_address(script): 
    locking_bytecode = script_to_locking_bytecode(script)
    prefix = "bitcoincash"
    address = cashaddress.locking_bytecode_to_cash_address(locking_bytecode, prefix)
    return address

class Contract:
    def __init__(self, artifact: dict, constructor_args, provider=None): 
    
        expected_properties = ['abi', 'bytecode', 'constructorInputs', 'contractName']
        missing_properties = [prop for prop in expected_properties if prop not in artifact]
        
        if missing_properties:
            raise ValueError(f'Invalid or incomplete artifact provided, missing properties: {missing_properties}')
        
        # Validate the number of constructor arguments
        if len(artifact['constructorInputs']) != len(vars(constructor_args)):
            raise ValueError(f"Incorrect number of arguments passed to {artifact['contractName']} constructor")
        encoded_args = encode_constructor_args(constructor_args, artifact)
         
        redeem_script = generate_redeem_script(asm_to_script(artifact['bytecode']), encoded_args)
        self.redeem_script=redeem_script
        self.artifact = artifact
        self.provider = provider   
        self.redeem_script = redeem_script
        self.functions = self.populate_functions(artifact['abi'])
        self.name = artifact.get('contractName', 'DefaultName') 
        self.address = script_to_address(self.redeem_script)  
        self.bytesize = len(self.redeem_script)
        self.opcount = count_opcodes(self.redeem_script)  
 
    def get_balance(self):
        # Placeholder for balance retrieval
        pass

    def get_utxos(self):
        # Placeholder for UTXO retrieval
        pass

    def get_redeem_script_hex(self):
        # Placeholder for redeem script hex conversion
        pass

    # populate_functions and create_function are pythonic ways to deal with dynamically creating functions as is done 
    # in the JS code in the contructor for the Contract class in Contract.js
    def populate_functions(self, abi):
        functions = {}
        for abi_function in abi: 
            functions[abi_function['name']] = self.create_function(abi_function, selector=None)
        return functions
        
    def create_function(self, abi_function, selector=None):
        def contract_function(*args):
            if len(abi_function['inputs']) != len(args):
                raise ValueError(f"Incorrect number of arguments passed to function {abi_function['name']}")
            
            # Encode passed args based on type
            encoded_args = [self.encode_to_bytes(arg, abi_function['inputs'][i]['type']) for i, arg in enumerate(args)]
             
            return {
                'function_name': abi_function['name'],
                'encoded_args': encoded_args,
                'selector': selector,
                'address': self.address,
                'redeem_script': self.redeem_script
            }
        
        return contract_function
 

