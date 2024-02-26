"""
   
"""

from oracle import OracleRequester
from gp_service import GPservice
from decimal import Decimal
import bech32
import cashaddress
import contract 
import pkg_resources
import json
from artifact import artifact_dict

class AnyHedgeManager:
    def __init__(self):
        # default constructor 
        pass
  
    def parse_data_message(self, message: bytes):
       
        # Parse a data message into individual parts.  Return all zeros if bad.
        messageTimestamp, messageSequence, dataSequenceOrType, dataContent= self.parse_oracle_message(message)
        if not self.validate_data_sequence(dataSequenceOrType):
            return 0, 0, 0, 0
        dataSequence = dataSequenceOrType    
        return messageTimestamp, messageSequence, dataSequence, dataContent
        
    def get_price_value(self, data_content_bin: bytes) -> int:
        # Simplified conversion from binary to int
        return int.from_bytes(data_content_bin, 'little', signed=True)

    def verify_message_structure(self,message: bytes, expected_length: int = 0):
        # Structure verification
        if not isinstance(message, bytes) or len(message) < expected_length:
            return False
        return True

    def parse_oracle_message(self,message: bytes):
        # Returns 4 values: message_timestamp, message_sequence, data_sequence_or_type, data_content
        # If any errors occur, a default of 0,0,0,0 is returned and the calling routine is expected
        # to handle the error situation.
    
        # Verify message has a valid structure.
        if not self.verify_message_structure(message):
            return 0, 0, 0, 0

        # Read data from the message.
        message_timestamp = int.from_bytes(message[0:4], byteorder='little', signed=True)
        message_sequence = int.from_bytes(message[4:8], byteorder='little', signed=True)
        data_sequence_or_type = int.from_bytes(message[8:12], byteorder='little', signed=True)
        data_content = message[12:]

        # Validate that price message parts have valid formats.
        if not self.validate_message_timestamp(message_timestamp):
            return 0, 0, 0, 0
        if not self.validate_message_sequence(message_sequence):
            return 0, 0, 0, 0
        if not self.validate_data_sequence_or_type(data_sequence_or_type):
            return 0, 0, 0, 0
 
        return message_timestamp, message_sequence, data_sequence_or_type, data_content


    def parse_price_message(self,message: bytes) -> dict:
        # Expecting messages are bytes
        price_message_length = 16
        try:
            self.verify_message_structure(message, price_message_length)
        except:
            return 0,0,0,0
        messageTimestamp, messageSequence, dataSequence, dataContent = self.parse_data_message(message)   
        
        price_value = int.from_bytes(dataContent, byteorder='little') 
        is_price_valid = self.validate_message_price(price_value)
        return messageTimestamp, messageSequence, dataSequence, price_value
 
         
    def validate_message_sequence(self,message_sequence) -> bool:
        # Message sequences are 4 bytes long.
        byte_length = 4
        is_valid = self.validate_script_integer_boundaries(
            name='messageSequence',
            value=message_sequence,
            byte_length=byte_length
        )
        return is_valid
    
    def validate_data_sequence_or_type(self,data_sequence_or_type) -> bool:
        # Data sequence and metadata types are both 4 bytes long.
        byte_length = 4
        # Allow negative numbers 
        is_valid = self.validate_script_integer_boundaries(
            name='dataSequenceOrType',
            value=data_sequence_or_type,
            byte_length=byte_length,
            allow_negative=True  
        )
        return is_valid
    
        
    def validate_message_timestamp(self,message_timestamp) -> bool:
        # Message timestamps are 4 bytes long. NOTE: this restriction will cause problems in 2038, see https://en.wikipedia.org/wiki/Year_2038_problem
        byte_length = 4
        is_valid = self.validate_script_integer_boundaries(
            name='messageTimestamp',
            value=message_timestamp,
            byte_length=byte_length
        )
        return is_valid
        
    def validate_message_price(self,price_value) -> bool:
        # Message prices are 4 bytes long.
        byte_length = 4 
        is_valid = self.validate_script_integer_boundaries(
            name='priceValue',
            value=price_value,
            byte_length=byte_length
        )
        return is_valid
 
    def validate_data_sequence(self,data_sequence) -> bool:
        # Message prices are 4 bytes long.
        byte_length = 4 
        is_valid = self.validate_script_integer_boundaries(
            name='dataSequence',
            value=data_sequence,
            byte_length=byte_length
        )
        return is_valid
 
    def validate_script_integer_boundaries(self,name, value, byte_length, allow_negative=False, allow_positive=True, allow_zero=False) -> bool:
    
        # (name is not really used here, could be used to return specific error messages like in the js implementation)
        # Returns True if valid, False if invalid.
        # Check if the provided value is not an integer

        if not isinstance(value, int):
            return False
        # Calculate the largest possible script value given the byte_length
        available_bits = (byte_length * 8) - 1
        max_script_value = (2 ** available_bits) - 1
        # Check if the provided value is outside of the signed script data structure
        if value >= max_script_value:
            return False
        # Check if zero values are not allowed and the provided value is exactly zero
        if not allow_zero and value == 0:
            return False
        # Check if negative values are not allowed and the provided value is negative
        if not allow_negative and value < 0:
            return False
        # Check if positive values are not allowed and the provided value is positive
        if not allow_positive and value > 0:
           return False
        # If no conditions are violated, return True
        return True

    def addressToLockScript(self, address: str):
        payload,prefix,typeBits = cashaddress.cash_address_to_locking_byte_code(address)
        return payload.hex()
        
    def validate_low_liquidation_price(self,low_liquidation_price, start_price):
        MIN_LIQUIDATION_RELATIVE_PRICE_CHANGE:Final = 0.005;
        # Low liquidation price is a contract value and therefore must be an integer.
        # Any non-integer values indicate a problem in the contract preparation process.
        if not isinstance(low_liquidation_price, int):
           return False
        
        # Validate Maximum Constraints for lowLiquidationPrice
        # Low liquidation price must be less than the start price (floor is conservative) to avoid instant liquidation.
        if not (low_liquidation_price < start_price):
            return False
 
        # Low liquidation price must have enough space between it and the start price for contracts to avoid near-instant liquidation.
        low_liquidation_price_with_reasonable_gap_to_start_price = start_price * (1 - MIN_LIQUIDATION_RELATIVE_PRICE_CHANGE) 
        if not (low_liquidation_price <= low_liquidation_price_with_reasonable_gap_to_start_price):
            return False
 
        # Validate Minimum Constraints for lowLiquidationPrice
        # Low liquidation price must be at least 1 to avoid a divide-by-zero error leading to a potentially unredeemable contract.
        if not (low_liquidation_price >= 1):
            return False
 
        # If all checks passed, return True.
        return True

    def validate_high_liquidation_price(self,high_liquidation_price, start_price):
        MIN_LIQUIDATION_RELATIVE_PRICE_CHANGE:Final = 0.005;
        # High liquidation price is a contract value and therefore must be an integer.
        if not isinstance(high_liquidation_price, int):
            return False

        # Validate Minimum Constraints for highLiquidationPrice
        # High liquidation price must be greater than the start price to avoid instant liquidation.
        if not (high_liquidation_price > start_price):
            return False

        # High liquidation price must have enough space between it and the start price for contracts to avoid near-instant liquidation.
        minimum_high_liquidation_price = start_price * (1 + MIN_LIQUIDATION_RELATIVE_PRICE_CHANGE)
        if not (high_liquidation_price >= minimum_high_liquidation_price):
            return False
            
        # If all checks passed, return True.
        return True

    def validate_integer_division_precision(self,positive_integer_numerator, positive_integer_denominator,minIntegerDivisionPrecisionSteps):

        # When all arguments are positive integers...
        numerator_is_positive_integer = isinstance(positive_integer_numerator, int) and positive_integer_numerator >= 1
        denominator_is_positive_integer = isinstance(positive_integer_denominator, int) and positive_integer_denominator >= 1
        precision_is_positive_integer = isinstance(minIntegerDivisionPrecisionSteps, int) and minIntegerDivisionPrecisionSteps >= 1

        # Validate all input as positive integers
        if not (numerator_is_positive_integer and denominator_is_positive_integer and precision_is_positive_integer):
            return False

        # Calculate real valued division steps between numerator and denominator
        actual_division_steps = positive_integer_numerator / positive_integer_denominator

        # Confirm that there are at least as many steps as the minimum requirement
        if not (actual_division_steps >= minIntegerDivisionPrecisionSteps):
            return False
     
        return True

    def validate_nominal_units_x_sats_per_bch(self,nominal_units_x_sats_per_bch, high_liquidation_price, low_liquidation_price, payout_sats):

        JAVASCRIPT_FRIENDLY_SCRIPT_INT_MAX: Final  = 2 ** 53
        SATS_PER_BCH: Final = 100000000
        MIN_INTEGER_DIVISION_PRECISION_STEPS: Final = 500
        
        # The compound nominal value is a contract value and therefore must be an integer.
        if not isinstance(nominal_units_x_sats_per_bch, int):
            return False

        # Validate Maximum Constraints for nominalUnitsXSatsPerBch
        if not (nominal_units_x_sats_per_bch <= JAVASCRIPT_FRIENDLY_SCRIPT_INT_MAX):
            return False

        reverse_calculated_compound_value = payout_sats * low_liquidation_price
        if not (nominal_units_x_sats_per_bch <= reverse_calculated_compound_value):
            return False

        # Validate Minimum Constraints for nominalUnitsXSatsPerBch
        if not (nominal_units_x_sats_per_bch >= SATS_PER_BCH):
            return False
 
        division_precision_valid = self.validate_integer_division_precision(nominal_units_x_sats_per_bch, high_liquidation_price, MIN_INTEGER_DIVISION_PRECISION_STEPS + 1)
        if not division_precision_valid:
            return False

        return True
 
    def validate_payout_sats(self,payout_sats: int) -> bool: 
    
        DUST_LIMIT: Final = 546  # Example value, adjust as needed
        SATS_PER_BCH: Final = 100000000
        MAX_CONTRACT_SATS: Final = 1000000000000
        
        # Payout satoshis must be an integer.
        if not isinstance(payout_sats, int):
            return False

        # Payout satoshis must be within the allowed total BCH value for contracts.
        if payout_sats > MAX_CONTRACT_SATS:
            return False

        # Payout satoshis must be greater than the dust limit.
        if payout_sats <= DUST_LIMIT:
            return False

        # If all checks passed, the payout satoshis value is valid
        return True

    def compileContract(self, contractParameters): 
        my_contract = contract.Contract(artifact_dict, contractParameters)
        return my_contract
 
# This is a class for the data structure for the set of Contract Creation Parameters 
class ContractCreationParameters:
    def __init__(self, taker_side: str, maker_side: str, oracle_public_key: str,
                 hedge_mutual_redeem_public_key: str, long_mutual_redeem_public_key: str,
                 hedge_payout_address: str, long_payout_address: str, enable_mutual_redemption: bool,
                 nominal_units: int, starting_oracle_message: str, starting_oracle_signature: str,
                 maturity_timestamp: str, high_liquidation_price_multiplier: Decimal,
                 low_liquidation_price_multiplier: Decimal):
        self.taker_side = taker_side
        self.maker_side = maker_side
        self.oracle_public_key = oracle_public_key
        self.hedge_mutual_redeem_public_key = hedge_mutual_redeem_public_key
        self.long_mutual_redeem_public_key = long_mutual_redeem_public_key
        self.hedge_payout_address = hedge_payout_address
        self.long_payout_address = long_payout_address
        self.enable_mutual_redemption = enable_mutual_redemption
        self.nominal_units = nominal_units
        self.starting_oracle_message = starting_oracle_message
        self.starting_oracle_signature = starting_oracle_signature
        self.maturity_timestamp = maturity_timestamp
        self.high_liquidation_price_multiplier = high_liquidation_price_multiplier
        self.low_liquidation_price_multiplier = low_liquidation_price_multiplier
        
 
    def to_dict(self):
    # Convert all attributes to a dictionary with camelCase keys, the exact spelling is expected by the anyhedge service
        my_hedge_payout_address = self.hedge_payout_address
        if "bitcoincash" not in my_hedge_payout_address:
            my_hedge_payout_address = "bitcoincash:" + my_hedge_payout_address
        my_long_payout_address = self.long_payout_address
        if "bitcoincash" not in my_long_payout_address:
            my_long_payout_address = "bitcoincash:" + my_long_payout_address
             
            
        return {
            "takerSide": self.taker_side,
            "makerSide": self.maker_side,
            "oraclePublicKey": self.oracle_public_key,
            "hedgeMutualRedeemPublicKey": self.hedge_mutual_redeem_public_key,
            "longMutualRedeemPublicKey": self.long_mutual_redeem_public_key,
            "hedgePayoutAddress": my_hedge_payout_address,
            "longPayoutAddress": my_long_payout_address,
            "enableMutualRedemption": self.enable_mutual_redemption,
            "enableMutualRedemption": 1 if self.enable_mutual_redemption else 0,  # expects number 0 or 1
            "nominalUnits": self.nominal_units,
            "startingOracleMessage": self.starting_oracle_message,    
            "startingOracleSignature": self.starting_oracle_signature,
            "maturityTimestamp": self.maturity_timestamp,
            "highLiquidationPriceMultiplier": float(self.high_liquidation_price_multiplier),  # Convert Decimal to float for JSON serialization
            "lowLiquidationPriceMultiplier": float(self.low_liquidation_price_multiplier)
            }

    def to_string(self):
    
        # This function is used for display to the user at the end of the plugin process.
        
        my_hedge_payout_address = self.hedge_payout_address
        if "bitcoincash" not in my_hedge_payout_address:
            my_hedge_payout_address = "bitcoincash:" + my_hedge_payout_address
        my_long_payout_address = self.long_payout_address
        if "bitcoincash" not in my_long_payout_address:
            my_long_payout_address = "bitcoincash:" + my_long_payout_address
          
        # Concatenate all parameters into one string
        parameters_string = (
            f"takerSide: {self.taker_side}\r\n"
            f"makerSide: {self.maker_side}\r\n"
            f"oraclePublicKey: {self.oracle_public_key}\r\n"
            f"hedgeMutualRedeemPublicKey: {self.hedge_mutual_redeem_public_key}\r\n"
            f"longMutualRedeemPublicKey: {self.long_mutual_redeem_public_key}\r\n"
            f"hedgePayoutAddress: {my_hedge_payout_address}\r\n"
            f"longPayoutAddress: {my_long_payout_address}\r\n"
            f"enableMutualRedemption: {1 if self.enable_mutual_redemption else 0}\r\n"
            f"nominalUnits: {self.nominal_units}\r\n"
            f"startingOracleMessage: {self.starting_oracle_message}\r\n"
            f"startingOracleSignature: {self.starting_oracle_signature}\r\n"
            f"maturityTimestamp: {self.maturity_timestamp}\r\n"
            f"highLiquidationPriceMultiplier: {float(self.high_liquidation_price_multiplier)}\r\n"
            f"lowLiquidationPriceMultiplier: {float(self.low_liquidation_price_multiplier)}"
            )

    
        return parameters_string

# Another class used for the structure of the contract, but more internal in the process than the contract creation parameters.
class ContractParameters:
    def __init__(self, maturityTimestamp: int, startTimestamp: int,
                 highLiquidationPrice: int, lowLiquidationPrice: int,
                 payoutSats: int, nominalUnitsXSatsPerBch: int,
                 oraclePublicKey: str, longLockScript: str, hedgeLockScript: str,
                 enableMutualRedemption: bool, longMutualRedeemPublicKey: str,
                 hedgeMutualRedeemPublicKey: str):
        self.maturityTimestamp = maturityTimestamp
        self.startTimestamp = startTimestamp
        self.highLiquidationPrice = highLiquidationPrice
        self.lowLiquidationPrice = lowLiquidationPrice
        self.payoutSats = payoutSats
        self.nominalUnitsXSatsPerBch = nominalUnitsXSatsPerBch
        self.oraclePublicKey = oraclePublicKey
        self.longLockScript = longLockScript
        self.hedgeLockScript = hedgeLockScript
        self.enableMutualRedemption = enableMutualRedemption
        self.longMutualRedeemPublicKey = longMutualRedeemPublicKey
        self.hedgeMutualRedeemPublicKey = hedgeMutualRedeemPublicKey

# Class for the structure of an oracle request
class OracleSearchRequest:
    def __init__(self, public_key: str, min_data_sequence: int, count: int):
        self.public_key = public_key
        self.min_data_sequence = min_data_sequence
        self.count = count   

    def to_dict(self):
        # Converts the instance into a dictionary.
        return {
            "publicKey": self.public_key,
            "minDataSequence": self.min_data_sequence,
            "count": self.count
        }
         
        
        



