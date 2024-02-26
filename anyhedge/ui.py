import threading
import asyncio
import datetime
import hashlib
import sys
import time
import os
import asyncio 
import math
import json

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import * 
from electroncash.i18n import _
from electroncash_gui.qt.util import MyTreeWidget, MessageBoxMixin, WindowModalDialog, Buttons, CancelButton,OkButton
from electroncash import util 
from electroncash.util import print_error
from electroncash.address import Address, PublicKey
from electroncash import schnorr as schnorr
import electroncash.bitcoin as bitcoin

sys.path.insert(0,os.path.join(os.path.dirname(__file__),'anyhedge_lib'))
 
from .anyhedgewrap import anyhedgewrap
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QApplication


class WaitingDialog(QDialog):
    def __init__(self, parent=None):
        super(WaitingDialog, self).__init__(parent)
        self.setWindowTitle("Please Wait")
        self.setMinimumSize(300, 100)
         
        self._vbox = vbox = QVBoxLayout(self)
        self._label = label = QLabel("ss")
        vbox.addWidget(label)
        
        # Make the dialog modal  
        self.setModal(True)
        self.update()
        
class Ui(MyTreeWidget, MessageBoxMixin):

    
    
    receive_refresh_feed_trigger = pyqtSignal(str)

    def __init__(self, parent, plugin, wallet_name):
        # An initial widget is required.
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 0, [])

        import os.path
        self.my_anyhedgewrap = anyhedgewrap(ui_window = self) 

        self.chat_history =""

        self.plugin = plugin
        self.wallet_name = wallet_name
        vbox = QVBoxLayout()
        vbox2 = QVBoxLayout() 
        vbox5 = QVBoxLayout() 
        self.setLayout(vbox)  
         
        self.my_instructions = QLabel(_("This is a proof of concept plugin for developers.  Paste WIF private keys into the boxes below.  WARNING: Normally you should NEVER paste your private keys anywhere!  Don't do this unless you trust this plugin.  The plugin will create a smart contract and register it but will not create any funding transaction.  Demonstration purposes only. "))
        self.my_instructions.setWordWrap(True)
        hbox7 = QHBoxLayout()
        hbox7.addWidget(self.my_instructions) 
        
        self.wif_hedge = QLineEdit()
        self.wif_long = QLineEdit()
        self.label21 = QLabel(_("WIF for Hedge Address"))
        self.label22 = QLabel(_("WIF for Long Address"))
        
        self.main_activation_button = QPushButton(_("Register Smart Contract"))
        self.main_activation_button.clicked.connect(self.activate_smart_contract_handler)
        hbox2=QHBoxLayout()
        hbox2.addWidget(self.label21)
        hbox2.addWidget(self.wif_hedge)
        
        
        hbox3=QHBoxLayout()
        hbox3.addWidget(self.label22)
        hbox3.addWidget(self.wif_long)

        hbox4=QHBoxLayout()
        hbox4.addWidget(self.main_activation_button)        
        
        vbox2.addLayout(hbox7)
        vbox2.addLayout(hbox2)
        vbox2.addLayout(hbox3)
        vbox2.addLayout(hbox4)
          
        my_line = QFrame()
        my_line.setLineWidth(3)
        my_line.setMidLineWidth(3)
        my_line.setFrameShape(QFrame.HLine)
        my_line.setFrameShadow(QFrame.Sunken)
        vbox5.addWidget(my_line) 
        
         
        # Add remaining widgets
        vbox.addLayout(vbox5)     
        vbox.addLayout(vbox2)
        
    def create_smart_contract(self, contract_creation_parameters):
    
        # This is the starting point of the actual meat of the smart contract creation.
        
        SATS_PER_BCH:Final = 100000000;
        
        # Extract parameters
        taker_side = contract_creation_parameters.taker_side
        maker_side = contract_creation_parameters.maker_side
        oracle_public_key = contract_creation_parameters.oracle_public_key
        hedge_payout_address = contract_creation_parameters.hedge_payout_address
        long_payout_address = contract_creation_parameters.long_payout_address
        enable_mutual_redemption = contract_creation_parameters.enable_mutual_redemption
        nominal_units = contract_creation_parameters.nominal_units
        starting_oracle_message = contract_creation_parameters.starting_oracle_message
        starting_oracle_signature = contract_creation_parameters.starting_oracle_signature
        maturity_timestamp = contract_creation_parameters.maturity_timestamp
        high_liquidation_price_multiplier = contract_creation_parameters.high_liquidation_price_multiplier
        low_liquidation_price_multiplier = contract_creation_parameters.low_liquidation_price_multiplier
        hedge_mutual_redeem_public_key = contract_creation_parameters.hedge_mutual_redeem_public_key
        long_mutual_redeem_public_key = contract_creation_parameters.long_mutual_redeem_public_key
 
        # Set prefixes if necessary
        if not ("bitcoincash" in hedge_payout_address):
            hedge_payout_address="bitcoincash:"+hedge_payout_address
         
        if not ("bitcoincash" in long_payout_address):
            long_payout_address="bitcoincash:"+long_payout_address
              
        # Validate taker side
        if taker_side not in ['hedge', 'long']:
            raise ContractCreationError(f"Taker ({taker_side}) must be either 'hedge' or 'long'.")

        # Validate maker side
        if maker_side != ('long' if taker_side == 'hedge' else 'hedge'):
             raise ContractCreationError(f"Maker ({maker_side}) must be on the opposite side of the taker ({taker_side}).")
 
        starting_oracle_message_bytes = bytes.fromhex(starting_oracle_message)
        my_anyhedge_manager=self.my_anyhedgewrap.Terminal.anyhedgemanager.AnyHedgeManager()
        messageTimestamp, messageSequence, priceSequence, priceValue = my_anyhedge_manager.parse_price_message(starting_oracle_message_bytes)
        
        if (messageTimestamp == 0):
            self.show_error("An error occured parsing the price message.")
            return
            
        # Calculate values based on parameters    
        start_price = priceValue
        start_timestamp = messageTimestamp 
        low_liquidation_price = round(low_liquidation_price_multiplier * start_price)
        high_liquidation_price = round(high_liquidation_price_multiplier * start_price)
        hedge_input_in_satoshis = round((nominal_units * SATS_PER_BCH) / start_price)
        total_input_sats = math.ceil((nominal_units * SATS_PER_BCH) / low_liquidation_price)
        nominal_units_x_sats_per_bch = round(nominal_units * SATS_PER_BCH)
        long_input_in_satoshis = total_input_sats - hedge_input_in_satoshis
        long_input_in_oracle_units = ((long_input_in_satoshis / SATS_PER_BCH) * start_price)
        hedge_input_in_oracle_units = ((hedge_input_in_satoshis / SATS_PER_BCH) * start_price)
        duration_in_seconds = maturity_timestamp - start_timestamp 
        hedgeLockScript = my_anyhedge_manager.addressToLockScript(hedge_payout_address);        
        longLockScript = my_anyhedge_manager.addressToLockScript(long_payout_address);
        
        # Pack the parameters into an object
        contract_parameters = self.my_anyhedgewrap.Terminal.anyhedgemanager.ContractParameters(
            maturityTimestamp=maturity_timestamp,
            startTimestamp=start_timestamp,
            highLiquidationPrice=high_liquidation_price,
            lowLiquidationPrice=low_liquidation_price,
            payoutSats=total_input_sats,
            nominalUnitsXSatsPerBch=nominal_units_x_sats_per_bch,
            oraclePublicKey=oracle_public_key,
            longLockScript=longLockScript,
            hedgeLockScript=hedgeLockScript,
            enableMutualRedemption=enable_mutual_redemption,
            longMutualRedeemPublicKey=long_mutual_redeem_public_key,
            hedgeMutualRedeemPublicKey=hedge_mutual_redeem_public_key
        )

        # Perform some validation
        if not my_anyhedge_manager.validate_low_liquidation_price(contract_parameters.lowLiquidationPrice,start_price):
            self.my_waiting_dialog.accept() 
            self.show_error("The smart contract failed validation.")
            return
        if not my_anyhedge_manager.validate_high_liquidation_price(contract_parameters.highLiquidationPrice,start_price):
            self.my_waiting_dialog.accept() 
            self.show_error("The smart contract failed validation.")
            return
        if not my_anyhedge_manager.validate_nominal_units_x_sats_per_bch(contract_parameters.nominalUnitsXSatsPerBch,contract_parameters.highLiquidationPrice,contract_parameters.lowLiquidationPrice,contract_parameters.payoutSats):
            self.my_waiting_dialog.accept() 
            self.show_error("The smart contract failed validation.")
            return
        if not my_anyhedge_manager.validate_payout_sats(contract_parameters.payoutSats):
            self.my_waiting_dialog.accept() 
            self.show_error("The smart contract failed validation.")
            return
                 
        # Call into the anyhedge_manager which does the heavy lifting to compile the contract.         
        compiled_contract = my_anyhedge_manager.compileContract(contract_parameters)
        return compiled_contract        
          
    
    def activate_smart_contract_handler(self):
    
        # This is a wrapper function which is called from clicking the UI Button to start everyting.
        # Its job is to set up the modal dialog and then kick off an async operation.
        
        self.my_waiting_dialog = WindowModalDialog(self)
        self.my_waiting_dialog.setWindowTitle("Please Wait")   
       
        label = QLabel("Processing...")
        layout = QHBoxLayout() 
        
        # Set the dialog's layout
        self.my_waiting_dialog.setLayout(layout)
        
        layout.addWidget(label)
        self.my_waiting_dialog.setFixedWidth(300)
        self.my_waiting_dialog.show() 
        # wait 50ms to let the dialog render
        QTimer.singleShot(50, self.start_async_smart_contract_operation)  
             
    def start_async_smart_contract_operation(self):
        # This is a helper function to start the async operation from within the Qt event loop
        asyncio.run(self.activate_smart_contract_with_timeout())
         
    async def activate_smart_contract_with_timeout(self):
        # This is another wrapper function which provides the timeout feature (10 seconds) 
        # within which we start actually building the smart contract.
        try: 
            await asyncio.wait_for(self.activate_smart_contract(), timeout=10)
        except asyncio.TimeoutError:
            
            self.my_waiting_dialog.accept() 
            self.show_error("The process timed out and may not have completed.")
            
      
         
    async def activate_smart_contract(self):
    
        #-------------
        # Uncomment the following line if you want to test sleeping for timeout behavior. If we wait too long we should exit gracefully with error pop up alert.
        #await asyncio.sleep(20)
        #-------------
        
        # Initialize some variables
        ORACLE_PUBLIC_KEY: Final = '02d09db08af1ff4e8453919cc866a4be427d7bfe18f2c05e5444c196fcf6fd2818'
        ORACLE_RELAY: Final = 'oracles.generalprotocols.com'
        
        # This may end up changing or you can generate a new auth token from the Anyhedge API service.
        AUTHENTICATION_TOKEN: Final = '1fe791cad49db8009312e1bb2fdb1a30fa8bbe5fd8131ef13e357967da94da95'
        
        CONTRACT_DURATION_IN_SECONDS: Final = 7500;
        NOMINAL_UNITS: Final = 50;
        CONTRACT_LOW_LIQUIDATION_PRICE_MULTIPLIER: Final = 0.75;
        CONTRACT_HIGH_LIQUIDATION_PRICE_MULTIPLIER: Final = 10.00;
        enableMutualRedemption = True
        
        # Get the initial prices from the Oracle.       
        search_request_instance = self.my_anyhedgewrap.Terminal.anyhedgemanager.OracleSearchRequest(public_key=ORACLE_PUBLIC_KEY, min_data_sequence=1, count=1)
        search_request_details = search_request_instance.to_dict()
        search_request = await self.my_anyhedgewrap.Terminal.oracle.OracleRequester.request(content=search_request_details,address=ORACLE_RELAY,port=7083)
        
        if search_request is None:
            self.show_error("Failed to retrieve oracle info.")
            return
        # Check if search_request is empty
        if len(search_request) == 0:
            self.show_error("Failed to retrieve oracle info.")
            return 

        # Unpack the data from the oracle.            
        response_data = search_request[0] # Get the first item from the list
        startingOracleMessage = response_data['message']
        startingOracleSignature = response_data['signature']
        publicKey = response_data['publicKey']
        
        
        # Convert hex strings to bytes
        pubkey_bytes = bytes.fromhex(publicKey)
        signature_bytes = bytes.fromhex(startingOracleSignature)
        message_bytes = bytes.fromhex(startingOracleMessage)
        message_hash_bytes = hashlib.sha256(message_bytes).digest()
        try:
            oracleMessageValid = schnorr.verify(pubkey_bytes, signature_bytes, message_hash_bytes)
            print(f"Verified an oracle message signature with validity: {oracleMessageValid}.")
        except ValueError as e:
            print(f"Failed to verify an oracle message signature: {e}")
            
        if (oracleMessageValid is False):    
            self.my_waiting_dialog.accept() 
            self.show_error("The oracle signature was invalid.")
            return
         
        
        # Parse the WIFs for Hedge Side
        myWifInput=self.wif_hedge.text().strip()
        try:
             try:
                  txin_type, privkey, compressed = bitcoin.deserialize_privkey(myWifInput)
             except Exception as e:  
                 print(f"An error occurred: {e}")
             try:    
                 pubkey = bitcoin.public_key_from_private_key(privkey, compressed)
             except Exception as e:  
                 print(f"An error occurred: {e}")
             
        except:
            self.my_waiting_dialog.accept() 
            self.show_error("Could not parse Hedge WIF")
            return
      
        # Finish parsing hedge WIF and get Address.      
        hedgePrivateKey = PublicKey.privkey_from_WIF_privkey(myWifInput)[0].hex()
        hedgeMutualRedeemPublicKey = pubkey
        hedgePayoutAddress =  Address.from_pubkey(pubkey) 
        hedgePayoutAddressString = hedgePayoutAddress.to_string(hedgePayoutAddress.FMT_CASHADDR)
 
        
        # DO THE SAME THING FOR LONG SIDE:

        # Parse the WIFs for Long Side
        myWifInput=self.wif_long.text().strip()
        try:
             try:
                  txin_type, privkey, compressed = bitcoin.deserialize_privkey(myWifInput)
             except Exception as e:  
                 print(f"An error occurred: {e}")
             try:    
                 pubkey = bitcoin.public_key_from_private_key(privkey, compressed)
             except Exception as e:  
                 print(f"An error occurred: {e}")
              
        except:
            self.my_waiting_dialog.accept() 
            self.show_error("Could not parse Long WIF")
            return
          
        # Finish parsing long WIF and get Address.           
        longPrivateKey = PublicKey.privkey_from_WIF_privkey(myWifInput)[0].hex()
        longMutualRedeemPublicKey = pubkey
        longPayoutAddress =  Address.from_pubkey(pubkey) 
        longPayoutAddressString = longPayoutAddress.to_string(longPayoutAddress.FMT_CASHADDR)
        
        # Get the Contract Maturity
        maturityTimestamp = int(time.time()) + CONTRACT_DURATION_IN_SECONDS
        
        # Contract Creation Parameters
        contract_creation_parameters = self.my_anyhedgewrap.Terminal.anyhedgemanager.ContractCreationParameters(
            taker_side='hedge',
            maker_side='long',
            oracle_public_key=ORACLE_PUBLIC_KEY,
            hedge_mutual_redeem_public_key=hedgeMutualRedeemPublicKey,
            long_mutual_redeem_public_key=longMutualRedeemPublicKey,
            hedge_payout_address=hedgePayoutAddressString,
            long_payout_address=longPayoutAddressString,
            enable_mutual_redemption=enableMutualRedemption,
            nominal_units=NOMINAL_UNITS,
            starting_oracle_message=startingOracleMessage,
            starting_oracle_signature=startingOracleSignature,
            maturity_timestamp=maturityTimestamp,
            high_liquidation_price_multiplier=CONTRACT_HIGH_LIQUIDATION_PRICE_MULTIPLIER,
            low_liquidation_price_multiplier=CONTRACT_LOW_LIQUIDATION_PRICE_MULTIPLIER)
        
        # Create the actual smart contract        
        final_result = self.create_smart_contract(contract_creation_parameters)
        
        # Get the bitcoincash address of the contract
        final_address = final_result.address
        
        # Register the contract with AnyHedge service
        contract_parameters_dict = contract_creation_parameters.to_dict()
        combined_registration_parameters = {**contract_parameters_dict, 'fees': []}
        json_body_registration = json.dumps(combined_registration_parameters) 
        SERVICE_URL = "https://staging-api.anyhedge.com:443/api/v1/registerContract"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': AUTHENTICATION_TOKEN  
            }
        
        # Call the service and display error on failure
        try:
            registration_request = await self.my_anyhedgewrap.Terminal.gp_service.GPservice.request(content=json_body_registration,url=SERVICE_URL,headers=headers) 
        except Exception as e:  
            self.my_waiting_dialog.accept() 
            self.show_error(f"{e}")
            return
        
        # If no errors, display a success message and we are done.
        self.my_waiting_dialog.accept()
        if (final_address):
            dialog_msg = "Smart Contract "+final_address+ " registered successfully.\r\n"
            dialog_msg += "Here are the contract creation parameters:\r\n \r\n"+contract_creation_parameters.to_string()
            msg = _(dialog_msg)  
            self.show_message(msg, title=_("Success"))
        else:
            msg = _('Smart Contract failed unexpectedly.')  
            self.show_message(msg, title=_("Error"))  
        
               
    # Functions for the plugin architecture.
    def create_menu(self):
        pass
    def on_delete(self):
        pass
    def on_update(self):
        pass
        
    

  
        
        
        
        
        
                            
