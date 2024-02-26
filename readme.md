# AnyHedge Proof of Concept

This is a proof of concept plugin for BCHBULL/AnyHedge smart contracts on BCH.  This plugin is
intended primarily for developers and is meant to demonstrate a succesful conversion
from JavaScript to Python of some of the key functionalities involved in AnyHedge
and how they could be set up in the context of an Electron Cash plugin.

The starting point for creation of the plugin was to roughly emulate the
functionality of the examples/custodial.js script, which creates a
smart contract given some starting inputs such as the WIF private
keys for the hedge and long positions.  That script generated a
smart contract, registered it using the Anyhedge service, and
created a funding transaction.  This plugin attemps to do the
same, but does not create the funding transaction; it merely
creates the smart contract and registers it with the Anyhedge service.

The anyhedge code relies heavily on many functions within the Cashscript and Bitauth
libraries.  The required functions have been converted here to python and mostly
live inside the Contract.py file.  

A few shortcuts have been taken for this proof of concept.  The registration
process does not first check if the contract exists, nor does it attempt
extra validation after registration.  For the most part, the python code
attempts to closely mirror the JS code but there are a few exceptions.
Notably, the cash_address_to_locking_byte_code function in cashaddress.py
assumes we're dealing with a P2PKH and does not attempt to deal with
malformed scripts.  The disassemble_parsed_authentication_instruction
function in contract.py also does not deal with malformed scripts.

The code flow begins with ui.py and then calls into the various helper
files, with most of the code living in anyhedgemanager.py and contract.py.
oracle.py and gp_service.py deal with network calls.  


