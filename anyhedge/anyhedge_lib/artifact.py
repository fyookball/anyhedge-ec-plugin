# Corresponds to javascript node_modules/@general_protocols/anyhedge-contracts/contracts/v0.11.
# Simpler to convert to pure python file in the context of loading from plugin rather than using a .json file.

artifact_dict = {
    "contractName": "AnyHedge_v0_11",
    "constructorInputs": [
        {"name": "hedgeMutualRedeemPublicKey", "type": "pubkey"},
        {"name": "longMutualRedeemPublicKey", "type": "pubkey"},
        {"name": "enableMutualRedemption", "type": "int"},
        {"name": "hedgeLockScript", "type": "bytes"},
        {"name": "longLockScript", "type": "bytes"},
        {"name": "oraclePublicKey", "type": "pubkey"},
        {"name": "nominalUnitsXSatsPerBch", "type": "int"},
        {"name": "payoutSats", "type": "int"},
        {"name": "lowLiquidationPrice", "type": "int"},
        {"name": "highLiquidationPrice", "type": "int"},
        {"name": "startTimestamp", "type": "int"},
        {"name": "maturityTimestamp", "type": "int"}
    ],
    "abi": [
        {
            "name": "mutualRedeem",
            "inputs": [
                {"name": "hedgeMutualRedeemSignature", "type": "sig"},
                {"name": "longMutualRedeemSignature", "type": "sig"}
            ]
        },
        {
            "name": "payout",
            "inputs": [
                {"name": "settlementMessage", "type": "bytes"},
                {"name": "settlementSignature", "type": "datasig"},
                {"name": "previousMessage", "type": "bytes"},
                {"name": "previousSignature", "type": "datasig"}
            ]
        }
    ],
    "bytecode": "OP_12 OP_PICK OP_0 OP_NUMEQUAL OP_IF OP_ROT OP_VERIFY OP_12 OP_ROLL OP_SWAP OP_CHECKSIGVERIFY OP_11 OP_ROLL OP_SWAP OP_CHECKSIGVERIFY OP_2DROP OP_2DROP OP_2DROP OP_2DROP OP_2DROP OP_1 OP_ELSE OP_12 OP_ROLL OP_1 OP_NUMEQUALVERIFY OP_TXINPUTCOUNT OP_1 OP_NUMEQUALVERIFY OP_15 OP_ROLL OP_15 OP_PICK OP_7 OP_PICK OP_CHECKDATASIGVERIFY OP_13 OP_ROLL OP_13 OP_PICK OP_7 OP_ROLL OP_CHECKDATASIGVERIFY OP_12 OP_PICK OP_8 OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_DROP OP_BIN2NUM OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY OP_12 OP_PICK OP_8 OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_DROP OP_BIN2NUM OP_1SUB OP_NUMEQUALVERIFY OP_12 OP_ROLL OP_4 OP_SPLIT OP_DROP OP_BIN2NUM OP_11 OP_PICK OP_LESSTHAN OP_VERIFY OP_11 OP_PICK OP_12 OP_SPLIT OP_NIP OP_BIN2NUM OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY OP_9 OP_PICK OP_MIN OP_8 OP_PICK OP_MAX OP_12 OP_ROLL OP_4 OP_SPLIT OP_DROP OP_BIN2NUM OP_DUP OP_12 OP_ROLL OP_GREATERTHANOREQUAL OP_VERIFY OP_11 OP_ROLL OP_GREATERTHANOREQUAL OP_OVER OP_10 OP_ROLL OP_1ADD OP_11 OP_ROLL OP_WITHIN OP_NOT OP_BOOLOR OP_VERIFY 2202 OP_DUP OP_8 OP_ROLL OP_3 OP_ROLL OP_DIV OP_MAX OP_SWAP OP_7 OP_ROLL OP_2 OP_PICK OP_SUB OP_MAX OP_TXOUTPUTCOUNT OP_2 OP_NUMEQUALVERIFY OP_0 OP_OUTPUTVALUE OP_ROT OP_NUMEQUALVERIFY OP_0 OP_OUTPUTBYTECODE OP_5 OP_ROLL OP_EQUALVERIFY OP_1 OP_OUTPUTVALUE OP_NUMEQUALVERIFY OP_1 OP_OUTPUTBYTECODE OP_4 OP_ROLL OP_EQUAL OP_NIP OP_NIP OP_NIP OP_ENDIF",
    "source": "<Omitted for compactness>",
    "compiler": {
        "name": "cashc",
        "version": "0.7.0"
    },
    "updatedAt": "2022-05-27T09:57:21.967Z"
}

