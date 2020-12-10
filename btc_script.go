package ecdsa

import (
	bytes "github.com/sea-project/stdlib-bytes"
)

// payToPubKeyHashScript creates a new script to pay a transaction
// output to a 20-byte pubkey hash. It is expected that the input is a valid
// hash.
func payToPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return bytes.NewScriptBuilder().AddOp(OP_DUP).AddOp(OP_HASH160).
		AddData(pubKeyHash).AddOp(OP_EQUALVERIFY).AddOp(OP_CHECKSIG).
		Script()
}

// payToWitnessPubKeyHashScript creates a new script to pay to a version 0
// pubkey hash witness program. The passed hash is expected to be valid.
func payToWitnessPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return bytes.NewScriptBuilder().AddOp(OP_0).AddData(pubKeyHash).Script()
}

// payToScriptHashScript creates a new script to pay a transaction output to a
// script hash. It is expected that the input is a valid hash.
func payToScriptHashScript(scriptHash []byte) ([]byte, error) {
	return bytes.NewScriptBuilder().AddOp(OP_HASH160).AddData(scriptHash).
		AddOp(OP_EQUAL).Script()
}

// payToWitnessPubKeyHashScript creates a new script to pay to a version 0
// script hash witness program. The passed hash is expected to be valid.
func payToWitnessScriptHashScript(scriptHash []byte) ([]byte, error) {
	return bytes.NewScriptBuilder().AddOp(OP_0).AddData(scriptHash).Script()
}

// payToPubkeyScript creates a new script to pay a transaction output to a
// public key. It is expected that the input is a valid pubkey.
func payToPubKeyScript(serializedPubKey []byte) ([]byte, error) {
	return bytes.NewScriptBuilder().AddData(serializedPubKey).
		AddOp(OP_CHECKSIG).Script()
}
