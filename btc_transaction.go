package ecdsa

// Worst case script and input/output size estimates.
const (
	// RedeemP2PKHSigScriptSize is the worst case (largest) serialize size
	// of a transaction input script that redeems a compressed P2PKH output.
	// It is calculated as:
	//
	//   - OP_DATA_73
	//   - 72 bytes DER signature + 1 byte sighash
	//   - OP_DATA_33
	//   - 33 bytes serialized compressed pubkey
	RedeemP2PKHSigScriptSize = 1 + 73 + 1 + 33

	// P2PKHPkScriptSize is the size of a transaction output script that
	// pays to a compressed pubkey hash.  It is calculated as:
	//
	//   - OP_DUP
	//   - OP_HASH160
	//   - OP_DATA_20
	//   - 20 bytes pubkey hash
	//   - OP_EQUALVERIFY
	//   - OP_CHECKSIG
	P2PKHPkScriptSize = 1 + 1 + 1 + 20 + 1 + 1

	// RedeemP2PKHInputSize is the worst case (largest) serialize size of a
	// transaction input redeeming a compressed P2PKH output.  It is
	// calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte compact int encoding value 107
	//   - 107 bytes signature script
	//   - 4 bytes sequence
	RedeemP2PKHInputSize = 32 + 4 + 1 + RedeemP2PKHSigScriptSize + 4

	// P2PKHOutputSize is the serialize size of a transaction output with a
	// P2PKH output script.  It is calculated as:
	//
	//   - 8 bytes output value
	//   - 1 byte compact int encoding value 25
	//   - 25 bytes P2PKH output script
	P2PKHOutputSize = 8 + 1 + P2PKHPkScriptSize

	// P2WPKHPkScriptSize is the size of a transaction output script that
	// pays to a witness pubkey hash. It is calculated as:
	//
	//   - OP_0
	//   - OP_DATA_20
	//   - 20 bytes pubkey hash
	P2WPKHPkScriptSize = 1 + 1 + 20

	// P2WPKHOutputSize is the serialize size of a transaction output with a
	// P2WPKH output script. It is calculated as:
	//
	//   - 8 bytes output value
	//   - 1 byte compact int encoding value 22
	//   - 22 bytes P2PKH output script
	P2WPKHOutputSize = 8 + 1 + P2WPKHPkScriptSize

	// RedeemP2WPKHScriptSize is the size of a transaction input script
	// that spends a pay-to-witness-public-key hash (P2WPKH). The redeem
	// script for P2WPKH spends MUST be empty.
	RedeemP2WPKHScriptSize = 0

	// RedeemP2WPKHInputSize is the worst case size of a transaction
	// input redeeming a P2WPKH output. It is calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte encoding empty redeem script
	//   - 0 bytes redeem script
	//   - 4 bytes sequence
	RedeemP2WPKHInputSize = 32 + 4 + 1 + RedeemP2WPKHScriptSize + 4

	// RedeemNestedP2WPKHScriptSize is the worst case size of a transaction
	// input script that redeems a pay-to-witness-key hash nested in P2SH
	// (P2SH-P2WPKH). It is calculated as:
	//
	//   - 1 byte compact int encoding value 22
	//   - OP_0
	//   - 1 byte compact int encoding value 20
	//   - 20 byte key hash
	RedeemNestedP2WPKHScriptSize = 1 + 1 + 1 + 20

	// RedeemNestedP2WPKHInputSize is the worst case size of a
	// transaction input redeeming a P2SH-P2WPKH output. It is
	// calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 1 byte compact int encoding value 23
	//   - 23 bytes redeem script (scriptSig)
	//   - 4 bytes sequence
	RedeemNestedP2WPKHInputSize = 32 + 4 + 1 + RedeemNestedP2WPKHScriptSize + 4

	// RedeemP2WPKHInputWitnessWeight is the worst case weight of
	// a witness for spending P2WPKH and nested P2WPKH outputs. It
	// is calculated as:
	//
	//   - 1 wu compact int encoding value 2 (number of items)
	//   - 1 wu compact int encoding value 73
	//   - 72 wu DER signature + 1 wu sighash
	//   - 1 wu compact int encoding value 33
	//   - 33 wu serialized compressed pubkey
	RedeemP2WPKHInputWitnessWeight = 1 + 1 + 73 + 1 + 33
)

type BTCAddress string

type BTCTX struct {
	Txid     string `json:"txid"`
	Hash     string `json:"hash,omitempty"`
	Version  int32  `json:"version"`
	Size     int32  `json:"size,omitempty"`
	Vsize    int32  `json:"vsize,omitempty"`
	Weight   int32  `json:"weight,omitempty"`
	LockTime uint32 `json:"locktime"`
	Vin      []Vin  `json:"vin"`
	Vout     []Vout `json:"vout"`
}

type Vin struct {
	Txid      string     `json:"txid"`
	Vout      uint32     `json:"vout"`
	ScriptSig *ScriptSig `json:"scriptSig"`
	Sequence  uint32     `json:"sequence"`
}

// Vout models parts of the tx data.  It is defined separately since both
// getrawtransaction and decoderawtransaction use the same structure.
type Vout struct {
	Value        float64            `json:"value"`
	N            uint32             `json:"n"`
	ScriptPubKey ScriptPubKeyResult `json:"scriptPubKey"`
}

// ScriptPubKeyResult models the scriptPubKey data of a tx script.  It is
// defined separately since it is used by multiple commands.
type ScriptPubKeyResult struct {
	Asm       string   `json:"asm"`
	Hex       string   `json:"hex,omitempty"`
	ReqSigs   int32    `json:"reqSigs,omitempty"`
	Type      string   `json:"type"`
	Addresses []string `json:"addresses,omitempty"`
}

// Unspent
type Unspent struct {
	TxID         string  `json:"txid"`
	Vout         uint32  `json:"vout"`
	Address      string  `json:"address"`
	ScriptPubKey string  `json:"scriptPubKey"`
	Amount       float64 `json:"amount"`
	Spendable    bool    `json:"spendable"`
}

// ScriptSig models a signature script.  It is defined separately since it only
// applies to non-coinbase.  Therefore the field in the Vin structure needs
// to be a pointer.
type ScriptSig struct {
	Asm string `json:"asm"`
	Hex string `json:"hex"`
}

func NewBTCTX(from, to BTCAddress, amount int64, fee float64) BTCTX {
	return newBTCTX(from, to, amount, fee)
}

func newBTCTX(from, to BTCAddress, amount int64, fee float64) BTCTX {
	// 1、查询from未花费输出是否
	// 2、添加output
	// 3、计算手续费
	// 4、找零金额
	// 5、拼接交易
	btctx := BTCTX{
		Txid:     "",
		Hash:     "",
		Version:  1,
		Size:     226,
		Vsize:    226,
		Weight:   904,
		LockTime: 0,
		Vin:      []Vin{},
		Vout:     []Vout{},
	}

	return btctx
}

// 手续费计算 每字节
// 基础 10 bytes：Version 4 bytes, LockTime 4 bytes, txin 1 bytes, txout 1 bytes,
// Input： Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes + serialized varint size for the length of SignatureScript + SignatureScript bytes.
// Output： 8 bytes + serialized varint size for the length of PkScript + PkScript bytes.
// ===========================================================================================
// Pay-to-pubkey-hash P2PKH which begin with the number 1, eg: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.
// Input with compressed pubkey (148 bytes):36 prev outpoint, 1 script len, 107 script [1 OP_DATA_72, 72 sig,1 OP_DATA_33, 33 compressed pubkey], 4 sequence
// Output to hash (34 bytes):8 value, 1 script len, 25 script [1 OP_DUP, 1 OP_HASH_160,1 OP_DATA_20, 20 hash, 1 OP_EQUALVERIFY, 1 OP_CHECKSIG]
// ===========================================================================================
// P2SH type starting with the number 3, eg: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.
// Input with compressed pubkey (92 bytes):36 prev outpoint, 1 script len, 0 script (not sigScript), 107=67 witness stack bytes [1 element length, 33 compressed pubkey,element length 72 sig], 4 sequence
// Output to hash (31 bytes):8 value, 1 script len, 22 script [1 OP_HASH_160, 20 hash, 1 OP_EQUAL]
// 7b54371cd23c5105119c3da9a905c0dd5d3cbf5719eb87676d38942ea1e6a484：191 bytes = 10 bytes + 1 * 147 bytes + 1 * 34 bytes
//
func estimateFee(inAddrNum, outAddrNum, feeRate float64) float64 {
	byteNum := inAddrNum*149 + 34*outAddrNum + 10
	return byteNum * feeRate / 1e8
}
