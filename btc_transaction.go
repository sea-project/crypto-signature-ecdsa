package ecdsa

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
func estimateFee(inAddrNum, outAddrNum, feeRate float64) float64 {

	byteNum := inAddrNum*148 + 34*outAddrNum + 10
	return byteNum * feeRate / 1e8
}

// baseSize returns the serialized size of the transaction without accounting
// for any witness data.
/*func (msg *BTCTX) baseSize() int {
	// Version 4 bytes + LockTime 4 bytes + Serialized varint size for the
	// number of transaction inputs and outputs.
	n := 8 + uint64(len(msg.Vin)) + uint64(len(msg.Vout))

	for _, txIn := range msg.Vin {
		n += txIn.SerializeSize()
	}

	for _, txOut := range msg.Vout {
		n += txOut.SerializeSize()
	}

	return n
}*/

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction input.
/*func (t *Vin) SerializeSize() int {
	// Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes +
	// serialized varint size for the length of SignatureScript +
	// SignatureScript bytes.
	return 40 + len(t.ScriptSig) +	len(t.ScriptSig)
}*/

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
/*func (t *Vout) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of PkScript +
	// PkScript bytes.
	return 8 + len(t.ScriptPubKey) + len(t.ScriptPubKey)
}*/

// makeInputSource creates an InputSource that creates inputs for every unspent
// output with non-zero output values.  The target amount is ignored since every
// output is consumed.  The InputSource does not return any previous output
// scripts as they are not needed for creating the unsinged transaction and are
// looked up again by the wallet during the call to signrawtransaction.
/*func (tx BTCTX) makeVin(unspents []Unspent)  {
	var vins []Vin
	for _, unspent := range unspents {
		vin := Vin{

		}
	}
}*/
