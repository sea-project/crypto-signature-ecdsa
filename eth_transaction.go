package ecdsa

import (
	"encoding/hex"
	rlp "github.com/sea-project/crypto-codec-rlp"
	sha3 "github.com/sea-project/crypto-hash-sha3"
	bytes "github.com/sea-project/stdlib-bytes"
	"math/big"
	"strings"
)

const ETHAddressLength = 20
const ETHHashLength = 32

type ETHAddress [ETHAddressLength]byte
type ETHHash [ETHHashLength]byte

func BytesToHash(b []byte) ETHHash {
	var h ETHHash
	h.SetBytes(b)
	return h
}
func (h *ETHHash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-ETHHashLength:]
	}

	copy(h[ETHHashLength-len(b):], b)
}

// BytesToAddress byte转address
func BytesToAddress(b []byte) ETHAddress {
	var a ETHAddress
	a.SetBytes(b)
	return a
}

// HexToAddress 十六进制字符串转地址
func HexToAddress(s string) ETHAddress { return BytesToAddress(bytes.FromHex(s)) }

// Hex 十六进制返回地址的十六进制字符串表示形式
func (a ETHAddress) Hex() string {
	unchecksummed := hex.EncodeToString(a[:])
	hash := sha3.Keccak256([]byte(unchecksummed))

	result := []byte(unchecksummed)
	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}
	return "0x" + strings.ToLower(string(result))
}

// SetBytes 将地址设置为b的值。如果b大于len(a)，会宕机
func (a *ETHAddress) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-ETHAddressLength:]
	}
	copy(a[ETHAddressLength-len(b):], b)
}

type ETHTX struct {
	AccountNonce uint64      `json:"nonce"    gencodec:"required"`
	Price        *big.Int    `json:"gasPrice" gencodec:"required"`
	GasLimit     uint64      `json:"gas"      gencodec:"required"`
	Recipient    *ETHAddress `json:"to"       rlp:"nil"`
	Amount       *big.Int    `json:"value"    gencodec:"required"`
	Payload      []byte      `json:"input"    gencodec:"required"`

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`
}

func NewETHTX(nonce uint64, to ETHAddress, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *ETHTX {
	return newETHTX(nonce, &to, amount, gasLimit, gasPrice, data)
}

func newETHTX(nonce uint64, to *ETHAddress, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *ETHTX {
	if len(data) > 0 {
		data = bytes.CopyBytes(data)
	}
	transaction := &ETHTX{
		AccountNonce: nonce,
		Recipient:    to,
		Payload:      data,
		Amount:       new(big.Int),
		GasLimit:     gasLimit,
		Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}
	if amount != nil {
		transaction.Amount.Set(amount)
	}
	if gasPrice != nil {
		transaction.Price.Set(gasPrice)
	}

	return transaction
}

// SignHash
// (nonce, gasprice, startgas, to, value, data, chainid, 0, 0)
func (tx *ETHTX) SignHash(chainId int64) []byte {
	t := []interface{}{
		tx.AccountNonce,
		tx.Price,
		tx.GasLimit,
		tx.Recipient,
		tx.Amount,
		tx.Payload,
		big.NewInt(chainId), uint(0), uint(0),
	}
	return rlp.RLPHash(t)
}

func (tx *ETHTX) Hash() (ETHHash, error) {
	txParam, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return ETHHash{}, err
	}
	hash := BytesToHash(sha3.Keccak256(txParam))
	return hash, nil
}

func (tx *ETHTX) RawTx() ([]byte, error) {
	txParam, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return nil, err
	}
	return txParam, nil
}
