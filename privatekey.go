package ecdsa

import (
	"bytes"
	e "crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	base58 "github.com/sea-project/crypto-codec-base58"
	ecc "github.com/sea-project/crypto-ecc-s256"
	math "github.com/sea-project/stdlib-math"
	"math/big"
)

type PrivateKey e.PrivateKey

var (
	secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
)

const (
	mainnetVersion = byte(0x00) // 定义版本号，一个字节[mainnet]
	// compressMagic is the magic byte used to identify a WIF encoding for
	// an address created from a compressed serialized public key.
	compressMagic byte = 0x01
)

// ToPubKey 返回与此私钥对应的公钥
func (p *PrivateKey) ToPubKey() *PublicKey {
	return (*PublicKey)(&p.PublicKey)
}

// ToHex 私钥转哈希
func (p *PrivateKey) ToHex() string {
	return hex.EncodeToString(p.ToByte())
}

// ToByte 私钥转byte
func (p *PrivateKey) ToByte() []byte {
	if p == nil {
		return nil
	}
	return math.PaddedBigBytes(p.D, p.Params().BitSize/8)
}

// Sign 使用私钥为提供的散列(应该是散列较大消息的结果)生成ECDSA签名。生成的签名是确定性的(相同的消息和相同的密钥生成相同的签名)，并且符合RFC6979和BIP0062的规范。
func (p *PrivateKey) Sign(hash []byte) (*Signature, error) {
	return signRFC6979(p, hash)
}

// HexToECDSA 哈希字符串转私钥
func HexToPrvKey(hexkey string) (*PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, errors.New("invalid hex string")
	}
	return ToECDSA(b, true)
}

// ToECDSA []byte转私钥
func ToECDSA(d []byte, strict bool) (*PrivateKey, error) {
	priv := new(PrivateKey)
	priv.PublicKey.Curve = ecc.S256()
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

// WIFToPrvKey 哈希字符串转私钥
func WIFToPrvKey(wif string) (*PrivateKey, error) {
	decoded, err := base58.Decode(wif, base58.BitcoinAlphabet)
	if err != nil {
		return nil, err
	}
	decodedLen := len(decoded)
	var compress bool
	// Length of base58 decoded WIF must be 32 bytes + an optional 1 byte
	// (0x01) if compressed, plus 1 byte for netID + 4 bytes of checksum.
	switch decodedLen {
	case 1 + 32 + 1 + 4:
		if decoded[33] != 0x01 {
			return nil, errors.New("malformed private key")
		}
		compress = true
	case 1 + 32 + 4:
		compress = false
	default:
		return nil, errors.New("malformed private key")
	}
	// Checksum is first four bytes of double SHA256 of the identifier byte
	// and privKey.  Verify this matches the final 4 bytes of the decoded
	// private key.
	var tosum []byte
	if compress {
		tosum = decoded[:1+32+1]
	} else {
		tosum = decoded[:1+32]
	}
	cksum := DoubleHashB(tosum)[:4]
	if !bytes.Equal(cksum, decoded[decodedLen-4:]) {
		return nil, errors.New("checksum mismatch")
	}

	privKeyBytes := decoded[1 : 1+32]
	privKey, _ := PrivKeyFromBytes(ecc.S256(), privKeyBytes)
	return privKey, nil
}

// PrvKeyToWIF creates the Wallet Import Format string encoding of a WIF structure.
// See DecodeWIF for a detailed breakdown of the format and requirements of
// a valid WIF string.
func PrvKeyToWIF(privKey *PrivateKey, compress bool) string {
	// Precalculate size.  Maximum number of bytes before base58 encoding
	// is one byte for the network, 32 bytes of private key, possibly one
	// extra byte if the pubkey is to be compressed, and finally four
	// bytes of checksum.
	encodeLen := 1 + 32 + 4
	if compress {
		encodeLen++
	}

	a := make([]byte, 0, encodeLen)
	a = append(a, mainnetVersion)
	// Pad and append bytes manually, instead of using Serialize, to
	// avoid another call to make.
	a = paddedAppend(32, a, privKey.D.Bytes())
	if compress {
		a = append(a, compressMagic)
	}
	cksum := DoubleHashB(a)[:4]
	a = append(a, cksum...)
	return base58.Encode(a, base58.BitcoinAlphabet)
}
