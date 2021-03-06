package ecdsa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	e "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	ecc "github.com/sea-project/crypto-ecc-s256"
	sha3 "github.com/sea-project/crypto-hash-sha3"
	"io"
	"math/big"
)

const (
	// 压缩序列化公钥的长度
	PubKeyBytesLenCompressed = 33
	// 序列化公钥的长度
	PubKeyBytesLenUncompressed = 65

	// x coord + y coord
	pubkeyUncompressed byte = 0x4
	// y_bit + x coord
	pubkeyCompressed byte = 0x2
	pubkeyHybrid     byte = 0x6 // y_bit + x coord + y coord
)

var (
	ciphCurveBytes  = [2]byte{0x02, 0xCA}
	ciphCoordLength = [2]byte{0x00, 0x20}
)

type PublicKey e.PublicKey

// ToECDSA 将公钥作为*ecdsa.PublicKey返回
func (p *PublicKey) ToECDSA() *e.PublicKey {
	return (*e.PublicKey)(p)
}

// IsEqual 公钥相等判断
func (p *PublicKey) IsEqual(otherPubKey *PublicKey) bool {
	return p.X.Cmp(otherPubKey.X) == 0 && p.Y.Cmp(otherPubKey.Y) == 0
}

// PubKeyToHex 公钥转哈希字符串
func (p *PublicKey) ToHex() string {

	// 将公钥序列化为65位非压缩
	unCompress := p.SerializeUncompressed()

	// 将Byte类型65位非压缩转哈希字符串
	return hex.EncodeToString(unCompress)
}

// SerializeUncompressed 将公钥序列化为65位的[]byte
func (p *PublicKey) SerializeUncompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenUncompressed)
	b = append(b, pubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

// SerializeCompressed serializes a public key in a 33-byte compressed format.
func (p *PublicKey) SerializeCompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubkeyCompressed
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, p.X.Bytes())
}

// FromECDSAPub 椭圆加密公钥转坐标
func (p *PublicKey) FromECDSAPub() []byte {
	if p == nil || p.X == nil || p.Y == nil {
		return nil
	}
	return elliptic.Marshal(ecc.S256(), p.X, p.Y)
}

// Encrypt 公钥加密
func (p *PublicKey) Encrypt(data []byte) ([]byte, error) {

	// 利用新私钥与公钥生成共享秘钥
	newprv, _ := GenerateKey()
	derivedKey := sha512.Sum512(GenerateSharedSecret(newprv, p))
	keyE := derivedKey[:32]
	keyM := derivedKey[32:]

	padding := aes.BlockSize - len(data) % aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	paddedIn := append(data, padtext...)

	out := make([]byte, aes.BlockSize+70+len(paddedIn)+sha256.Size)
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	pb := newprv.ToPubKey().SerializeUncompressed()
	offset := aes.BlockSize
	copy(out[offset:offset+4], append(ciphCurveBytes[:], ciphCoordLength[:]...))
	offset += 4
	// X
	copy(out[offset:offset+32], pb[1:33])
	offset += 32
	// Y length
	copy(out[offset:offset+2], ciphCoordLength[:])
	offset += 2
	// Y
	copy(out[offset:offset+32], pb[33:])
	offset += 32

	// 开始加密
	block, err := aes.NewCipher(keyE)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out[offset:len(out)-sha256.Size], paddedIn)

	// start HMAC-SHA-256
	hm := hmac.New(sha256.New, keyM)
	hm.Write(out[:len(out)-sha256.Size])          // everything is hashed
	copy(out[len(out)-sha256.Size:], hm.Sum(nil)) // write checksum
	return out, nil
}

// ParsePubKey parses a public key for a koblitz curve from a bytestring into a
// ecdsa.Publickey, verifying that it is valid. It supports compressed,
// uncompressed and hybrid signature formats.
func ParsePubKey(pubKeyStr []byte) (key *PublicKey, err error) {
	curve := ecc.S256()
	pubkey := PublicKey{}
	pubkey.Curve = curve

	if len(pubKeyStr) == 0 {
		return nil, errors.New("pubkey string is empty")
	}

	format := pubKeyStr[0]
	ybit := (format & 0x1) == 0x1
	format &= ^byte(0x1)

	switch len(pubKeyStr) {
	case PubKeyBytesLenUncompressed:
		if format != pubkeyUncompressed && format != pubkeyHybrid {
			return nil, fmt.Errorf("invalid magic in pubkey str: "+
				"%d", pubKeyStr[0])
		}

		pubkey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubkey.Y = new(big.Int).SetBytes(pubKeyStr[33:])
		// hybrid keys have extra information, make use of it.
		if format == pubkeyHybrid && ybit != isOdd(pubkey.Y) {
			return nil, fmt.Errorf("ybit doesn't match oddness")
		}

		if pubkey.X.Cmp(pubkey.Curve.Params().P) >= 0 {
			return nil, fmt.Errorf("pubkey X parameter is >= to P")
		}
		if pubkey.Y.Cmp(pubkey.Curve.Params().P) >= 0 {
			return nil, fmt.Errorf("pubkey Y parameter is >= to P")
		}
		if !pubkey.Curve.IsOnCurve(pubkey.X, pubkey.Y) {
			return nil, fmt.Errorf("pubkey isn't on secp256k1 curve")
		}

	case PubKeyBytesLenCompressed:
		// format is 0x2 | solution, <X coordinate>
		// solution determines which solution of the curve we use.
		/// y^2 = x^3 + Curve.B
		if format != pubkeyCompressed {
			return nil, fmt.Errorf("invalid magic in compressed "+
				"pubkey string: %d", pubKeyStr[0])
		}
		pubkey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubkey.Y, err = decompressPoint(curve, pubkey.X, ybit)
		if err != nil {
			return nil, err
		}

	default: // wrong!
		return nil, fmt.Errorf("invalid pub key length %d",
			len(pubKeyStr))
	}

	return &pubkey, nil
}

// HexToPubKey 哈希字符串转换secp256k1公钥
func HexToPubKey(hexkey string) (*PublicKey, error) {
	b, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, errors.New("invalid hex string")
	}
	return UnmarshalPubkey(b)
}

// UnmarshalPubkey 将[]byte转换为secp256k1公钥
func UnmarshalPubkey(pub []byte) (*PublicKey, error) {
	x, y := elliptic.Unmarshal(ecc.S256(), pub)
	if x == nil {
		return nil, errors.New("invalid secp256k1 public key")
	}
	return &PublicKey{Curve: ecc.S256(), X: x, Y: y}, nil
}

// paddedAppend 将src字节片追加到dst，返回新的片。如果源的长度小于传递的大小，则在添加src之前先将前置零字节附加到dst片。
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// PubkeyToAddress 公钥转地址方法
func (p *PublicKey) ToAddress() ETHAddress {
	pubBytes := p.FromECDSAPub()
	i := sha3.Keccak256(pubBytes[1:])[12:]
	return BytesToAddress(i)
}
