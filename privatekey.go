package ecdsa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	e "crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
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
	// 解密过程中，当消息验证检查(MAC)失败时，发生ErrInvalidMAC。这是因为无效的私钥或损坏的密文。
	errInvalidMAC = errors.New("invalid mac hash")
	// 发生在解密函数的输入密文长度小于134字节的情况下。
	errInputTooShort = errors.New("ciphertext too short")
	// 发生在加密文本的前两个字节不是0x02CA (= 712 = secp256k1，来自OpenSSL)的时候。
	errUnsupportedCurve = errors.New("unsupported curve")
	errInvalidXLength   = errors.New("invalid X length, must be 32")
	errInvalidYLength   = errors.New("invalid Y length, must be 32")
	errInvalidPadding   = errors.New("invalid PKCS#7 padding")
	
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

// Decrypt 私钥解密
func (p *PrivateKey) Decrypt(in []byte) ([]byte, error) {
	// IV + Curve params/X/Y + 1 block + HMAC-256
	if len(in) < aes.BlockSize+70+aes.BlockSize+sha256.Size {
		return nil, errInputTooShort
	}

	// read iv
	iv := in[:aes.BlockSize]
	offset := aes.BlockSize

	// start reading pubkey
	if !bytes.Equal(in[offset:offset+2], ciphCurveBytes[:]) {
		return nil, errUnsupportedCurve
	}
	offset += 2

	if !bytes.Equal(in[offset:offset+2], ciphCoordLength[:]) {
		return nil, errInvalidXLength
	}
	offset += 2

	xBytes := in[offset : offset+32]
	offset += 32

	if !bytes.Equal(in[offset:offset+2], ciphCoordLength[:]) {
		return nil, errInvalidYLength
	}
	offset += 2

	yBytes := in[offset : offset+32]
	offset += 32

	pb := make([]byte, PubKeyBytesLenUncompressed)
	pb[0] = byte(0x04) // uncompressed
	copy(pb[1:33], xBytes)
	copy(pb[33:], yBytes)
	// 检查(X, Y)是否位于曲线上，如果位于曲线上，则创建一个Pubkey
	pubkey, err := UnmarshalPubkey(pb)
	if err != nil {
		return nil, err
	}

	// 检查密码文本的长度
	if (len(in)-aes.BlockSize-offset-sha256.Size)%aes.BlockSize != 0 {
		return nil, errInvalidPadding // not padded to 16 bytes
	}

	// 生成共享密钥
	ecdhKey := GenerateSharedSecret(p, pubkey)
	derivedKey := sha512.Sum512(ecdhKey)
	keyE := derivedKey[:32]
	keyM := derivedKey[32:]

	// verify mac
	hm := hmac.New(sha256.New, keyM)
	hm.Write(in[:len(in)-sha256.Size]) // everything is hashed
	expectedMAC := hm.Sum(nil)
	messageMAC := in[len(in)-sha256.Size:]
	if !hmac.Equal(messageMAC, expectedMAC) {
		return nil, errInvalidMAC
	}

	// 开始解密
	block, err := aes.NewCipher(keyE)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(in)-offset-sha256.Size)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, in[offset:len(in)-sha256.Size])

	length := len(plaintext)
	padLength := int(plaintext[length-1])
	if padLength > aes.BlockSize || length < aes.BlockSize {
		return nil, errInvalidPadding
	}
	return plaintext[:length-padLength], nil
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
// 1 WIF：KxbF2HbMFTTfpiic6X8g5GSaKSLLqFYn5bfMquNrYwokySpqeBn8
// 2 base58解码：8028ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a349310118afa009
// 3 丢弃后四字节：8028ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a3493101
// 4 丢弃前后各一字节：28ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a34931
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
// 1 私钥：28ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a34931
// 2 前缀增加0x80，后缀增加01：8028ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a3493101
// 3 进行hash：f0722e985124f3d12e63abc8016f7c775471ff76c59143c52334b99bf0d13547
// 4 在进行hash：18afa0093fe60a479ee51ffe026900aaa4ae545a3c6d3bea0192b82e3a59bc06
// 5 取双hash结果前四个字节，加在第二步结果后面：8028ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a349310118afa009
// 6 进行base58编码：KxbF2HbMFTTfpiic6X8g5GSaKSLLqFYn5bfMquNrYwokySpqeBn8
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
	a = append(a, 0x80)
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
