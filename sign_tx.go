package ecdsa

import (
	"encoding/hex"
	"fmt"
	ecc "github.com/sea-project/crypto-ecc-s256"
	"math/big"
)

// Sign calculates an ECDSA signature
func Sign(hash []byte, prv *PrivateKey) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}
	if prv.Curve != ecc.S256() {
		return nil, fmt.Errorf("private key curve is not secp256k1")
	}
	sig, err := SignCompact(ecc.S256(), (*PrivateKey)(prv), hash, false)
	if err != nil {
		return nil, err
	}
	// Convert to Ethereum signature format with 'recovery id' v at the end.
	v := sig[0] - 27
	copy(sig, sig[1:])
	sig[64] = v
	return sig, nil
}

// BTCSign 比特币交易签名
func BTCSign(msg []byte, prikey *PrivateKey) string {
	return ""
}

// ETHSign 以太坊交易签名
func ETHSign(msg []byte, prikey *PrivateKey) (string, error) {
	signature, err := Sign(msg, prikey)
	//r := new(big.Int).SetBytes(signature[:32])
	//s := new(big.Int).SetBytes(signature[32:64])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature), nil
}

// ETHUNSign 以太坊交易验签
func ETHUNSign(sign, hash []byte) (*PublicKey, error) {
	ethSig := make([]byte, 65)
	ethSig[0] = sign[64] + 27
	copy(ethSig[1:], sign)
	pub, _, err := RecoverCompact(ecc.S256(), ethSig, hash)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// SignToRSV
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
// https://www.cnblogs.com/wanghui-garcia/p/9648147.html
func SignToRSV(sign []byte, chainId int64) (r, s, v *big.Int) {
	r = new(big.Int).SetBytes(sign[:32])
	s = new(big.Int).SetBytes(sign[32:64])
	// 先加固定值27
	v = new(big.Int).SetBytes([]byte{sign[64] + 27})
	// 如果是eip155则chainId * 2 + 8
	chainIdM := (chainId << 1) + 8
	v.Add(v, big.NewInt(chainIdM))
	return r, s, v
}

// RSVToSign
func RSVToSign(r, s, v *big.Int, chainId int64) []byte {
	sig := make([]byte, 65)
	chainIdM := (chainId << 1) + 8
	v.Sub(v, big.NewInt(chainIdM))
	v.Sub(v, big.NewInt(27))
	copy(sig[:32], r.Bytes())
	copy(sig[32:64], s.Bytes())
	sig[64] = v.Bytes()[0]
	return sig
}

// SEASign sea交易签名
func SEASign(msg []byte, prikey *PrivateKey) (string, error) {

	sign, err := SignCompact(ecc.S256(), prikey, msg, true)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sign), nil
}

// SEAUNSign sea交易验签
func SEAUNSign(sign, hash []byte) (*PublicKey, error) {
	pub, _, err := RecoverCompact(ecc.S256(), sign, hash)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
