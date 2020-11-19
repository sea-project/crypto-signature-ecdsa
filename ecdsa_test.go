package ecdsa

import (
	"encoding/hex"
	ecc "github.com/sea-project/crypto-ecc-s256"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	prv, pub := GenerateKey()
	t.Log("私钥原型：", prv.ToHex())
	t.Log("公钥原型：", pub.ToHex())
	t.Log("私钥转公钥：", prv.ToPubKey().ToHex())

	pubHex := pub.ToHex()
	t.Log("公钥哈希：", pubHex)

	pubs, err := HexToPubKey(pubHex)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("公钥还原：", pubs.ToHex())

	prvHex := prv.ToHex()
	t.Log("私钥哈希：", prvHex)

	prvs, err := HexToPrvKey(prvHex)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("还原私钥：", prvs.ToHex())
}

func TestPrivateKey_Sign(t *testing.T) {
	prv, pub := GenerateKey()
	t.Log("原公钥：", pub.ToHex())
	hash := []byte("1111111111111")

	// 第一种签名
	signature, err := prv.Sign(hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("第一种签名：", signature.S, signature.R)

	isCheck := signature.Verify(hash, pub)
	t.Log(isCheck)

	// 第二种签名方式
	sign, err := SignCompact(ecc.S256(), prv, hash, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("第二种签名：", hex.EncodeToString(sign))
	t.Log("第二种签名：", len(sign))

	pubs, istrue, err := RecoverCompact(ecc.S256(), sign, hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("结果：", istrue)
	t.Log("导公钥：", pubs.ToHex())
}

// 比特币WIF转换
func Test_BTC(t *testing.T) {
	wif := "KxbF2HbMFTTfpiic6X8g5GSaKSLLqFYn5bfMquNrYwokySpqeBn8"
	prikey, err := WIFToPrvKey(wif)
	if err != nil {
		t.Log(err)
	}
	t.Log(prikey.ToHex())
	t.Log(PrvKeyToWIF(prikey, true))
}
