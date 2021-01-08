package ecdsa

import "testing"

// 公钥加密私钥解密
func TestPublicKey_Encrypt(t *testing.T) {
	data := "962a3216577de604a0a44086e78960263131b05b92f5ccd3b1d494acf05d3057"
	prv, pub := GenerateKey()
	encrypt, err := pub.Encrypt([]byte(data))
	if err != nil {
		t.Fatal("公钥加密失败：", err)
	}

	out, err := prv.Decrypt(encrypt)
	if err != nil {
		t.Fatal("私钥解密失败：", err)
	}
	t.Log(string(out))
}