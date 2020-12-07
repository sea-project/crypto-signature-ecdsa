package ecdsa

import (
	"encoding/hex"
	sha3 "github.com/sea-project/crypto-hash-sha3"
	bytes "github.com/sea-project/stdlib-bytes"
	"math/big"
	"testing"
)

func Test_SEASign(t *testing.T) {
	prikey, err := HexToPrvKey("84bddb7a58350d555191602200116174c21df108645daf4fb7d642b8bc4b2c37")
	if err != nil {
		t.Log(err)
	}
	chainID := "2"
	from := "sea390000snrrd7durhsdsgpobyh28u2fmof5yr5"
	to := "sea46ffffr5n4zm9knbedri4d9p0y7mn3dv22rbs"
	input := "transfer,sea960000mphh0oajsmpi062c6nw5alhb7bq0888,1"
	timestampStr := "1606126390084077300"
	hash := sha3.Keccak256(bytes.BytesCombine([]byte(chainID), []byte(from), []byte(to), []byte(input), []byte(timestampStr)))
	sig, err := SEASign(hash, prikey)
	if err != nil {
		t.Log(err)
	}
	t.Log(sig)
}

func Test_ETHSign(t *testing.T) {
	prikey, err := HexToPrvKey("e39f8ec10d86468d2f2695cfae962c534bbcc8efb192592ecb9987895d5e94e2")
	if err != nil {
		t.Log(err)
	}
	transaction := NewETHTX(3, HexToAddress("0x98b8b94469eb979b437273b05c58a606fdccbccb"), big.NewInt(0), 100000, big.NewInt(0), []byte("0x0"))
	hash := transaction.SignHash(171222)
	sig, err := ETHSign(hash, prikey)
	if err != nil {
		t.Log(err)
	}
	t.Log(sig)
	sigByte, err := hex.DecodeString(sig)
	r, s, v := SignToRSV(sigByte, 171222)
	t.Log("r:", r, "s:", s, "v", v)
	transaction.R = r
	transaction.S = s
	transaction.V = v

	txParam, err := transaction.RawTx()
	if err != nil {
		t.Log(err)
	}
	t.Log(hex.EncodeToString(txParam))
	txhash, _ := transaction.Hash()
	t.Log(hex.EncodeToString(txhash[:]))
}

func Test_BTCSign(t *testing.T) {
	// 1、查询from未花费输出是否
	// 2、添加output
	// 3、计算手续费
	// 4、找零金额
	// 5、拼接交易
	/*	unspends := []Unspent{
		{
			TxID:         "22c2926449ea33fe602d75621b5b8b88624bdc7c5613630305ca74d252edce93",
			Vout:         0,
			Address:      "my3d1YZVPnsBsWpRepfts6KYLW5WTyazPB",
			ScriptPubKey: "2102e32ad9b15e6646fd2da058d75ee3625f97d20b4a51b1b238c6215b0877f761f7ac",
			Amount:       12.5,
			Spendable:    true,
		},
		{
			TxID:         "1c7be4cc3db75fa257b2fd7ce5b799747785cb372e2f814f6e33bcad7d68de50",
			Vout:         0,
			Address:      "my3d1YZVPnsBsWpRepfts6KYLW5WTyazPB",
			ScriptPubKey: "2102e32ad9b15e6646fd2da058d75ee3625f97d20b4a51b1b238c6215b0877f761f7ac",
			Amount:       12.5,
			Spendable:    true,
		},
	}*/
	//vin :
	//a := estimateFee(1,2,442.478)
}
