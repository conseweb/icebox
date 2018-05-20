package core

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"fmt"
	"encoding/hex"
	"github.com/conseweb/coinutil/base58"
	"github.com/conseweb/icebox/core/env"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/conseweb/icebox/common"
	"github.com/conseweb/coinutil"
)

type tx_test struct {
	private        string // hex
	wif            string // WIF private
	public         string // hex
	address        string // base58 from address
	inputTxHash    string
	inputTxIdx     uint32
	base58ToAddr   string
	amountSatoshis uint64
	hexScriptSig   string
	rawTx          string
	signedTx	   string
	resultTxHash   string
}

const (
	// 19 76 a9 14 dd6cce9f255a8cc17bda8ba0373df8e861cb866e 88 ac
	scriptTemplate = "76a914%s88ac"
)

// key size should be divided by 8
var tx_tests = []tx_test{
	// testnet3 working and validated
	{
		"68855a72a1e728d332025f5813ef35e8a6c1a8f5fb43e610c149b782ee290538",
		"cR5soFTPrbdDiFRehXFRwzC8gKvETa2roa2ApN5pxRbK8tfQYbQP",
		"0259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c", // compressed public key
		"mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse",	// compressed public key
		"3ef58f2581ed01ab1ba231aeb77846d3340367e651fa6bb1022cdc2790e0698f",
		0,
		"msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb",
		64990000,
		scriptTemplate,
		"01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e000000001976a914b644cf69fcc76fef6db694e671316e55a1a2e0b288acffffffff0130abdf03000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000",
		"01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e000000006a47304402202230eb38890dbde121b4c0deee44a53adac32f891792bdb46f27fac437d15fa5022045250ef5cf5a8d62135b5995903c8a1c19fa270ce42b17c13cfe884f2a1d52ea01210259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8cffffffff0130abdf03000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000",
		"c5a08c595b47c0be165aeb297505c82c7cb6c4a6293eb4c9c99c7e7cca86de7f", // 中间结果的hash: "9d5f89bd7855e6dcfb0fb7aef8b4748d7b3082f313e88eb7936b19c95de454d9", 使用中间结果(rawTx)的hash计算的sig
	},
	// amount changed
	{
		"68855a72a1e728d332025f5813ef35e8a6c1a8f5fb43e610c149b782ee290538",
		"cR5soFTPrbdDiFRehXFRwzC8gKvETa2roa2ApN5pxRbK8tfQYbQP",
		"0259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c",
		"mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse",
		"3ef58f2581ed01ab1ba231aeb77846d3340367e651fa6bb1022cdc2790e0698f",
		0,
		"msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb",
		65000000,
		scriptTemplate,
		"01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e000000001976a914e20b2d724ff385e3172b07bad14187c682f8b22e88acffffffff0130abdf03000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000",
		"",
		"",
	},
	{
		"6400191867352c57123318dc15875fc0bf8b3104ba9b28a2018a35f6366af71f",
		"cQw68iYNJeFhcU4x8qs9gP2Aka9s2Q6vL8Lq9XqA3bPetNZziFKC",
		"0340ac2087db1b455ecb498dc1dbfff5e9977b1a4634a7e6c68e72e666f31d5627",
		"mwWfd7p3NYz7wVqiQCnwkk4WXRCMGqwJqX",
		"",
		0,
		"mwWfd7p3NYz7wVqiQCnwkk4WXRCMGqwJqX",
		650000,
		scriptTemplate,
		"",
		"010000000158467395b8ce5365df91968b9dbe52b1449ceca4b9ad4edc490ad6b8ecc4c332010000006b483045022100fc8c31f256b0cbb757e5c661d94cde5e2bfe4603d7d9474bd1bf21ffa198c59c022018e5fb2d3f7ae220bf9e83f6b4885fc9469ba2e50bf2555dbad98bb86dc3cf9601210259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8cffffffff02c0e1e400000000001976a914af741895ba6bd639c1656dfca4f345fb6a25dce188ac0191a805000000001976a914b644cf69fcc76fef6db694e671316e55a1a2e0b288ac00000000",
		"",
	},
}


func TestCreateScriptPubKey(t *testing.T) {
	Convey(`createScriptPubKey should be working.`, t, func() {

		base58DestAddr := tx_tests[0].base58ToAddr
		x, _, err := base58.CheckDecode(base58DestAddr)
		So(err, ShouldBeEmpty)
		script := createScriptPubKey(base58DestAddr)
		So(hex.EncodeToString(script), ShouldEqual, fmt.Sprintf(scriptTemplate, hex.EncodeToString(x)))
		//So(hex.EncodeToString(script), ShouldEqual, fmt.Sprintf(scriptTemplate, hex.EncodeToString([]byte(addr.String()))))
	})
}

func TestCreateScriptPubKey2(t *testing.T) {
	Convey(`createScriptPubKey and PayToAddrScript should be working.`, t, func() {

		base58DestAddr := tx_tests[0].base58ToAddr
		net := env.RTEnv.GetNet()
		addr, err := btcutil.DecodeAddress(base58DestAddr, net)
		So(err, ShouldBeEmpty)
		script := createScriptPubKey(base58DestAddr)
		So(hex.EncodeToString(script), ShouldEqual, fmt.Sprintf(scriptTemplate, hex.EncodeToString([]byte(addr.ScriptAddress()))))
	})
}

func TestCreateScriptPubKey3(t *testing.T) {
	Convey(`createScriptPubKey and PayToAddrScript should return same result.`, t, func() {

		base58DestAddr := tx_tests[0].base58ToAddr
		net := env.RTEnv.GetNet()
		addr, err := btcutil.DecodeAddress(base58DestAddr, net)
		So(err, ShouldBeEmpty)

		script := createScriptPubKey(base58DestAddr)

		pks, err := txscript.PayToAddrScript(addr)
		So(err, ShouldBeEmpty)
		So(hex.EncodeToString(script), ShouldEqual, hex.EncodeToString(pks))
	})
}

func TestKeys(t *testing.T) {
	Convey(`WIF decode should working.`, t, func() {
		s := newHelper()
		subKey, _ := s.generateSubPrivKey(1, 1671493468, common.Test_password)
		xk, _ := subKey.ECPrivKey()
		So(hex.EncodeToString(xk.Serialize()), ShouldEqual, tx_tests[0].private)
		net := env.RTEnv.GetNet()
		wif1, err := btcutil.NewWIF(xk, net, true)
		So(err, ShouldBeEmpty)
		So(wif1.String(), ShouldEqual, tx_tests[0].wif)

		wif2, err := btcutil.DecodeWIF(wif1.String())
		So(err, ShouldBeEmpty)
		So(hex.EncodeToString(wif2.PrivKey.Serialize()), ShouldEqual, tx_tests[0].private)
		pubK := wif2.PrivKey.PubKey()
		So(hex.EncodeToString(pubK.SerializeCompressed()), ShouldEqual, tx_tests[0].public)
		// decode source public key
		addresspubkey, err := btcutil.NewAddressPubKey(pubK.SerializeCompressed(), net)
		So(err, ShouldBeEmpty)
		base58FromAddr := addresspubkey.EncodeAddress()
		So(base58FromAddr, ShouldEqual, tx_tests[0].address)
	})
}

func TestCreateRawTransaction(t *testing.T) {
	Convey(`createRawTransaction should working.`, t, func() {

		inputTxHash := tx_tests[0].inputTxHash
		inputTxIdx := tx_tests[0].inputTxIdx
		base58ToAddr := tx_tests[0].base58ToAddr
		amountSatoshis := tx_tests[0].amountSatoshis
		base58FromAddr := tx_tests[0].address
		byteScriptSig := createScriptPubKey(base58FromAddr)
		logger.Debug().Msgf("%s, %s", base58FromAddr, hex.EncodeToString(byteScriptSig))
		sig := createRawTransaction(inputTxHash, inputTxIdx, base58ToAddr, amountSatoshis, byteScriptSig)
		So(hex.EncodeToString(sig), ShouldEqual, tx_tests[0].rawTx)
	})
}

func TestCreateRawTransactionWithUnCompressedFromAddr(t *testing.T) {
	Convey(`createRawTransaction should working.`, t, func() {

		inputTxHash := tx_tests[0].inputTxHash
		inputTxIdx := tx_tests[0].inputTxIdx
		base58ToAddr := tx_tests[0].base58ToAddr
		amountSatoshis := tx_tests[0].amountSatoshis
		base58FromAddr := tx_tests[0].address
		byteScriptSig := createScriptPubKey(base58FromAddr)
		//logger.Debug().Msgf("%s, %s", address, hex.EncodeToString(byteScriptSig))
		sig := createRawTransaction(inputTxHash, inputTxIdx, base58ToAddr, amountSatoshis, byteScriptSig)
		So(hex.EncodeToString(sig), ShouldEqual, tx_tests[0].rawTx)
	})
}

func TestDecoceWif(t *testing.T) {
	Convey(`Decode WIF should working.`, t, func() {
		wif, err := coinutil.DecodeWIF(tx_tests[0].wif)
		So(err, ShouldBeEmpty)
		So(hex.EncodeToString(wif.PrivKey.Serialize()), ShouldEqual, tx_tests[0].private)
		pubK := wif.PrivKey.PubKey()
		So(hex.EncodeToString(pubK.SerializeCompressed()), ShouldEqual, tx_tests[0].public)
		net := env.RTEnv.GetNet()
		// decode source public key
		addresspubkey, err := btcutil.NewAddressPubKey(pubK.SerializeCompressed(), net)
		So(err, ShouldBeEmpty)
		base58FromAddr := addresspubkey.EncodeAddress()
		So(base58FromAddr, ShouldEqual, tx_tests[0].address)
	})
}

func TestSignedTxHash(t *testing.T) {
	Convey(`Create double hash should working.`, t, func() {

		inputTxHash := tx_tests[0].inputTxHash
		inputTxIdx := tx_tests[0].inputTxIdx
		base58ToAddr := tx_tests[0].base58ToAddr
		amountSatoshis := tx_tests[0].amountSatoshis
		base58FromAddr := tx_tests[0].address
		byteScriptSig := createScriptPubKey(base58FromAddr)
		//logger.Debug().Msgf("%s, %s", address, hex.EncodeToString(byteScriptSig))
		rawTx := createRawTransaction(inputTxHash, inputTxIdx, base58ToAddr, amountSatoshis, byteScriptSig)
		So(hex.EncodeToString(rawTx), ShouldEqual, tx_tests[0].rawTx)
		//txHash := DoubleHash256(rawTx)
	})
}

func TestSignature(t *testing.T) {
	Convey(`Ecc signature should working.`, t, func() {
		wif, err := coinutil.DecodeWIF(tx_tests[0].wif)
		So(err, ShouldBeEmpty)
		So(hex.EncodeToString(wif.PrivKey.Serialize()), ShouldEqual, tx_tests[0].private)
		pubK := wif.PrivKey.PubKey()
		So(hex.EncodeToString(pubK.SerializeCompressed()), ShouldEqual, tx_tests[0].public)
		net := env.RTEnv.GetNet()
		// decode source public key
		addresspubkey, err := btcutil.NewAddressPubKey(pubK.SerializeCompressed(), net)
		So(err, ShouldBeEmpty)
		address := addresspubkey.EncodeAddress()
		So(address, ShouldEqual, tx_tests[0].address)

	})
}

//func TestCreateScriptSig(t *testing.T) {
//	Convey(`createScriptSig should working.`, t, func() {
//
//		inputTxHash := tx_tests[0].inputTxHash
//		inputTxIdx := tx_tests[0].inputTxIdx
//		base58ToAddr := tx_tests[0].base58ToAddr
//		amountSatoshis := tx_tests[0].amountSatoshis
//		address := tx_tests[0].address
//		byteScriptSig := createScriptPubKey(address)
//		rawTx := createRawTransaction(inputTxHash, inputTxIdx, base58ToAddr, amountSatoshis, byteScriptSig)
//		So(hex.EncodeToString(rawTx), ShouldEqual, tx_tests[0].rawTx)
//		wif, err := coinutil.DecodeWIF(tx_tests[0].wif)
//		So(err, ShouldBeEmpty)
//		sig, hash, err := createScriptSig(rawTx, *wif.PrivKey, true)
//		So(err, ShouldBeEmpty)
//
//	})
//}

// actual
// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// ffffffff
// 01
// 30abdf0300000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// 00000000

// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 19 76 a9 14 b644cf69fcc76fef6db694e671316e55a1a2e0b2 88 ac
// ffffffff
// 01
// 30abdf0300000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// 00000000


// expected:
// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 19 76 a9 14 e20b2d724ff385e3172b07bad14187c682f8b22e 88 ac
// ffffffff
// 01
// 30abdf0300000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// 00000000

// 76 a9 14 e20b2d724ff385e3172b07bad14187c682f8b22e 88 ac

// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 19 76 a9 14 b644cf69fcc76fef6db694e671316e55a1a2e0b2 88 ac
// ffffffff
// 01
// 30abdf0300000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// 00000000

// 01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e000000001976a914b644cf69fcc76fef6db694e671316e55a1a2e0b288acffffffff0130abdf03000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000


// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 19 76 a9 14 b644cf69fcc76fef6db694e671316e55a1a2e0b2 88 ac
// ffffffff
// 01
// 30abdf0300000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// 00000000

// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 84
// 41
// 955ec3fe1a8393e19e746dc8278faa674a93913f21b4a73e8e05e2872c53a63dcf591736a16e8b0bacb1e1d9472d81f7c137b628c13c1b5c18fb98815cc1389701
// 41
// 0459c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c0b8424f2fa6398404927fcf6b5b492e7fc508b7950ed8e84ce6c01ecff71828c
// ffffffff
// 01
// 30abdf0300000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// 00000000

// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 64
// 41
// ee57686955886b9a6d90f9d561164aa8986d8e41c45fd175f0b4313784ade2f03f038e37a14e64de6682f9013875cfc6427ac1477c50208083a9d95002f3d7b1 01
// 21
// 0259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c
// ffffffff
// 01
// 30abdf0300000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// 00000000

// working version
// go run signer.go 9d5f89bd7855e6dcfb0fb7aef8b4748d7b3082f313e88eb7936b19c95de454d9 68855a72a1e728d332025f5813ef35e8a6c1a8f5fb43e610c149b782ee290538
// 304402202230eb38890dbde121b4c0deee44a53adac32f891792bdb46f27fac437d15fa5022045250ef5cf5a8d62135b5995903c8a1c19fa270ce42b17c13cfe884f2a1d52ea
// bx tx-decode -f json 01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e000000006a47304402202230eb38890dbde121b4c0deee44a53adac32f891792bdb46f27fac437d15fa5022045250ef5cf5a8d62135b5995903c8a1c19fa270ce42b17c13cfe884f2a1d52ea01210259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8cffffffff0130abdf03000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000
//{
//	"transaction": {
//		"hash": "c5a08c595b47c0be165aeb297505c82c7cb6c4a6293eb4c9c99c7e7cca86de7f",
//		"inputs": [
//			{
//				"address_hash": "b644cf69fcc76fef6db694e671316e55a1a2e0b2",
//				"previous_output": {
//					"hash": "3ef58f2581ed01ab1ba231aeb77846d3340367e651fa6bb1022cdc2790e0698f",
//					"index": "0"
//				},
//				"script": "[304402202230eb38890dbde121b4c0deee44a53adac32f891792bdb46f27fac437d15fa5022045250ef5cf5a8d62135b5995903c8a1c19fa270ce42b17c13cfe884f2a1d52ea01] [0259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c]",
//				"sequence": "4294967295"
//			}
//		],
//		"lock_time": "0",
//		"outputs": [
//			{
//				"address_hash": "82e81438d7fa15ce205a9683dc786c241bc820f2",
//				"script": "dup hash160 [82e81438d7fa15ce205a9683dc786c241bc820f2] equalverify checksig",
//				"value": "64990000"
//			}
//		],
//		"version": "1"
//	}
//}

// 01000000
// 01
// 58467395b8ce5365df91968b9dbe52b1449ceca4b9ad4edc490ad6b8ecc4c332
// 01000000
// 6b
// 48
// 3045022100fc8c31f256b0cbb757e5c661d94cde5e2bfe4603d7d9474bd1bf21ffa198c59c022018e5fb2d3f7ae220bf9e83f6b4885fc9469ba2e50bf2555dbad98bb86dc3cf9601
// 21
// 0259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c
// ffffffff
// 02
// c0e1e40000000000
// 19 76 a9 14 af741895ba6bd639c1656dfca4f345fb6a25dce1 88 ac
// 0191a80500000000
// 19 76 a9 14 b644cf69fcc76fef6db694e671316e55a1a2e0b2 88 ac
// 00000000

//signture test
// ./signer 9d5f89bd7855e6dcfb0fb7aef8b4748d7b3082f313e88eb7936b19c95de454d9 68855a72a1e728d332025f5813ef35e8a6c1a8f5fb43e610c149b782ee290538
// 304402202230eb38890dbde121b4c0deee44a53adac32f891792bdb46f27fac437d15fa5022045250ef5cf5a8d62135b5995903c8a1c19fa270ce42b17c13cfe884f2a1d52ea