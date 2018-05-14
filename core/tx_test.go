package core

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"fmt"
	"encoding/hex"
	"conseweb.com/wallet/icebox/coinutil/base58"
	"conseweb.com/wallet/icebox/core/env"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
)

type tx_test struct {
	privateKey     string	// hex
	publicKey      string	// hex
	base58FromAddr string		// base58
	inputTxHash    string
	inputTxIdx     uint32
	base58ToAddr   string
	amountSatoshis uint64
	hexScriptSig   string
	rawTx          string
}

const (
	// 19 76 a9 14 dd6cce9f255a8cc17bda8ba0373df8e861cb866e 88 ac
	scriptTemplate = "76a914%s88ac"
)

// key size should be divided by 8
var tx_tests = []tx_test{
	// testnet3
	{
		"68855a72a1e728d332025f5813ef35e8a6c1a8f5fb43e610c149b782ee290538",
		"0259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c",
		"mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse",
		"3ef58f2581ed01ab1ba231aeb77846d3340367e651fa6bb1022cdc2790e0698f",
		0,
		"msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb",
		64990000,
		scriptTemplate,
		"01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e000000001976a914e20b2d724ff385e3172b07bad14187c682f8b22e88acffffffff0130abdf03000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000",
	},
	// amount changed
	{
		"68855a72a1e728d332025f5813ef35e8a6c1a8f5fb43e610c149b782ee290538",
		"0259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c",
		"mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse",
		"3ef58f2581ed01ab1ba231aeb77846d3340367e651fa6bb1022cdc2790e0698f",
		0,
		"msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb",
		65000000,
		scriptTemplate,
		"01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e000000001976a914e20b2d724ff385e3172b07bad14187c682f8b22e88acffffffff0130abdf03000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000",
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

func TestCreateRawTransaction(t *testing.T) {
	Convey(`createRawTransaction should working.`, t, func() {

		inputTxHash := tx_tests[0].inputTxHash
		inputTxIdx := tx_tests[0].inputTxIdx
		base58ToAddr := tx_tests[0].base58ToAddr
		amountSatoshis := tx_tests[0].amountSatoshis
		base58FromAddr := tx_tests[0].base58FromAddr
		byteScriptSig := createScriptPubKey(base58FromAddr)
		logger.Debug().Msgf("%s, %s", base58FromAddr, hex.EncodeToString(byteScriptSig))
		sig := createRawTransaction(inputTxHash, inputTxIdx, base58ToAddr, amountSatoshis, byteScriptSig)
		So(hex.EncodeToString(sig), ShouldEqual, tx_tests[0].rawTx)
	})
}
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