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
	inputTxHash string
	inputTxIdx uint32
	base58DestAddr string
	amountSatoshis uint64
	hexScriptSig string
	result string
}

const (
	// 19 76 a9 14 dd6cce9f255a8cc17bda8ba0373df8e861cb866e 88 ac
	scriptTemplate = "76a914%s88ac"
)

// key size should be divided by 8
var tx_tests = []tx_test{
	{
		"3ef58f2581ed01ab1ba231aeb77846d3340367e651fa6bb1022cdc2790e0698f",
		0,
		"msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb",
		15000000,
		scriptTemplate,
		"",
	},
}


func TestCreateScriptPubKey(t *testing.T) {
	Convey(`createScriptPubKey should be working.`, t, func() {

		base58DestAddr := tx_tests[0].base58DestAddr
		//net := env.RTEnv.GetNet()
		//addr, _ := coinutil.DecodeAddress(base58DestAddr, net)
		x, _, err := base58.CheckDecode(base58DestAddr)
		So(err, ShouldBeEmpty)
		script := createScriptPubKey(base58DestAddr)
		So(hex.EncodeToString(script), ShouldEqual, fmt.Sprintf(scriptTemplate, hex.EncodeToString(x)))
		//So(hex.EncodeToString(script), ShouldEqual, fmt.Sprintf(scriptTemplate, hex.EncodeToString([]byte(addr.String()))))
	})
}

func TestCreateScriptPubKey2(t *testing.T) {
	Convey(`createScriptPubKey and PayToAddrScript should be working.`, t, func() {

		base58DestAddr := tx_tests[0].base58DestAddr
		net := env.RTEnv.GetNet()
		addr, err := btcutil.DecodeAddress(base58DestAddr, net)
		So(err, ShouldBeEmpty)
		script := createScriptPubKey(base58DestAddr)
		So(hex.EncodeToString(script), ShouldEqual, fmt.Sprintf(scriptTemplate, hex.EncodeToString([]byte(addr.ScriptAddress()))))
	})
}

func TestCreateScriptPubKey3(t *testing.T) {
	Convey(`createScriptPubKey and PayToAddrScript should return same result.`, t, func() {

		base58DestAddr := tx_tests[0].base58DestAddr
		net := env.RTEnv.GetNet()
		addr, err := btcutil.DecodeAddress(base58DestAddr, net)
		So(err, ShouldBeEmpty)

		script := createScriptPubKey(base58DestAddr)

		pks, err := txscript.PayToAddrScript(addr)
		So(err, ShouldBeEmpty)
		So(hex.EncodeToString(script), ShouldEqual, hex.EncodeToString(pks))
	})
}

//func TestcreateRawTransaction(t *testing.T) {
//	Convey(`createRawTransaction should first create raw tx.`, t, func() {
//
//		inputTxHash := tx_tests[0].inputTxHash
//		inputTxIdx := tx_tests[0].inputTxIdx
//		base58DestAddr := tx_tests[0].base58DestAddr
//		amountSatoshis := tx_tests[0].amountSatoshis
//		hexScriptSig, _ := hex.DecodeString(tx_tests[0].hexScriptSig)
//		sig := createRawTransaction(inputTxHash, inputTxIdx, base58DestAddr, amountSatoshis, hexScriptSig)
//		So(sig, ShouldEqual, "")
//	})
//}