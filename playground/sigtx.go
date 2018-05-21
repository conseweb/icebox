package main

import (
	"encoding/hex"
	"fmt"

	"github.com/conseweb/btcd/btcec"
	"github.com/conseweb/btcd/chaincfg"
	"github.com/conseweb/btcd/chaincfg/chainhash"
	"github.com/conseweb/btcd/txscript"
	"github.com/conseweb/btcd/wire"
	"github.com/conseweb/btcutil"
	"bytes"
)

// createFakeOriginTx creates a fake coinbase transaction that is used in the
// example as a stand-in for what ordinarily be the real transaction that is
// being spent.
func createFakeOriginTx(addr btcutil.Address) (*wire.MsgTx, error) {
	tx := wire.NewMsgTx(wire.TxVersion)
	prevOut := wire.NewOutPoint(&chainhash.Hash{}, ^uint32(0))
	txIn := wire.NewTxIn(prevOut, []byte{txscript.OP_0, txscript.OP_0}, nil)
	tx.AddTxIn(txIn)

	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}
	txOut := wire.NewTxOut(100000000, pkScript)
	tx.AddTxOut(txOut)
	return tx, nil
}

func main() {
	// Ordinarily the private key would come from whatever storage mechanism
	// is being used, but for this example just hard code it.
	privKeyBytes, err := hex.DecodeString("22a47fa09a223f2aa079edf85a7c2" +
		"d4f8720ee63e502ee2869afab7de234b80c")
	if err != nil {
		fmt.Println(err)
		return
	}
	privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	addr, err := btcutil.NewAddressPubKey(pubKey.SerializeCompressed(),
		&chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return
	}

	// For this example, create a fake transaction that represents what
	// would ordinarily be the real transaction that is being spent.  It
	// contains a single output that pays to address in the amount of 1 BTC.
	originTx, err := createFakeOriginTx(addr.AddressPubKeyHash())
	if err != nil {
		fmt.Println(err)
		return
	}

	originTxHash := originTx.TxHash()
	// Create the transaction to redeem the fake transaction.
	redeemTx := wire.NewMsgTx(wire.TxVersion)
	// prevOut := wire.NewOutPoint(&chainhash.Hash{}, ^uint32(0))

	// Add the input(s) the redeeming transaction will spend.  There is no
	// signature script at this point since it hasn't been created or signed
	// yet, hence nil is provided for it.
	prevOut := wire.NewOutPoint(&originTxHash, 0)
	txIn := wire.NewTxIn(prevOut, nil, nil)
	redeemTx.AddTxIn(txIn)

	// Ordinarily this would contain that actual destination of the funds,
	// but for this example don't bother.
	txOut := wire.NewTxOut(0, nil)
	redeemTx.AddTxOut(txOut)

	// Sign the redeeming transaction.
	lookupKey := func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
		// Ordinarily this function would involve looking up the private
		// key for the provided address, but since the only thing being
		// signed in this example uses the address associated with the
		// private key from above, simply return it with the compressed
		// flag set since the address is using the associated compressed
		// public key.
		//
		// NOTE: If you want to prove the code is actually signing the
		// transaction properly, uncomment the following line which
		// intentionally returns an invalid key to sign with, which in
		// turn will result in a failure during the script execution
		// when verifying the signature.
		//
		// privKey.D.SetInt64(12345)
		//
		return privKey, true, nil
	}
	// Notice that the script database parameter is nil here since it isn't
	// used.  It must be specified when pay-to-script-hash transactions are
	// being signed.
	sigScript, err := txscript.SignTxOutput(&chaincfg.MainNetParams,
		redeemTx, 0, originTx.TxOut[0].PkScript, txscript.SigHashAll,
		txscript.KeyClosure(lookupKey), nil, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	redeemTx.TxIn[0].SignatureScript = sigScript

	// Print the scripts involved for illustrative purposes.
	pkScriptDisasm, _ := txscript.DisasmString(originTx.TxOut[0].PkScript)
	sigScriptDisasm, _ := txscript.DisasmString(redeemTx.TxIn[0].SignatureScript)
	fmt.Println("pkScript:", pkScriptDisasm)
	fmt.Println("sigScript:", sigScriptDisasm)

	// Prove that the transaction has been validly signed by executing the
	// script pair.
	flags := txscript.ScriptBip16 | txscript.ScriptVerifyDERSignatures |
		txscript.ScriptStrictMultiSig |
		txscript.ScriptDiscourageUpgradableNops
	vm, err := txscript.NewEngine(originTx.TxOut[0].PkScript, redeemTx, 0,
		flags, nil, nil, -1)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := vm.Execute(); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Transaction successfully signed")
	//redeemTx.

	var signedTx bytes.Buffer
	//newTx.Serialize(&unsignedTx)
	redeemTx.Serialize(&signedTx)
	fmt.Printf("Signed Tx: %s\n", hex.EncodeToString(signedTx.Bytes()))
}
