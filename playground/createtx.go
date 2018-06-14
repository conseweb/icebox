package main

import (
	"bytes"
	"encoding/hex"
	"github.com/conseweb/btcd/chaincfg/chainhash"
	"github.com/conseweb/btcd/txscript"
	"github.com/conseweb/btcd/wire"
	"github.com/conseweb/btcutil"
	"log"

	"github.com/conseweb/btcd/chaincfg"
)

const (
	txFee       = 10000
	fromAddress = "mijhw2WHeqgimoTqoKMWSCRVs8XFXxk9qx"
	toAddress   = "muph2LMYEHiTUuCC9FusNJ8aWyjySJ9srB"
	fromWIF     = "5Jg5fEQHNF385G1vQunCzBAC9rKakKAqgfVuFet6DN6J32qsmnL"
)

type utxo struct {
	Address     string
	TxID        string
	OutputIndex uint32
	Script      string
	Satoshis    int64
	Height      int64
}

func main() {
	params := &chaincfg.TestNet3Params

	toAddress, err := btcutil.DecodeAddress(toAddress, params)
	if err != nil {
		log.Fatalf("invalid address: %v", err)
	}

	unspentTx := utxo{
		Address:     "mijhw2WHeqgimoTqoKMWSCRVs8XFXxk9qx",
		TxID:        "5de1f708644f269f4fd87c648cc5d67cac64ebcf5b743f5d5063a141d6a01f14",
		OutputIndex: 0,
		Script:      "76a9142351cbad27a2607960ba370dccd1400c481230fa88ac",
		Satoshis:    8125000,
		Height:      1291076,
	}

	tx := wire.NewMsgTx(wire.TxVersion)

	hash, err := chainhash.NewHashFromStr(unspentTx.TxID)
	if err != nil {
		log.Fatalf("could not get hash from transaction ID: %v", err)
	}

	outPoint := wire.NewOutPoint(hash, unspentTx.OutputIndex)

	txIn := wire.NewTxIn(outPoint, nil, nil)
	tx.AddTxIn(txIn)

	script, err := hex.DecodeString(unspentTx.Script)
	if err != nil {
		log.Fatalf("could not decode the script: %v", err)
	}

	oldTxOut := wire.NewTxOut(unspentTx.Satoshis, script)

	// Pay the minimum network fee so that nodes will broadcast the tx.
	outCoin := oldTxOut.Value - txFee

	script, err = txscript.PayToAddrScript(toAddress)
	if err != nil {
		log.Fatalf("could not get pay to address script: %v", err)
	}

	txOut := wire.NewTxOut(outCoin, script)
	tx.AddTxOut(txOut)

	wif, err := btcutil.DecodeWIF(fromWIF)
	if err != nil {
		log.Fatalf("could not decode wif: %v", err)
	}

	sig, err := txscript.SignatureScript(
		tx,                  // The tx to be signed.
		0,                   // The index of the txin the signature is for.
		txIn.PkScript,       // The other half of the script from the PubKeyHash.
		txscript.SigHashAll, // The signature flags that indicate what the sig covers.
		wif.PrivKey,         // The key to generate the signature with.
		true,                // The compress sig flag. This saves space on the blockchain.
	)
	if err != nil {
		log.Fatalf("could not generate signature: %v", err)
	}

	tx.TxIn[0].SignatureScript = sig

	log.Printf("signed raw transaction: %s", txToHex(tx))
}

func txToHex(tx *wire.MsgTx) string {
	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	tx.Serialize(buf)
	return hex.EncodeToString(buf.Bytes())
}

// signed tx
//
// 01000000
// 01
// 141fa0d641a163505d3f745bcfeb64ac7cd6c58c647cd84f9f264f6408f7e15d
// 00000000
// 6b 	dec=107
// 48 	dec=72
// 30450221009149da0c6820c13d787a18214a1af5d8e548a313389dc271b7cbd95c41d4387002202c5a4f5664f3a914c718a2199ba77ba1cc9e56f5532ecfb1fd39423853239bb7 01
// 21	dec=33 compressed public key
// 03d8bda2c82ce282a7c64c00203d668ef654294798178d8d7f483a08901cd2e09d
// ffffffff
// 01
// 38d37b0000000000
// 19 76 a9 14 9cec802c33fa0cedd8059158d657fc22fdc5708f 88 ac
// 00000000
