package core

import (
	"bytes"
	"encoding/hex"
	"github.com/conseweb/btcd/chaincfg/chainhash"
	"github.com/conseweb/btcd/txscript"
	"github.com/conseweb/btcd/wire"
	"github.com/conseweb/coinutil"
	"github.com/conseweb/icebox/core/env"
	"github.com/prettymuchbryce/hellobitcoin/base58check"
	"encoding/binary"
	"github.com/conseweb/btcd/btcec"
	"github.com/conseweb/btcutil"
)

type utxo struct {
	Address     string
	TxID        string
	OutputIndex uint32
	Script      string
	Satoshis    int64
	Height      int64
}

type Transaction struct {
	TxId               string `json:"txid"`
	SourceAddress      string `json:"source_address"`
	DestinationAddress string `json:"dest_address"`
	Amount             int64  `json:"amount"`
	UnsignedTx         string `json:"unsignedtx"`
	SignedTx           string `json:"signedtx"`
}

type TxOutput struct {
	value uint64
	address string
}

func (x *TxOutput) Get() (uint64, string) {
	return x.value, x.address
}

type TxInput struct {
	prev_hash 		[]byte  // prev_hash's bytes, not hex string
	output_index 	uint32
}

func (in *TxInput) Get() ([]byte, uint32) {
	return in.prev_hash, in.output_index
}

func createScriptPubKey(publicKeyBase58 string) []byte {
	publicKeyBytes := base58check.Decode(publicKeyBase58)

	var scriptPubKey bytes.Buffer
	scriptPubKey.WriteByte(byte(118))                 	//OP_DUP 			hex=76
	scriptPubKey.WriteByte(byte(169))                 	//OP_HASH160 		hex=a9
	scriptPubKey.WriteByte(byte(len(publicKeyBytes))) 	//PUSH				hex=14 dec=20
	scriptPubKey.Write(publicKeyBytes)
	scriptPubKey.WriteByte(byte(136)) 					//OP_EQUALVERIFY	hex=88
	scriptPubKey.WriteByte(byte(172)) 					//OP_CHECKSIG		hex=ac
	return scriptPubKey.Bytes()
}

func sign(private, data []byte) ([]byte, error) {
	privkey, _ := btcec.PrivKeyFromBytes(btcec.S256(), private)
	sig, err := privkey.Sign(data)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func reverseByteOrder(inputBytes []byte) []byte {
	inputBytesReversed := make([]byte, len(inputBytes))
	for i := 0; i < len(inputBytes); i++ {
		inputBytesReversed[i] = inputBytes[len(inputBytes)-i-1]
	}
	return inputBytesReversed
}

// createScriptSig
// createUnlockScript
// createScriptSig
func createScriptSig(rawTransaction []byte, privateKey *btcec.PrivateKey, compressed bool) (rawTxHash, rawTxSig []byte, err error) {
	//Here we start the process of signing the raw transaction.
	//Hash the raw transaction twice before the signing
	rawTxHash = DoubleHash256(rawTransaction)

	//Sign the raw transaction
	signedTx, err := sign(privateKey.Serialize(), rawTxHash)
	if err != nil {
		logger.Fatal().Err(err).Msgf("ecdsa.Sign")
		return nil, nil, err
	}

	hashCodeType, err := hex.DecodeString("01")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
		return nil, nil, err
	}

	//+1 for hashCodeType
	signedTxLength := byte(len(signedTx) + 1)

	pubK := privateKey.PubKey()
	var publicKeyBytes []byte
	if compressed {
		publicKeyBytes = pubK.SerializeCompressed()
	} else {
		publicKeyBytes = pubK.SerializeUncompressed()
	}

	var publicKeyBuffer bytes.Buffer
	publicKeyBuffer.Write(publicKeyBytes)
	pubKeyLength := byte(len(publicKeyBuffer.Bytes()))

	var buffer bytes.Buffer
	buffer.WriteByte(signedTxLength)
	buffer.Write(signedTx)
	buffer.WriteByte(hashCodeType[0])
	buffer.WriteByte(pubKeyLength)
	buffer.Write(publicKeyBuffer.Bytes())

	rawTxSig = buffer.Bytes()

	return rawTxHash, rawTxSig, nil
}

func createRawTransaction(inputTxBytes []byte, inputTxIdx uint32, base58DestAddr string, satoshis uint64, scriptSig []byte) []byte {
	// Create the raw transaction.

	// Version field
	version, err := hex.DecodeString("01000000")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
	}

	//# number of Inputs (always 1 in our case)
	numInputs, err := hex.DecodeString("01")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
	}

	//Input transaction hash
	//inputTxBytes, err := hex.DecodeString(inputTxHash)
	//if err != nil {
	//	log.Fatal(err)
	//}

	//Convert input transaction hash to little-endian form
	inputTxBytesReversed := reverseByteOrder(inputTxBytes)

	//Output index of input transaction
	outputIndexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(outputIndexBytes, inputTxIdx)

	//Script sig length
	scriptSigLength := len(scriptSig)

	//sequence_no. Normally 0xFFFFFFFF. Always in this case.
	sequence, err := hex.DecodeString("ffffffff")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
	}

	//Numbers of outputs for the transaction being created. Always one in this example.
	// TODO: should add change's output
	numOutputs, err := hex.DecodeString("01")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
	}

	// Satoshis to send.
	satoshiBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(satoshiBytes, satoshis)

	//Script pub key
	scriptPubKey := createScriptPubKey(base58DestAddr)
	scriptPubKeyLength := len(scriptPubKey)

	//Lock time field
	lockTimeField, err := hex.DecodeString("00000000")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
	}

	var buffer bytes.Buffer
	buffer.Write(version)
	buffer.Write(numInputs)
	buffer.Write(inputTxBytesReversed)
	buffer.Write(outputIndexBytes)
	buffer.WriteByte(byte(scriptSigLength))
	buffer.Write(scriptSig)
	buffer.Write(sequence)
	buffer.Write(numOutputs)
	buffer.Write(satoshiBytes)
	buffer.WriteByte(byte(scriptPubKeyLength))
	buffer.Write(scriptPubKey)
	buffer.Write(lockTimeField)

	return buffer.Bytes()
}


func createRawTransaction2(input *TxInput, dest *TxOutput, change *TxOutput, scriptSig []byte) []byte {
	// Create the raw transaction.

	// Version field
	version, err := hex.DecodeString("01000000")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
	}

	//# number of Inputs (always 1 in our case)
	numInputs, err := hex.DecodeString("01")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
	}

	inputTxBytes, inputTxIdx := input.Get()

	//Input transaction hash
	//inputTxBytes, err := hex.DecodeString(inputTxHash)
	//if err != nil {
	//	log.Fatal(err)
	//}

	//Convert input transaction hash to little-endian form
	inputTxBytesReversed := reverseByteOrder(inputTxBytes)

	//Output index of input transaction
	outputIndexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(outputIndexBytes, inputTxIdx)

	//Script sig length
	scriptSigLength := len(scriptSig)

	//sequence_no. Normally 0xFFFFFFFF. Always in this case.
	sequence, err := hex.DecodeString("ffffffff")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
	}

	//Numbers of outputs for the transaction being created. Always two in this example.
	numOutputs, err := hex.DecodeString("02")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
	}

	satoshis1, base58DestAddr1 := dest.Get()
	// *************** for output 1  **************
	//Satoshis to send.
	satoshiBytes1 := make([]byte, 8)
	binary.LittleEndian.PutUint64(satoshiBytes1, satoshis1)

	//Script pub key
	scriptPubKey1 := createScriptPubKey(base58DestAddr1)
	scriptPubKeyLength1 := len(scriptPubKey1)

	satoshis2, base58DestAddr2 := change.Get()
	// *************** for output 2 == change address **************
	satoshiBytes2 := make([]byte, 8)
	binary.LittleEndian.PutUint64(satoshiBytes2, satoshis2)

	//Script pub key
	scriptPubKey2 := createScriptPubKey(base58DestAddr2)
	scriptPubKeyLength2 := len(scriptPubKey2)

	//Lock time field
	lockTimeField, err := hex.DecodeString("00000000")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
	}

	var buffer bytes.Buffer
	buffer.Write(version)
	buffer.Write(numInputs)
	buffer.Write(inputTxBytesReversed)
	buffer.Write(outputIndexBytes)
	buffer.WriteByte(byte(scriptSigLength))
	buffer.Write(scriptSig)
	buffer.Write(sequence)
	buffer.Write(numOutputs)
	buffer.Write(satoshiBytes1)
	buffer.WriteByte(byte(scriptPubKeyLength1))
	buffer.Write(scriptPubKey1)
	buffer.Write(satoshiBytes2)
	buffer.WriteByte(byte(scriptPubKeyLength2))
	buffer.Write(scriptPubKey2)
	buffer.Write(lockTimeField)

	return buffer.Bytes()
}

func CreateSignedMessage(privKey *btcec.PrivateKey, msg []byte) ([]byte, error) {

	priv := privKey.Serialize()
	signedTx, err := sign(priv, msg)
	if err != nil {
		logger.Fatal().Err(err).Msgf("CreateSignedMessage")
		return nil, err
	}

	return signedTx, nil
}


// FIXME: default should have change output
func CreateSignedTx(privKey *btcec.PrivateKey, input *TxInput, dest *TxOutput, compressed bool) (*Transaction, error) {
	var transaction Transaction
	// get source private key
	net := env.RTEnv.GetNet()

	// decode source public key
	var addresspubkey *coinutil.AddressPubKey
	if compressed {
		addresspubkey, _ = coinutil.NewAddressPubKey(privKey.PubKey().SerializeCompressed(), net)
	} else {
		addresspubkey, _ = coinutil.NewAddressPubKey(privKey.PubKey().SerializeUncompressed(), net)
	}

	//First we create the raw transaction.
	//In order to construct the raw transaction we need the input transaction hash,
	//the destination address, the number of satoshis to send, and the rawTxSig
	//which is temporarily (prior to signing) the ScriptPubKey of the input transaction.
	base58FromAddr := addresspubkey.EncodeAddress()
	tempScriptSig := createScriptPubKey(base58FromAddr)

	logger.Debug().Msgf("temp rawTxSig: %s, fromAddr: %s", hex.EncodeToString(tempScriptSig), base58FromAddr)

	amount, destination := dest.Get()
	txHash, srcIdx := input.Get()
	rawTransaction := createRawTransaction(txHash, srcIdx, destination, amount, tempScriptSig)

	//After completing the raw transaction, we append
	//SIGHASH_ALL in little-endian format to the end of the raw transaction.
	hashCodeType, err := hex.DecodeString("01000000")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
		return nil, err
	}

	var rawTransactionBuffer bytes.Buffer
	rawTransactionBuffer.Write(rawTransaction)
	rawTransactionBuffer.Write(hashCodeType)
	rawTransactionWithHashCodeType := rawTransactionBuffer.Bytes()

	//Sign the raw transaction, and output it to the console.
	rawTxHash, rawTxSig, err := createScriptSig(rawTransactionWithHashCodeType, privKey, true)
	logger.Debug().Msgf("RawTx: %s, TxID: %s", hex.EncodeToString(rawTransaction), hex.EncodeToString(rawTxHash))
	// create signed tx with scriptsig
	finalTransaction := createRawTransaction(txHash, srcIdx, destination, amount, rawTxSig)

	transaction.TxId = hex.EncodeToString(rawTxHash)
	transaction.UnsignedTx = hex.EncodeToString(rawTransaction)
	finalTransactionHex := hex.EncodeToString(finalTransaction)
	transaction.SignedTx = finalTransactionHex
	transaction.Amount = int64(amount)
	transaction.SourceAddress = base58FromAddr
	transaction.DestinationAddress = destination

	return &transaction,nil
}


func CreateSignedTx2(privKey *btcec.PrivateKey, input *TxInput, dest *TxOutput, change *TxOutput, compressed bool) (*Transaction, error) {
	var transaction Transaction
	// get source private key
	net := env.RTEnv.GetNet()

	// decode source public key
	var addresspubkey *coinutil.AddressPubKey
	if compressed {
		addresspubkey, _ = coinutil.NewAddressPubKey(privKey.PubKey().SerializeCompressed(), net)
	} else {
		addresspubkey, _ = coinutil.NewAddressPubKey(privKey.PubKey().SerializeUncompressed(), net)
	}

	//First we create the raw transaction.
	//In order to construct the raw transaction we need the input transaction hash,
	//the destination address, the number of satoshis to send, and the rawTxSig
	//which is temporarily (prior to signing) the ScriptPubKey of the input transaction.
	base58FromAddr := addresspubkey.EncodeAddress()
	tempScriptSig := createScriptPubKey(base58FromAddr)

	logger.Debug().Msgf("temp rawTxSig: %s, fromAddr: %s", hex.EncodeToString(tempScriptSig), base58FromAddr)

	amount, destination := dest.Get()
	//txHash, srcIdx := input.Get()
	rawTransaction := createRawTransaction2(input, dest, change, tempScriptSig)

	//After completing the raw transaction, we append
	//SIGHASH_ALL in little-endian format to the end of the raw transaction.
	hashCodeType, err := hex.DecodeString("01000000")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
		return nil, err
	}

	var rawTransactionBuffer bytes.Buffer
	rawTransactionBuffer.Write(rawTransaction)
	rawTransactionBuffer.Write(hashCodeType)
	rawTransactionWithHashCodeType := rawTransactionBuffer.Bytes()

	//Sign the raw transaction, and output it to the console.
	rawTxHash, rawTxSig, err := createScriptSig(rawTransactionWithHashCodeType, privKey, true)
	logger.Debug().Msgf("RawTx: %s, TxID: %s", hex.EncodeToString(rawTransaction), hex.EncodeToString(rawTxHash))
	// create signed tx with scriptsig
	finalTransaction := createRawTransaction2(input, dest, change, rawTxSig)

	transaction.TxId = hex.EncodeToString(rawTxHash)
	transaction.UnsignedTx = hex.EncodeToString(rawTransaction)
	finalTransactionHex := hex.EncodeToString(finalTransaction)
	transaction.SignedTx = finalTransactionHex
	transaction.Amount = int64(amount)
	transaction.SourceAddress = base58FromAddr
	transaction.DestinationAddress = destination

	return &transaction,nil
}


// from: utxo
// to: address, amount
// change: address
// sign: private key
func CreateTransaction(secret string, destination string, amount uint64, txHash string, srcIdx uint32) (*Transaction, error) {
	logger.Debug().Msgf("CreateTransaction: %s, %s, %d, %s, %d", secret, destination, amount, txHash, srcIdx)
	var transaction Transaction
	// get source private key
	wif, err := coinutil.DecodeWIF(secret)
	if err != nil {
		return nil, err
	}

	net := env.RTEnv.GetNet()
	pubKey := wif.PrivKey.PubKey()
	logger.Debug().Msgf("From privKey: %s, pubKey: %s", hex.EncodeToString(wif.PrivKey.Serialize()), hex.EncodeToString(pubKey.SerializeCompressed()))
	// decode source public key
	addresspubkey, err := coinutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeUncompressed(), net)
	if err != nil {
		logger.Fatal().Err(err).Msgf("coinutil.NewAddressPubKey")
		return nil, err
	}
	// create new tx == unsigned Tx
	newTx := wire.NewMsgTx(wire.TxVersion)
	sourceUtxoHash, _ := chainhash.NewHashFromStr(txHash)
	sourceUtxo := wire.NewOutPoint(sourceUtxoHash, srcIdx)
	toAddr, err := btcutil.DecodeAddress(destination, net)
	if err != nil {
		logger.Fatal().Err(err).Msgf("coinutil.DecodeAddress")
		return nil, err
	}
	fromAddr, err := btcutil.DecodeAddress(addresspubkey.String(), net)
	if err != nil {
		logger.Fatal().Err(err).Msgf("coinutil.DecodeAddress")
		return nil, err
	}
	sourcePkScript, err := txscript.PayToAddrScript(fromAddr)
	if err != nil {
		logger.Fatal().Err(err).Msgf("txscript.PayToAddrScript. fromAddr: %s", fromAddr.EncodeAddress())
		return nil, err
	}
	destinationPkScript, err := txscript.PayToAddrScript(toAddr)
	if err != nil {
		logger.Fatal().Err(err).Msgf("txscript.PayToAddrScript. toAddr: %s", toAddr.EncodeAddress())
		return nil, err
	}
	// create txin for new tx
	sourceTxIn := wire.NewTxIn(sourceUtxo, sourcePkScript, nil)

	// create txout for new tx
	sourceTxOut := wire.NewTxOut(int64(amount), destinationPkScript)
	newTx.AddTxIn(sourceTxIn)
	newTx.AddTxOut(sourceTxOut)
	newTxHash := newTx.TxHash()

	// create redeem Tx == signed Tx
	redeemTx := wire.NewMsgTx(wire.TxVersion)
	prevOut := wire.NewOutPoint(sourceUtxoHash, 0)
	redeemTxIn := wire.NewTxIn(prevOut, nil, nil)
	redeemTx.AddTxIn(redeemTxIn)
	redeemTxOut := wire.NewTxOut(int64(amount), destinationPkScript)
	redeemTx.AddTxOut(redeemTxOut)
	sigScript, err := txscript.SignatureScript(redeemTx, 0, newTx.TxOut[0].PkScript, txscript.SigHashAll, wif.PrivKey, false)
	if err != nil {
		logger.Fatal().Err(err).Msgf("txscript.SignatureScript")
		return nil, err
	}
	redeemTx.TxIn[0].SignatureScript = sigScript

	// verify tx script
	//flags := txscript.StandardVerifyFlags
	//vm, err := txscript.NewEngine(newTx.TxOut[0].PkScript, redeemTx, 0, flags, nil, nil, amount)
	//if err != nil {
	//	return Transaction{}, err
	//}
	//if err := vm.Execute(); err != nil {
	//	return Transaction{}, err
	//}

	var unsignedTx bytes.Buffer
	var signedTx bytes.Buffer
	newTx.Serialize(&unsignedTx)
	redeemTx.Serialize(&signedTx)

	logger.Debug().Msgf("Unsigned Tx: %s", hex.EncodeToString(unsignedTx.Bytes()))
	logger.Debug().Msgf("Signed Tx: %s", hex.EncodeToString(signedTx.Bytes()))
	logger.Debug().Msgf("Tx Hash: %s", newTxHash.String())

	transaction.TxId = newTxHash.String()
	transaction.UnsignedTx = hex.EncodeToString(unsignedTx.Bytes())
	transaction.Amount = int64(amount)
	transaction.SignedTx = hex.EncodeToString(signedTx.Bytes())
	transaction.SourceAddress = fromAddr.EncodeAddress()
	transaction.DestinationAddress = toAddr.EncodeAddress()
	return &transaction, nil
}

// unsigned tx:
//
// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 00
// ffffffff
// 01
// c0e1e400000000000000000000

// CreateTransaction: unsigned tx:
// 01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e0000000043410459c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c0b8424f2fa6398404927fcf6b5b492e7fc508b7950ed8e84ce6c01ecff71828cacffffffff01c0e1e400000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000
//
// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 43
// 41 dec=65
// 0459c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c0b8424f2fa6398404927fcf6b5b492e7fc508b7950ed8e84ce6c01ecff71828c
// ac
// ffffffff
// 01
// c0e1e40000000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// 00000000

// CreateTransaction - signed tx:
// 0100000001db840a8aefe7bda5b1f02c949ae6607758b2951299a1814e4afa24e06acd4ccc000000008b483045022100ad3650264e19b398d1636f476180ac189371015896384b5873d0cb907ab75f9402201d4a4db1727b4fe085e722ab05431ba8998f118135b09cc13e807e9a33d99b1601410459c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c0b8424f2fa6398404927fcf6b5b492e7fc508b7950ed8e84ce6c01ecff71828cffffffff01c0e1e400000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000
//
// 01000000
// 01
// db840a8aefe7bda5b1f02c949ae6607758b2951299a1814e4afa24e06acd4ccc
// 00000000
// 8b
// 48
// 3045022100ad3650264e19b398d1636f476180ac189371015896384b5873d0cb907ab75f9402201d4a4db1727b4fe085e722ab05431ba8998f118135b09cc13e807e9a33d99b16 01
// 41
// 0459c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c0b8424f2fa6398404927fcf6b5b492e7fc508b7950ed8e84ce6c01ecff71828c
// ffffffff
// 01
// c0e1e40000000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// 00000000


// CreateSignedTx - raw tx:
// 01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e000000001976a914e20b2d724ff385e3172b07bad14187c682f8b22e88acffffffff01c0e1e400000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000
//
//  |||
//	|||
//   V
//
// CreateSignedTx - signed tx:
//
// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 84
// 41
// a41ea0ae1ef15ba31c98f40d46a76c836af740dfef6ac82bf78e42904bebe74b2ec2f68846bd1f40f240d09f441884160ec8700f6d8cd99677eac04ca8ce2cf1 01
// 41
// 0459c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c0b8424f2fa6398404927fcf6b5b492e7fc508b7950ed8e84ce6c01ecff71828c
// ffffffff
// 01
// c0e1e40000000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// 00000000
//
//  |||
//	|||
//   V
//
// Decoded Transaction (https://live.blockcypher.com/btc/decodetx/)
//{
//	"addresses": [
//		"mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse",
//		"msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb"
//	],
//	"block_height": -1,
//	"block_index": -1,
//	"confirmations": 0,
//	"double_spend": false,
//	"fees": 50000000,
//	"hash": "fd6b4f470aa65f9b4713637ffaecb21fcf6df0f1fa3f79e72a0fd6331eb709d2",
//	"inputs": [
//		{
//			"addresses": [
//				"mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse"
//			],
//			"age": 1297102,
//			"output_index": 0,
//			"output_value": 65000000,
//			"prev_hash": "3ef58f2581ed01ab1ba231aeb77846d3340367e651fa6bb1022cdc2790e0698f",
//			"script": "41083368e1bfbf29987dfec4645285c7dcd7950b866cc1b52fcd639628e73c562add8dcb03d62ee76473074bedc4a962ff8284a714a5977a9d56400c1538c1a4f001410459c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c0b8424f2fa6398404927fcf6b5b492e7fc508b7950ed8e84ce6c01ecff71828c",
//			"script_type": "pay-to-pubkey-hash",
//			"sequence": 4294967295
//		}
//	],
//	"outputs": [
//		{
//			"addresses": [
//				"msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb"
//			],
//			"script": "76a91482e81438d7fa15ce205a9683dc786c241bc820f288ac",
//			"script_type": "pay-to-pubkey-hash",
//			"value": 15000000
//		}
//	],
//	"preference": "high",
//	"received": "2018-05-14T09:14:12.899437518Z",
//	"relayed_by": "54.224.71.237",
//	"size": 217,
//	"total": 15000000,
//	"ver": 1,
//	"vin_sz": 1,
//	"vout_sz": 1
//}

// signed tx:
//
// 0100000001ec14e766975d7ec991c313a6f9670924adbcd79b8c38859dfb7e69608016b30a000000008a47304402204af3ee6e1e6443cb5b84ad4964e4f7bc360c4742b41a01f163d90b2d11f690fc02206ba61fc16acb2355adb9bc30e457f22cd3fab6eb782e808bff7a448d888381ce01410459c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c0b8424f2fa6398404927fcf6b5b492e7fc508b7950ed8e84ce6c01ecff71828cffffffff01c0e1e400000000000000000000

// raw tx:
// 01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e000000001976a914e20b2d724ff385e3172b07bad14187c682f8b22e88acffffffff0130abdf03000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000
//
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

// signed tx:
// 01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e000000008441f5cf829daaf35775f688a43ecf17de3387089420657c5dbc6a994ea82076bbe9e1b80ca08e9e24ecc98ee9c684dbf506fc55e9801f76d289b6b001fb0d25b85d01410459c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c0b8424f2fa6398404927fcf6b5b492e7fc508b7950ed8e84ce6c01ecff71828cffffffff0130abdf03000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000
//
// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 84
// 41 	dec=65
// f5cf829daaf35775f688a43ecf17de3387089420657c5dbc6a994ea82076bbe9e1b80ca08e9e24ecc98ee9c684dbf506fc55e9801f76d289b6b001fb0d25b85d 01
// 41	dec=65
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
// 84
// 41
// 0e01210b77c264ff000a152a6a2359d815ce2b97fdd98468a91a281b37dc5819798e907adb5b8be40fd7258a16248a257afcf7f7860031e3de1a831030bba1de 01
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
// 0376a914
// ffffffff
// 01
// 30abdf0300000000
// 19 76 a9 14 82e81438d7fa15ce205a9683dc786c241bc820f2 88 ac
// 00000000