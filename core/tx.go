package core

import (
	"bytes"
	"encoding/hex"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"conseweb.com/wallet/icebox/coinutil"
	"conseweb.com/wallet/icebox/core/env"
	"github.com/prettymuchbryce/hellobitcoin/base58check"
	"crypto/sha256"
	"log"
	"crypto/rand"
	"encoding/binary"
	"crypto/ecdsa"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
)

type Transaction struct {
	TxId               string `json:"txid"`
	SourceAddress      string `json:"source_address"`
	DestinationAddress string `json:"dest_address"`
	Amount             int64  `json:"amount"`
	UnsignedTx         string `json:"unsignedtx"`
	SignedTx           string `json:"signedtx"`
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

// createScriptSig
// createUnlockScript
// createScriptSig
func createScriptSig(rawTransaction []byte, privateKey btcec.PrivateKey) (scriptSig, txHash []byte, err error) {
	//Here we start the process of signing the raw transaction.
	//Hash the raw transaction twice before the signing
	shaHash := sha256.New()
	shaHash.Write(rawTransaction)
	var hash []byte = shaHash.Sum(nil)

	shaHash2 := sha256.New()
	shaHash2.Write(hash)
	txHash = shaHash2.Sum(nil)[:32]

	//Sign the raw transaction
	privK := ecdsa.PrivateKey(privateKey)

	r, s, err := ecdsa.Sign(rand.Reader, &privK, txHash)
	if err != nil {
		logger.Fatal().Err(err).Msgf("ecdsa.Sign")
		return nil, nil, err
	}
	signedTx := r.Bytes()
	signedTx = append(signedTx, s.Bytes()...)

	hashCodeType, err := hex.DecodeString("01")
	if err != nil {
		logger.Fatal().Err(err).Msgf("hex.DecodeString")
		return nil, nil, err
	}

	//+1 for hashCodeType
	signedTxLength := byte(len(signedTx) + 1)

	pubK := privateKey.PubKey()
	// TODO: use compressed public key
	publicKeyBytes := pubK.SerializeUncompressed()
	var publicKeyBuffer bytes.Buffer
	publicKeyBuffer.Write(publicKeyBytes)
	pubKeyLength := byte(len(publicKeyBuffer.Bytes()))

	var buffer bytes.Buffer
	buffer.WriteByte(signedTxLength)
	buffer.Write(signedTx)
	buffer.WriteByte(hashCodeType[0])
	buffer.WriteByte(pubKeyLength)
	buffer.Write(publicKeyBuffer.Bytes())

	scriptSig = buffer.Bytes()

	return scriptSig, txHash, nil
}

func createRawTransaction(inputTxHash string, inputTxIdx uint32, base58DestAddr string, satoshis uint64, scriptSig []byte) []byte {
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
	inputTxBytes, err := hex.DecodeString(inputTxHash)
	if err != nil {
		log.Fatal(err)
	}

	//Convert input transaction hash to little-endian form
	inputTxBytesReversed := make([]byte, len(inputTxBytes))
	for i := 0; i < len(inputTxBytes); i++ {
		inputTxBytesReversed[i] = inputTxBytes[len(inputTxBytes)-i-1]
	}

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

	//Satoshis to send.
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

func CreateSignedTx(wifPrivKey string, destination string, amount uint64, txHash string, srcIdx uint32) (*Transaction, error) {
	var transaction Transaction
	// get source private key
	wif, err := coinutil.DecodeWIF(wifPrivKey)
	if err != nil {
		logger.Fatal().Err(err).Msgf("coinutil.DecodeWIF")
	}

	net := env.RTEnv.GetNet()
	// decode source public key
	addresspubkey, _ := coinutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeUncompressed(), net)

	//First we create the raw transaction.
	//In order to construct the raw transaction we need the input transaction hash,
	//the destination address, the number of satoshis to send, and the scriptSig
	//which is temporarily (prior to signing) the ScriptPubKey of the input transaction.
	base58PubAddr := addresspubkey.EncodeAddress()
	tempScriptSig := createScriptPubKey(base58PubAddr)

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
	scriptSig, txID, err := createScriptSig(rawTransactionWithHashCodeType, *wif.PrivKey)
	// create signed tx with scriptsig
	finalTransaction := createRawTransaction(txHash, srcIdx, destination, amount, scriptSig)

	transaction.TxId = hex.EncodeToString(txID)
	transaction.UnsignedTx = hex.EncodeToString(rawTransaction)
	finalTransactionHex := hex.EncodeToString(finalTransaction)
	transaction.SignedTx = finalTransactionHex
	transaction.Amount = int64(amount)
	transaction.SourceAddress = base58PubAddr
	transaction.DestinationAddress = destination

	return &transaction,nil
}


// from: utxo
// to: address, amount
// change: address
// sign: private key
func CreateTransaction(secret string, destination string, amount uint64, txHash string, srcIdx uint32) (Transaction, error) {
	logger.Debug().Msgf("CreateTransaction: %s, %s, %d, %s, %d", secret, destination, amount, txHash, srcIdx)
	var transaction Transaction
	// get source private key
	wif, err := coinutil.DecodeWIF(secret)
	if err != nil {
		return Transaction{}, err
	}

	net := env.RTEnv.GetNet()
	pubKey := wif.PrivKey.PubKey()
	logger.Debug().Msgf("From privKey: %s, pubKey: %s", hex.EncodeToString(wif.PrivKey.Serialize()), hex.EncodeToString(pubKey.SerializeCompressed()))
	// decode source public key
	addresspubkey, err := coinutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeUncompressed(), net)
	if err != nil {
		logger.Fatal().Err(err).Msgf("coinutil.NewAddressPubKey")
		return Transaction{}, err
	}
	// create new tx == unsigned Tx
	newTx := wire.NewMsgTx(wire.TxVersion)
	sourceUtxoHash, _ := chainhash.NewHashFromStr(txHash)
	sourceUtxo := wire.NewOutPoint(sourceUtxoHash, srcIdx)
	toAddr, err := coinutil.DecodeAddress(destination, net)
	if err != nil {
		logger.Fatal().Err(err).Msgf("coinutil.DecodeAddress")
		return Transaction{}, err
	}
	fromAddr, err := coinutil.DecodeAddress(addresspubkey.String(), net)
	if err != nil {
		logger.Fatal().Err(err).Msgf("coinutil.DecodeAddress")
		return Transaction{}, err
	}
	sourcePkScript, err := txscript.PayToAddrScript(btcutil.Address(fromAddr))
	if err != nil {
		logger.Fatal().Err(err).Msgf("txscript.PayToAddrScript. fromAddr: %s", fromAddr.EncodeAddress())
		return Transaction{}, err
	}
	destinationPkScript, err := txscript.PayToAddrScript(toAddr)
	if err != nil {
		logger.Fatal().Err(err).Msgf("txscript.PayToAddrScript. toAddr: %s", toAddr.EncodeAddress())
		return Transaction{}, err
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
	prevOut := wire.NewOutPoint(&newTxHash, 0)
	redeemTxIn := wire.NewTxIn(prevOut, nil, nil)
	redeemTx.AddTxIn(redeemTxIn)
	redeemTxOut := wire.NewTxOut(int64(amount), destinationPkScript)
	redeemTx.AddTxOut(redeemTxOut)
	sigScript, err := txscript.SignatureScript(redeemTx, 0, newTx.TxOut[0].PkScript, txscript.SigHashAll, wif.PrivKey, false)
	if err != nil {
		logger.Fatal().Err(err).Msgf("txscript.SignatureScript")
		return Transaction{}, err
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

	transaction.TxId = newTxHash.String()
	transaction.UnsignedTx = hex.EncodeToString(unsignedTx.Bytes())
	transaction.Amount = int64(amount)
	transaction.SignedTx = hex.EncodeToString(signedTx.Bytes())
	transaction.SourceAddress = fromAddr.EncodeAddress()
	transaction.DestinationAddress = toAddr.EncodeAddress()
	return transaction, nil
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

// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 00
// ffffffff
// 01
// c0e1e40000000000
// 0000000000

// signed tx:
//
// 0100000001ec14e766975d7ec991c313a6f9670924adbcd79b8c38859dfb7e69608016b30a000000008a47304402204af3ee6e1e6443cb5b84ad4964e4f7bc360c4742b41a01f163d90b2d11f690fc02206ba61fc16acb2355adb9bc30e457f22cd3fab6eb782e808bff7a448d888381ce01410459c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c0b8424f2fa6398404927fcf6b5b492e7fc508b7950ed8e84ce6c01ecff71828cffffffff01c0e1e400000000000000000000