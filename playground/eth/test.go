package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	_ "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/crypto"
	"encoding/hex"
	"encoding/json"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/rs/zerolog"
	"github.com/conseweb/icebox/common/flogging"
	"github.com/ethereum/go-ethereum/accounts/abi"
)

const (
	key = `{"address": "", "crypto": {"cipher": "ase-128-ctr"}}`
	TestABI = ""
	TestBin = "0x6006"
)

var (
	logger = flogging.MustGetLogger("main", zerolog.InfoLevel)
)

type GethTxn struct {
  To   string     `json:"to"`
  From string     `json:"from"`
  Gas string      `json:"gas"`
  GasPrice string `json:"gasPrice"`
  Value string    `json:"value"`
  Data string     `json:"input"`
}

func SignTxn(from string, _to string, data []byte, nonce uint64, value int64,
	gas *big.Int, gasPrice *big.Int, privkey *ecdsa.PrivateKey) (*GethTxn, error) {

  var parsed_tx = new(GethTxn)
  var amount = big.NewInt(value)
  var bytesto [20]byte
  _bytesto, _ := hex.DecodeString(_to[2:])
  copy(bytesto[:], _bytesto)
  to := common.Address([20]byte(bytesto))

  signer := types.NewEIP155Signer(nil)
  tx := types.NewTransaction(nonce, to, amount, gas, gasPrice, data)
  signature, _ := crypto.Sign(tx.SigHash(signer).Bytes(), privkey)
  signed_tx, _ := tx.WithSignature(signer, signature)

  json_tx, _ := signed_tx.MarshalJSON()
  _ = json.Unmarshal(json_tx, parsed_tx)
  parsed_tx.From = from
  fmt.Println("data", parsed_tx.Data)
  my_string_var := signed_tx.String()
  fmt.Println("raw tx: %s", my_string_var)
  return parsed_tx, nil
}

func rawTransaction(client *ethclient.Client) {
	d := time.Now().Add(1000 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()

	unlockedKey, err := keystore.DecryptKey([]byte(key), "password")
	nonce, _ := client.NonceAt(ctx, unlockedKey.Address, nil)

	if err != nil {
		logger.Debug().Msgf("Wrong passcode")
	} else {
		tx := types.NewTransaction(nonce, common.HexToAddress("0x56724a9e4d2bb2dca01999acade2e88a92b11a9e"),
			big.NewInt(12400000), big.NewInt(10000000), big.NewInt(0), nil)
		//signTx, err := types.SignTx(tx, types.HomesteadSigner{}, unlockedKey.PrivateKey)
		signTx, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(1)), unlockedKey.PrivateKey)
		err = client.SendTransaction(ctx, signTx)

		if err != nil {
			logger.Error().Msgf("%s, %s", err, nonce)
		} else {
			select {
			case <-time.After(1 * time.Millisecond):
				logger.Debug().Msgf("overslept")
			case <-ctx.Done():
				logger.Debug().Err(ctx.Err())
			default:
				logger.Debug().Msgf("%s", tx.Hash().String())
			}
		}
	}
}

func rawDeployContract(client *ethclient.Client) {
	d := time.Now().Add(1000 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()

	byteCode := common.Hex2Bytes(TestBin[2:])
	testabi, _ := abi.JSON(strings.NewReader(TestABI))
	input, _ := testabi.Pack("")

	byteCode = append(byteCode, input...)
	unlockedKey, _ := keystore.DecryptKey([]byte(key), "password")
	nonce, _ := client.NonceAt(ctx, unlockedKey.Address, nil)

	tx := types.NewContractCreation(nonce, big.NewInt(0), big.NewInt(10000000), big.NewInt(0), byteCode)

	signTx, _ := types.SignTx(tx, types.HomesteadSigner{}, unlockedKey.PrivateKey)
	err := client.SendTransaction(ctx, signTx)
	if err != nil {
		logger.Error().Err(err)
	} else {
		logger.Debug().Msgf("%v", signTx)
	}
}

func Main() {
	// Create an IPC based RPC connection to a remote node
	client, err := ethclient.Dial("geth.ipc")
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	// getBlock(client)
	// rawTransaction(client)

	//tx := types.NewTransaction(nonce, recipient, value, gasLimit, gasPrice, input)
	//signature, _ := crypto.Sign(transaction.SigHash().Bytes(), key)
	//signed, _ := tx.WithSignature(signature)

}