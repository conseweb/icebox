package main

import (
	"flag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/testdata"
	"os/signal"
	"os"

	"github.com/rs/zerolog"
	"conseweb.com/wallet/icebox/common/flogging"
	"conseweb.com/wallet/icebox/common"
	"conseweb.com/wallet/icebox/core/paginator"
	"conseweb.com/wallet/icebox/protos"
	"conseweb.com/wallet/icebox/client/util"
	"encoding/hex"
	"github.com/blockcypher/gobcy"
)

const (
	blockcypher_api_token = "3732964492194d02a0b76e84149aa669"
)

var (
	ctls   = flag.Bool("ctls", false, "Connection uses TLS if true, else plain TCP")
	caFile = flag.String("ca_file", "", "The file containning the CA root cert file")
	// Address gRPC服务地址
	serverAddr         = flag.String("server_addr", "127.0.0.1:50052", "The server address in the format of host:port")
	serverHostOverride = flag.String("server_host_override", "x.test.youtube.com", "The server name use to verify the hostname returned by TLS handshake")

	logger = flogging.MustGetLogger("client", zerolog.DebugLevel)
)

func main() {

	flag.Parse()
	var opts []grpc.DialOption
	//append(opts, grpc.WithTimeout(time.Duration(5 * 1000 * time.Duration)))
	if *ctls {
		if *caFile == "" {
			*caFile = testdata.Path("ca.pem")
		}
		creds, err := credentials.NewClientTLSFromFile(*caFile, *serverHostOverride)
		if err != nil {
			logger.Fatal().Err(err).Msgf("Failed to create TLS credentials")
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	handler := NewHandler(*serverAddr, opts)

	handler.FSM.Event("CREATE")

	err := handler.Connect()
	if err != nil {
		logger.Fatal().Err(err).Msgf("fail to dial")
	}
	handler.FSM.Event("IN")

	//ticker := time.NewTicker(10000 * time.Millisecond)
	//go func() {
	//	for  range ticker.C {
	//		//fmt.Println("Tick at ", t.UnixNano() / int64(time.Millisecond))
	//		common.PingDevice(client)
	//	}
	//}()

	// 调用方法
	//res := checkDevice(common)
	handler.Hello()
	logger.Debug().Msgf("Received hello's reply")

	handler.FSM.Event("HELLO")
	_, err = handler.Negotiate()
	if err != nil {
		// 不是目标设备
		handler.FSM.Event("OUT")
	}
	handler.FSM.Event("NEGOTIATE")

	_, err = handler.Start()
	if err != nil {
		logger.Fatal().Err(err).Msgf("Start command failed !!!")
	}

	handler.FSM.Event("START")
	//handler.session.id

	rep, err := handler.CheckDevice()
	if err != nil {
		logger.Fatal().Err(err).Msgf("")
	}
	switch rep.GetState() {
	case 1:
		handler.FSM.Event("CK_INITED")
	case 0:
		handler.FSM.Event("CK_UNINITED")
		irep, err := handler.InitDevice("Secret")
		if err != nil {
			logger.Fatal().Err(err).Msgf("")
		}
		logger.Info().Msgf("Inited, DevID: %s", *irep.DevId)
		handler.FSM.Event("INIT")
	default:
		logger.Fatal().Msgf("Something wrong!!")
	}

	//rand.Seed(time.Now().UnixNano())
	//var idx = rand.Uint32()
	//rex, _ := handler.CreateAddress(1, common.Test_password)
	//logger.Debug().Msgf("Created address: %s", rex.GetAddressByIdx())
	//
	//{
	//	reply, _ := handler.ListAddress(1, 0, 8, common.Test_password)
	//	offset := reply.GetOffset()
	//	limit := reply.GetLimit()
	//	total := reply.GetTotalRecords()
	//	logger.Debug().Msgf("%d, %d, %d", total, limit, offset)
	//	for {
	//		if paginator.HaveNext(total, limit, offset) {
	//			reply, _ = handler.ListAddress(1, offset, limit, common.Test_password)
	//			offset = reply.GetOffset()
	//			limit = reply.GetLimit()
	//			total = reply.GetTotalRecords()
	//			logger.Debug().Msgf("%d, %d, %d", total, limit, offset)
	//		} else {
	//			break
	//		}
	//	}
	//}

	handler.CreateSecret(32, 1, common.Test_password)

	{
		secretReply, _ := handler.ListSecret(1, 32, 0, 4, common.Test_password)
		offset := secretReply.GetOffset()
		limit := secretReply.GetLimit()
		total := secretReply.GetTotalRecords()
		logger.Debug().Msgf("%d, %d, %d", total, limit, offset)
		for {
			if paginator.HaveNext(total, limit, offset) {
				secretReply, _ = handler.ListSecret(1, 32, offset, limit, common.Test_password)
				offset = secretReply.GetOffset()
				limit = secretReply.GetLimit()
				total = secretReply.GetTotalRecords()
				logger.Debug().Msgf("%d, %d, %d", total, limit, offset)
			} else {
				break
			}
		}
	}

	tp := 1	// testnet
	idx := 1671493468
	gap, err := handler.GetAddressByIdx(uint32(tp), uint32(idx), common.Test_password)
	if err != nil {
		logger.Fatal().Err(err).Msgf("GetAddressByIdx error encountered.")
	}
	fromAddr := gap.GetAddr().GetSAddr()
	logger.Debug().Msgf("from addr: %s", fromAddr)

	bcy := gobcy.API{blockcypher_api_token, "btc", "test3"}
	// get address balance
	addrBal, err := bcy.GetAddrBal(fromAddr, nil)
	if err != nil {
		logger.Fatal().Err(err).Msgf("GetAddrBal error encountered.")
	}
	logger.Debug().Msgf("Balance: %d", addrBal.Balance)

	var params = map[string]string{"unspentOnly": "true"}
	addr, err := bcy.GetAddr(fromAddr, params)
	if err != nil {
		logger.Fatal().Err(err).Msgf("GetAddr error encountered.")
	}
	for i, _ := range addr.TXRefs {
		txref := addr.TXRefs[i]
		logger.Debug().
			Str("tx_hash", txref.TXHash).
			Int("value", txref.Value).
			Int("ref_balance", txref.RefBalance).
			Msgf("")
	}

	amount := int(15000000)
  	goodTxId, outn, err := util.FindFirstSuitableUTXO(bcy, fromAddr, amount)
	if goodTxId == nil && outn == -1 && err == nil {
		logger.Fatal().Msgf("Not enough balance.")
		os.Exit(-1)
	}
  	if goodTxId != nil {
  		logger.Debug().Msgf("Got suitable utxo: %s, %d", *goodTxId, outn)
	}

	// src: "1, 1671493468,
	// addr: base58: mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse",
	// priv: hex: 68855a72a1e728d332025f5813ef35e8a6c1a8f5fb43e610c149b782ee290538
	// pub key: hex: 0259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c
	// dest: "1, 807294064, msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb"
	var signTxReply *protos.SignTxReply
	if RTEnv.isTestNet {
		signTxReply, err = handler.SignTx(uint32(tp), uint32(idx), uint64(amount), "msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb", *goodTxId, uint32(outn), common.Test_password)
	} else {
		// TODO: address should change to mainnet address
		signTxReply, err = handler.SignTx(0, uint32(idx), uint64(amount), "msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb", *goodTxId, uint32(outn), common.Test_password)
	}
	if err != nil {
		logger.Fatal().Err(err).Msgf("")
	} else {
		hexTxSig := hex.EncodeToString(signTxReply.GetSignedTx())
		logger.Debug().Msgf("SignTx reply: %s", hexTxSig)

		txHash := util.DoubleHash256(signTxReply.GetSignedTx())
		txHashReversed := util.ReverseByteOrder(txHash)
		logger.Debug().Msgf("Tx hash: %s", hex.EncodeToString(txHashReversed))
	}

	{
		var reply *protos.SignMsgReply
		msg := "9d5f89bd7855e6dcfb0fb7aef8b4748d7b3082f313e88eb7936b19c95de454d9"
		wantToSign, _ := hex.DecodeString(msg)
		if RTEnv.isTestNet {
			reply, err = handler.SignMsg(uint32(tp), uint32(idx), wantToSign, common.Test_password)
		} else {
			// TODO: address should change to mainnet address
			reply, err = handler.SignMsg(0, uint32(idx), wantToSign, common.Test_password)
		}
		if err != nil {
			logger.Fatal().Err(err).Msgf("")
		} else {
			signed := reply.GetSigned()
			//msgReversed := util.ReverseByteOrder(signed)
			logger.Debug().Msgf("Msg hash: %s", hex.EncodeToString(signed))
		}
	}


	// TODO: broadcast it


	// send reset request
	//resetDevice(common)

	//time.Sleep(1600 * time.Millisecond)
	//ticker.Stop()

	//grpclog.Infoln(res.State)

	// Wait for SIGINT (CTRL-c), then close servers and exit.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt)
	<-shutdown
}

func IsLastPage(total, limit, offset uint32) int {
	if (total == offset) && (offset <= limit) {
		// page 1
		return 0
	}
	if (offset >= total) && (offset > limit) {
		// last page
		return -1
	}
	if (total > offset) && (offset > limit) {
		return 1
	}
	return 2
}