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
	rex, _ := handler.CreateAddress(1,"default", common.Test_password)
	//rex, _ = handler.CreateAddress(60, 21, "eth default", common.Test_password)
	logger.Debug().Msgf("Created address: %s", rex.GetAddress())

	handler.ListAddress(1, common.Test_password)

	handler.SignTx(0, 115155635, 91234, "1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa", "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48", common.Test_password)

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

