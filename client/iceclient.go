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
	reply := handler.Hello()
	if reply.GetHeader().GetCode() == 0 {
		logger.Debug().Msgf("Received hello's reply")

		handler.FSM.Event("HELLO")
		_, err := handler.Negotiate()
		if err != nil {
			// 不是目标设备
			handler.FSM.Event("OUT")
		}
		handler.FSM.Event("NEGOTIATE")

		handler.CheckDevice()

	} else {
		// 不是目标设备
		handler.FSM.Event("OUT")
	}

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

