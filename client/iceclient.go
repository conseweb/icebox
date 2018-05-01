package main

import (
	"flag"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "conseweb.com/wallet/icebox/protos"
	"google.golang.org/grpc/testdata"
	"time"
	"os/signal"
	"os"

	"conseweb.com/wallet/icebox/client/common"
	"github.com/rs/zerolog"
	"conseweb.com/wallet/icebox/common/flogging"
)


var (
	ctls   = flag.Bool("ctls", false, "Connection uses TLS if true, else plain TCP")
	caFile = flag.String("ca_file", "", "The file containning the CA root cert file")
	// Address gRPC服务地址
	serverAddr         = flag.String("server_addr", "127.0.0.1:50052", "The server address in the format of host:port")
	serverHostOverride = flag.String("server_host_override", "x.test.youtube.com", "The server name use to verify the hostname returned by TLS handshake")

	logger = flogging.MustGetLogger("client", zerolog.InfoLevel)
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
			log.Fatalf("Failed to create TLS credentials %v", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(*serverAddr, opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewIceboxClient(conn)

	ticker := time.NewTicker(10000 * time.Millisecond)
	go func() {
		for  range ticker.C {
			//fmt.Println("Tick at ", t.UnixNano() / int64(time.Millisecond))
			common.HandshakeDevice(client)
		}
	}()

	// 调用方法
	//res := checkDevice(common)
	reply := common.Hello(client)
	if reply.GetHeader().GetCode() == 0 {
		logger.Info().Msgf("Received hello's reply")

		common.Negotiate(client)
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

