package main

import (
	"flag"
	"log"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "conseweb.com/wallet/icebox/protos"
	"google.golang.org/grpc/testdata"
	"fmt"
	"google.golang.org/grpc/grpclog"
	"time"
	"os/signal"
	"os"
)

var (
	tls                = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	caFile             = flag.String("ca_file", "", "The file containning the CA root cert file")
	// Address gRPC服务地址
	serverAddr         = flag.String("server_addr", "127.0.0.1:50052", "The server address in the format of host:port")
	serverHostOverride = flag.String("server_host_override", "x.test.youtube.com", "The server name use to verify the hostname returned by TLS handshake")
)

func newUInt32(v uint32) *uint32 {
	var i = v
	return &i
}

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func checkDevice(client pb.IceboxClient) *pb.CheckReply {
	var err error
	req := pb.NewCheckRequest()
	res, err := client.CheckDevice(context.Background(), req)
	if err != nil {
		grpclog.Fatalln(err)
	}
	fmt.Println("CheckReply: ", res)
	if res.GetHeader().GetCode() == 0 && res.GetState() == 0 {
		// send initrequest
		ireq := pb.NewInitRequest("Secret")
		irep, xe := client.InitDevice(context.Background(), ireq)
		if xe != nil {
			grpclog.Fatalln(xe)
		}
		fmt.Println("InitReply: ", irep)
	}
	return res
}

func handshakeDevice(client pb.IceboxClient) {
	req := pb.NewHelloRequest()
	res, err := client.HandShake(context.Background(), req)
	if err != nil {
		grpclog.Fatalln(err)
	}
	fmt.Println("HelloReply: ", res)
}

func resetDevice(client pb.IceboxClient) {
	var err error
	resetReq := pb.NewResetRequest()
	var res1 *pb.ResetReply
	res1, err = client.ResetDevice(context.Background(), resetReq)
	if err != nil {
		grpclog.Fatalln(err)
	}
	fmt.Println("ResetReply: ", res1)
}

func main() {
	flag.Parse()
	var opts []grpc.DialOption
	if *tls {
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

	ticker := time.NewTicker(500 * time.Millisecond)
	go func() {
		for t := range ticker.C {
			fmt.Println("Tick at ", t.UnixNano() / int64(time.Millisecond))
			handshakeDevice(client)
		}
	}()

	// 调用方法
	res := checkDevice(client)

	// send reset request
	//resetDevice(client)

	//time.Sleep(1600 * time.Millisecond)
	//ticker.Stop()

	grpclog.Infoln(res.State)

	// Wait for SIGINT (CTRL-c), then close servers and exit.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt)
	<-shutdown
}

