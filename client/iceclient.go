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

	// 调用方法
	req := pb.NewCheckRequest(1, uint32(makeTimestamp()))
	res, err := client.CheckDevice(context.Background(), req)
	if err != nil {
		grpclog.Fatalln(err)
	}
	fmt.Println("CheckReply: ", res)

	if res.GetHeader().GetCode()==0 && res.GetState()==0 {
		 // send initrequest
		 ireq := pb.NewInitRequest(1, 101, "Secret")
		 irep, xe := client.InitDevice(context.Background(), ireq)
		 if xe != nil {
			 grpclog.Fatalln(xe)
		 }
		 fmt.Println("InitReply: ", irep)
	}

	grpclog.Infoln(res.State)

}
