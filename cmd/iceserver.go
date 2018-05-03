package main

import (
	"flag"
	"golang.org/x/net/trace"  // 引入trace包
	"google.golang.org/grpc/grpclog"
	"net/http"
	"conseweb.com/wallet/icebox/common/flogging"
	"fmt"
	"github.com/cheapRoc/grpc-zerolog"
	"net"
	"conseweb.com/wallet/icebox/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/testdata"

	"os"
	"github.com/rs/zerolog"
	_ "github.com/rs/zerolog/log"
	pb "conseweb.com/wallet/icebox/protos"
)

var (
	tls        = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile   = flag.String("cert_file", "root/server.pem", "The TLS cert file")
	keyFile    = flag.String("key_file", "root/server.key", "The TLS key file")
	//jsonDBFile = flag.String("json_db_file", "testdata/route_guide_db.json", "A json file containing a list of features")
	port       = flag.Int("port", 50052, "The server port")

	// Address gRPC服务地址
	Address = fmt.Sprintf("localhost:%d", *port)

	logger = flogging.MustGetLogger("main", zerolog.InfoLevel)
)

func startTrace() {
	trace.AuthRequest = func(req *http.Request) (any, sensitive bool) {
		return true, true
	}
	go http.ListenAndServe(":50051", nil)
	grpclog.Infoln("Trace listen on 50051")
}

func main() {
	//log.Logger = logger.Level(zerolog.DebugLevel)
	//zerolog.SetGlobalLevel(zerolog.DebugLevel)

	grpclog.SetLoggerV2(grpczerolog.New(*logger))

	flag.Parse()

	//log.Debug().Msg("Testing debug level ...")
	logger.Info().Msg("Starting ....")

	logger.Debug().Msg("Testing 2 debug level ...")

	lis, err := net.Listen("tcp", Address)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to listen")
		os.Exit(1)
	}
	defer lis.Close()

	var opts []grpc.ServerOption
	if *tls {
		if *certFile == "" {
			*certFile = testdata.Path("root/keys/server.pem")
		}
		if *keyFile == "" {
			*keyFile = testdata.Path("root/keys/server.key")
		}
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			logger.Fatal().Msgf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	grpcServer := grpc.NewServer(opts...)
	serv := core.NewIcebergHandler()
	pb.RegisterIceboxServer(grpcServer, serv)

	// 开启trace
	go startTrace()

	grpclog.Infoln("Listen on " + Address)
	grpcServer.Serve(lis)
}