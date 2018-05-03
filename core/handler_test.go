package core

import (
	_ "github.com/smartystreets/goconvey/convey"
	pb "conseweb.com/wallet/icebox/protos"

	"testing"
	_ "fmt"
	"os/exec"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
	"net"
	"time"
	"conseweb.com/wallet/icebox/client/common"
	"os"
)

const (
	//App_magic    = int64(87383432003452347)
	//Device_magic = int64(13467864003578678)
)

var client pb.IceboxClient
var conn *grpc.ClientConn
var serverCmd *exec.Cmd

func TestMain(m *testing.M) {
	grpclog.Printf("TestMain()")
	//startServer()
	//startServer2()
	client, conn = startClient()
	returnCode := m.Run()
	stopClient()
	//stopServer()
	os.Exit(returnCode)
}

func startServer() {
	grpclog.Infoln("startServer()")
	cmdStr := "./iceserver"
	serverCmd = exec.Command(cmdStr)
	serverCmd.Dir = "."
	err := serverCmd.Start()
	if err != nil {
		grpclog.Fatal("Server failed to start: ", err)
	}

	//time.Sleep(3000 * time.Millisecond)

	if !serverUp() {
		grpclog.Fatal("Server failed to open port")
		stopServer()
	}

}

func serverUp() bool {
	// wait for port to open
	for i := 0; i < 100; i++ {
		if checkServerUp() {
			grpclog.Infoln("server up!")
			return true
		}
		grpclog.Infoln("server not up yet...trying again!")
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func checkServerUp() bool {
	// Check if server port is in use

	// Try to create a server with the port
	server, err := net.Listen("tcp", ":50052")

	// if it fails then the port is likely taken
	if err != nil {
		return true
	}

	err = server.Close()
	if err != nil {
		return true
	}

	// we successfully used and closed the port
	// so it's now available to be used again
	return false

}

func stopServer() {
	grpclog.Infoln("stopServer()")
	if err := serverCmd.Process.Kill(); err != nil {
		grpclog.Fatal("failed to kill: ", err)
	}
}

func startClient() (pb.IceboxClient, *grpc.ClientConn) {
	grpclog.Infof("startClient()")
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	//conn, err := grpc.Dial("127.0.0.1:"+string(*port), opts...)
	conn, err := grpc.Dial("127.0.0.1:50052", opts...)
	if err != nil {
		grpclog.Fatalf("fail to dial: %v", err)
	}
	client := pb.NewIceboxClient(conn)

	return client, conn
}

func stopClient() {
	conn.Close()
}

func TestFirstHi(t *testing.T) {
	grpclog.Printf("TestFirstHi()")
	reply := common.Hello(client)

	//var err error
	//req := pb.NewHiRequest(common.App_magic)
	//fmt.Println("HiRequest: ", req)
	//res, err := client.Hello(context.Background(), req)
	//if err != nil {
	//	grpclog.Fatalf("%v.firstSayHi(_) = _, %v: ", client, err)
	//}
	grpclog.Println("HiReply: ", reply)
}


//func TestEncryption(t *testing.T) {
//	Convey(`Decrypted text should equal original message.`, t, func() {
//		var err error
//		req := pb.NewHiRequest(App_magic)
//		res, err := common.Hello(context.Background(), req)
//		if err != nil {
//			grpclog.Fatalln(err)
//		}
//		fmt.Println("HiReply: ", res)
//		if res.GetHeader().GetCode() == 0 && res.GetMagicB() == Device_magic {
//			// send negoniate request
//			ireq := pb.NewNegotiateRequest(App_magic)
//			irep, xe := common.Hello(context.Background(), ireq)
//			if xe != nil {
//				grpclog.Fatalln(xe)
//			}
//			fmt.Println("InitReply: ", irep)
//		}
//		return res
//	})
//
//}

