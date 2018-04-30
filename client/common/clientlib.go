package common

import (

	"golang.org/x/net/context"
	pb "conseweb.com/wallet/icebox/protos"
	"fmt"
	"google.golang.org/grpc/grpclog"
	"time"
	"conseweb.com/wallet/icebox/coinutil/bip32"
	"conseweb.com/wallet/icebox/coinutil/bip39"
	"github.com/btcsuite/btcd/chaincfg"

	"conseweb.com/wallet/icebox/core/common"
)

func newUInt32(v uint32) *uint32 {
	var i = v
	return &i
}

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func GenerateSessionKey(r string) *bip32.ExtendedKey {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)

	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	// 此处password只是需要外部提供一个不确定的输入，以增强安全性，并不用做加密
	seed := bip39.NewSeed(mnemonic, r)

	masterKey, _ := bip32.NewMaster(seed, &chaincfg.MainNetParams)
	return masterKey
}

func FirstSayHi(client pb.IceboxClient) *pb.HiReply {
	var err error
	req := pb.NewHiRequest(common.App_magic)
	res, err := client.FirstHi(context.Background(), req)
	if err != nil {
		//grpclog.Fatalln(err)
		grpclog.Fatalf("%v.firstSayHi(_) = _, %v: ", client, err)
	}
	fmt.Println("HiReply: ", res)
	//if res.GetHeader().GetCode() == 0 && res.GetMagicB() == device_magic {
	//	// send negoniate request
	//	r := fmt.Sprintf("%d", makeTimestamp())
	//	key := generateSessionKey(r)
	//	ireq := pb.NewNegotiateRequest(key.String())
	//	irep, xe := common.FirstHi(context.Background(), ireq)
	//	if xe != nil {
	//		grpclog.Fatalln(xe)
	//	}
	//	fmt.Println("InitReply: ", irep)
	//}
	return res
}

func CheckDevice(client pb.IceboxClient) *pb.CheckReply {
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

func HandshakeDevice(client pb.IceboxClient) {
	req := pb.NewHelloRequest()
	res, err := client.HandShake(context.Background(), req)
	if err != nil {
		grpclog.Fatalln(err)
	}
	grpclog.Println("HelloReply: ", res)
}

func ResetDevice(client pb.IceboxClient) {
	var err error
	resetReq := pb.NewResetRequest()
	var res1 *pb.ResetReply
	res1, err = client.ResetDevice(context.Background(), resetReq)
	if err != nil {
		grpclog.Fatalln(err)
	}
	fmt.Println("ResetReply: ", res1)
}


