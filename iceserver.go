package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/testdata"
	_ "conseweb.com/wallet/icebox/bip44"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"

	"conseweb.com/wallet/icebox/models"

	//"github.com/golang/protobuf/proto"
	pb "conseweb.com/wallet/icebox/protos"
	"errors"
	"github.com/jinzhu/gorm"
	"os"
	"io/ioutil"
	"conseweb.com/wallet/icebox/guid"
	"encoding/hex"
	"conseweb.com/wallet/icebox/bip38"
	"conseweb.com/wallet/icebox/address"
)

const (
	icebox_path = "ss"
	secret_path = "ss/secret.dat"
	devid_path = "ss/devid.dat"
)

var (
	tls        = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile   = flag.String("cert_file", "", "The TLS cert file")
	keyFile    = flag.String("key_file", "", "The TLS key file")
	//jsonDBFile = flag.String("json_db_file", "testdata/route_guide_db.json", "A json file containing a list of features")
	port       = flag.Int("port", 10000, "The server port")

)

type FeatureID struct {
	T1	   uint32 			// for bip44: purpose = 44; for password: 16
	T2     uint32           // for bip44: coin_type; for password: 8
}

type FormulaID struct {
	T1	   uint32 			// for bip44: purpose = 44; for password: 16
	T2     uint32           // for bip44: coin_type; for password: 8
	T5     uint32			// for bip44: address_index; for password: index
}

type iceberg struct {
	id string
	db gorm.DB
	// features
	features map[FeatureID] models.Feature

	// formulas
	formulas map[FeatureID][]*models.Formula
}

func (s *iceberg) GenerateEquality() (res string) {
	return ""
}

//func _CreateFormula(coin, chain, index uint32, name string) (*bip32.Key, error) {
//	db.Create(&models.Formula{T2: coin, T4: chain, T5: index, Name: name})
//
//	mkey, err := loadMasterPrivKey(secretFn)
//	if mkey != nil {
//		var key *bip32.Key
//		key, err = bip44.NewKeyFromMasterKey(mkey, coin, 0, chain, index)
//		if err != nil {
//			return nil, err
//		}
//		return key, nil
//	}
//	return nil, err
//}

func makeCheckReply(req *pb.CheckRequest, state *int32, devid *string) *pb.CheckReply {
	h := req.Header

	zero := int32(0)

	reply := new(pb.CheckReply)
	reply.Header.Sn = h.Sn
	reply.Header.Ver = h.Ver
	reply.State = state
	status := new(pb.Status)
	status.Code = &zero
	reply.Header.Status = status
	if devid != nil {
		reply.DevId = devid
	}
	return reply
}


func (s *iceberg) CheckDevice(ctx context.Context, req *pb.CheckRequest) (*pb.CheckReply, error) {
	// check device is initialized

	if !s.isInitialized() {
		// return uninit
		zero := int32(0)
		reply := makeCheckReply(req, &zero,nil)
		return reply, nil
	}

	// 初步判断依据初始化了，需要获取深度数据以进行检测
	devid, _ := s.loadDeviceID(devid_path)
	one := int32(1)
	reply := makeCheckReply(req, &one, &devid)
	return reply, nil
}

func makeInitReply(req *pb.InitRequest, devid string) *pb.InitReply {
	h := req.Header

	reply := new(pb.InitReply)
	reply.Header.Sn = h.Sn
	reply.Header.Ver = h.Ver
	reply.DevId = &devid
	status := new(pb.Status)
	zero := int32(0)
	status.Code = &zero
	reply.Header.Status = status
	return reply
}

func (s *iceberg) InitDevice(ctx context.Context, req *pb.InitRequest) (*pb.InitReply, error) {
	// remove all files
	s.resetDevice()

	//fmt.Println("==> start init device")
	// new devid and privkey
	devid, err := s.newDeviceID(devid_path)
	if err != nil {
		return nil, err
	}
	_, err = s.newPrivKey(secret_path, *(req.Password))
	if err != nil {
		return nil, err
	}

	reply := makeInitReply(req, devid)
	fmt.Println("==> done init device")

	return reply, nil
}

func (s *iceberg) HandShake(context.Context, *pb.HelloRequest) (*pb.HelloReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) AddFeature(context.Context, *pb.AddFeatureRequest) (*pb.AddFeatureReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) CreateFormula(context.Context, *pb.CreateFormulaRequest) (*pb.CreateFormulaReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) ListFeature(context.Context, *pb.ListFeatureRequest) (*pb.ListFeatureReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) ListFormula(context.Context, *pb.ListFormulaRequest) (*pb.ListFormulaReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) SignTx(context.Context, *pb.SignTxRequest) (*pb.SignTxReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) RemoveFeature(context.Context, *pb.RemoveFeatureRequest) (*pb.RemoveFeatureReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) DeleteFormula(context.Context, *pb.DeleteFormulaRequest) (*pb.DeleteFormulaReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) ResetDevice(context.Context, *pb.ResetRequest) (*pb.ResetReply, error)  {
	return nil, errors.New("Not implemented!")
}

//////////////////////////////////////////////////////////////////////////////

func (s *iceberg) resetDevice() error {
	// remove all files in device
	var err = os.Remove(devid_path)
	if err != nil {
		return err
	}
	err = os.Remove(secret_path)
	if err != nil {
		return err
	}

	fmt.Println("==> done reset device")
	return nil

}

func (s *iceberg) newDeviceID(dfn string) (string, error) {
	id := guid.New96()
	s.id = hex.EncodeToString(id.Bytes())
	// serialize to file
	err := ioutil.WriteFile(dfn, []byte(s.id), 0644)
	return s.id, err
}

func (s *iceberg) loadDeviceID(dfn string) (sid string, err error) {
	var data []byte
	data, err = ioutil.ReadFile(dfn)
	if err != nil {
		return "", err
	}

	sid = string(data)
	return sid, err
}

func (s *iceberg) newPrivKey(sfn, password string) (key *address.PrivateKey, err error) {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)

	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	// 此处password只是需要外部提供一个不确定的输入，以增强安全性，并不用做加密
	seed := bip39.NewSeed(mnemonic, password)

	masterKey, _ := bip32.NewMasterKey(seed)
	publicKey := masterKey.PublicKey()

	// Display mnemonic and keys
	fmt.Println("Mnemonic: ", mnemonic)
	fmt.Println("Master private key: ", masterKey)
	fmt.Println("Master public key: ", publicKey)

	// encrypt private key
	key = &address.PrivateKey{}
	key.SetBytes(masterKey.Key)
	if key.IsValid() {
		// password此处才是真正用作对称加密密钥
		secret := bip38.Encrypt(key, password)
		err = ioutil.WriteFile(sfn, []byte(secret), 0644)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	return nil, errors.New("Invalid private key.")
}

func (s *iceberg) loadSecretKey(fn, password string) (key *address.PrivateKey, err error) {
	var data []byte
	data, err = ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	return bip38.Decrypt(string(data), password)
}

func (s *iceberg) isInitialized() bool {
	var _, err = os.Stat(devid_path)

	// create file if not exists
	if !os.IsNotExist(err) {
		return false
	}

	_, err = os.Stat(secret_path)
	if !os.IsNotExist(err) {
		return false
	}

	return true
}

func newIceberg() *iceberg {
	s := &iceberg{}
	id := guid.New96()
	s.id = hex.EncodeToString(id.Bytes())
	//s.loadFeatures(*jsonDBFile)
	return s
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if *tls {
		if *certFile == "" {
			*certFile = testdata.Path("root/server.pem")
		}
		if *keyFile == "" {
			*keyFile = testdata.Path("root/server.key")
		}
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	grpcServer := grpc.NewServer(opts...)
	serv := newIceberg()
	pb.RegisterIceboxServer(grpcServer, serv)
	grpcServer.Serve(lis)
}