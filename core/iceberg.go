package core

import (
	"fmt"
	"golang.org/x/net/context"

	"conseweb.com/wallet/icebox/coinutil/bip44"
	"conseweb.com/wallet/icebox/coinutil/bip38"
	"conseweb.com/wallet/icebox/coinutil/bip39"
	"conseweb.com/wallet/icebox/core/models"
	pb "conseweb.com/wallet/icebox/protos"

	"errors"
	"github.com/jinzhu/gorm"
	"os"
	"io/ioutil"
	"conseweb.com/wallet/icebox/common/guid"
	"encoding/hex"
	"conseweb.com/wallet/icebox/common/address"
	"github.com/btcsuite/btcd/chaincfg"
	"time"
	"conseweb.com/wallet/icebox/coinutil/bip32"
	"conseweb.com/wallet/icebox/core/common"
	"conseweb.com/wallet/icebox/common/flogging"
	"conseweb.com/wallet/icebox/common/crypto/koblitz/kelliptic"
	"github.com/btcsuite/btcd/btcec"
	"conseweb.com/wallet/icebox/coinutil/base58"
	"conseweb.com/wallet/icebox/coinutil"
	"encoding/binary"
	"github.com/rs/zerolog"
)

const (
	icebox_path = "ss"
	secret_path = "root/ss/secret.dat"	// encrypted priv key
	devid_path = "root/ss/devid.dat"
	db_path = "root/ss/db.dat"
	session_path = "root/ss/session.dat"  // session priv key and peer's public key
)

var (
	logger = flogging.MustGetLogger("core", zerolog.DebugLevel)
)

type CoinID struct {
	T1	   uint32 			// for bip44: purpose = 44;
	T2     uint32           // for bip44: coin_type;
}

type AddressID struct {
	Coin 	CoinID
	T5     	uint32			// for bip44: address_index;
}

func exists(fn string) bool {
	var _, err = os.Stat(fn)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

type Session struct {
	id 	uint32 		// session id
	key string			// private key
	peerKey []byte		// peer's public key
	sharedKey []byte	// shared public key
}

type iceberg struct {
	id string
	db gorm.DB
	session Session
	// session info
	//session_id uint32
	// a
	//session_key string
	// Q
	//shared_key []byte

	// features
	features map[CoinID] models.Coin

	// formulas
	formulas map[CoinID][]*models.Address
}

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func (s *iceberg) GenerateEquality() (res string) {
	return ""
}

//func _CreateFormula(coin, chain, index uint32, name string) (*bip32.Key, error) {
//	db.Create(&models.Address{T2: coin, T4: chain, T5: index, Name: name})
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

func (s *iceberg) Hello(ctx context.Context, req *pb.HiRequest) (*pb.HiReply, error) {
	if common.App_magic == req.GetMagicA() {
		reply := pb.MakeHiReply(req, common.Device_magic)
		return reply, nil
	}
	return nil, errors.New("Unknown app!")
}

func (s *iceberg) NegotiateKey(ctx context.Context, req *pb.NegotiateRequest) (*pb.NegotiateReply, error) {

	// should be base58 compressed
	keyA := *req.KeyA
	logger.Debug().Msgf("Received keyA: %s", keyA)

	r := fmt.Sprintf("%d", makeTimestamp())
	ek := s.generateSessionKey(r)
	sk, err := ek.ECPrivKey()
	if err != nil {
		return nil, err
	}
	//pk, _ := ek.ECPubKey2()
	//reply := pb.MakeNegotiateReply(req, pk.Compress())
	// generate session shared key
	// sk * KeyA

	var pkA = new(address.PublicKey)
	pkA.Curve = kelliptic.S256()
	cp := base58.Decode(keyA)
	//cp, err := address.FromBase58(keyA)
	//if err != nil {
	//	logger.Fatal().Err(err).Msg("")
	//	return nil, err
	//}
	var curve = btcec.S256()
	pk, err := btcec.ParsePubKey(cp, curve)
	if err != nil {
		logger.Fatal().Err(err).Msg("")
		return nil, err
	}
	//logger.Info().Msgf("Received pkA: %s", pk)

	spk := pk.SerializeCompressed()
	bpk := base58.Encode(spk)
	if bpk == keyA {
		logger.Debug().Msgf("Encode ok!")
	}
	//var curve = kelliptic.S256()
	//pkA.Curve = curve
	//pkA.X, pkA.Y, err = pkA.Curve.DecompressPoint(cp)
	//err = address.DeCompress(keyA, pkA)
	//if err != nil {
	//	return nil, err
	//}

	shared := address.NewPublickKey("256")
	shared.X, shared.Y = shared.ScalarMult(pk.X, pk.Y, sk.Serialize())
	s.session.sharedKey = shared.Bytes()

	// generate aes key
	aesKey := s.session.sharedKey[:16]

	logger.Debug().Msgf("Got shared key: %s", base58.Encode(aesKey))
	pkB := sk.PubKey()
	bpkB := base58.Encode(pkB.SerializeCompressed())
	logger.Debug().Msgf("Iceberg's public session key: %s", bpkB)
	reply := pb.MakeNegotiateReply(req, bpkB)

	return reply, nil
}

func (s *iceberg) StartSession(ctx context.Context, req *pb.StartRequest) (*pb.StartReply, error) {

	return nil, errors.New("Not implemented!")
}

func (s *iceberg) Conversation(pb.Icebox_ConversationServer) error  {
	return errors.New("Not implemented!")
}

func (s *iceberg) EndSession(ctx context.Context, req *pb.EndRequest) (*pb.EndReply, error) {
	return nil, errors.New("Not implemented!")
}

////////////////////////////////// Bussiness Logic ////////////////////////////////////////

func (s *iceberg) CheckDevice(ctx context.Context, req *pb.CheckRequest) (*pb.CheckReply, error) {
	// check device is initialized

	if !s.isInitialized() {
		// return uninit
		// zero := int32(0)
		reply := pb.MakeCheckReply(req, 0,nil)
		return reply, nil
	}

	// 初步判断依据初始化了，需要获取深度数据以进行检测
	devid, _ := s.loadDeviceID(devid_path)
	//one := int32(1)
	reply := pb.MakeCheckReply(req, 1, &devid)
	return reply, nil
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
	_, err = s.initDB(db_path)
	if err != nil {
		return nil, err
	}

	reply := pb.MakeInitReply(req, devid)
	fmt.Println("==> done init device")

	return reply, nil
}

func (s *iceberg) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingReply, error)  {
	reply := pb.MakePingReply(req)
	return reply, nil
}

func (s *iceberg) AddCoin(ctx context.Context, req *pb.AddCoinRequest) (*pb.AddCoinReply, error)  {
	tp := req.GetType()
	idx := req.GetIdx()
	symbol := req.GetSymbol()
	name := req.GetName()
	s.db.Create(&models.Coin{T2: tp, T3: idx, Symbol: symbol, Name: name})
	reply := pb.MakeAddCoinReply(req)
	return reply, nil
}

func (s *iceberg) CreateAddress(ctx context.Context, req *pb.CreateAddressRequest) (*pb.CreateAddressReply, error)  {

	tp := req.GetType()
	idx := req.GetIdx()
	name := req.GetName()
	pwd := req.GetPassword()
	// 需要首先判断是否支持该币种
	var cnt int
	s.db.Where("t2 = ?", tp).Count(&cnt)
	if cnt <= 0 {
		return nil, errors.New("Unsupported coin type: " + string(tp))
	}

	s.db.Create(&models.Address{T2: tp, T5: idx, Name: name})
	p := models.GetPath(&s.db, tp, idx)
	// TODO: should generate key and address by bip44
	masterKey, _ := s.loadSecretKey(secret_path, pwd)
	ek, _ := bip32.NewKeyFromString(masterKey.String())
	bip44.NewKeyFromMasterKey(ek, tp, 0, 0, idx)
	reply := pb.MakeCreateAddressReply(req, p)
	return reply, nil
}

func (s *iceberg) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.CreateSecretReply, error)  {

	//tp := req.GetType()
	//idx := req.GetIdx()
	//name := req.GetName()
	//pwd := req.GetPassword()
	//// 需要首先判断是否支持该币种
	//var cnt int
	//s.db.Where("t2 = ?", tp).Count(&cnt)
	//if cnt <= 0 {
	//	return nil, errors.New("Unsupported coin type: " + string(tp))
	//}
	//
	//s.db.Create(&models.Address{T2: tp, T5: idx, Name: name})
	//p := models.GetPath(&s.db, tp, idx)
	//// TODO: should generate key and address by bip44
	//masterKey, _ := s.loadSecretKey(secret_path, pwd)
	//ek, _ := bip32.NewKeyFromString(masterKey.String())
	//bip44.NewKeyFromMasterKey(ek, tp, 0, 0, idx)
	//reply := pb.MakeCreateAddressReply(req, p)
	//return reply, nil
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) ListCoin(context.Context, *pb.ListCoinRequest) (*pb.ListCoinReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) ListSecret(context.Context, *pb.ListSecretRequest) (*pb.ListSecretReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) ListFormula(context.Context, *pb.ListFormulaRequest) (*pb.ListFormulaReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) SignTx(context.Context, *pb.SignTxRequest) (*pb.SignTxReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) RemoveCoin(context.Context, *pb.RemoveCoinRequest) (*pb.RemoveCoinReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) DeleteSecret(context.Context, *pb.DeleteSecretRequest) (*pb.DeleteSecretReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) DeleteFormula(context.Context, *pb.DeleteFormulaRequest) (*pb.DeleteFormulaReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceberg) ResetDevice(ctx context.Context, req *pb.ResetRequest) (*pb.ResetReply, error)  {
	// reset device: remove all files
	err := s.resetDevice()
	if err != nil {
		return nil, err
	}

	reply := pb.MakeResetReply(req)
	return reply, nil
}

//////////////////////////////////////////////////////////////////////////////

func (s *iceberg) generateSessionKey(r string) *bip32.ExtendedKey {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)

	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	// 此处password只是需要外部提供一个不确定的输入，以增强安全性，并不用做加密
	seed := bip39.NewSeed(mnemonic, r)

	masterKey, _ := bip32.NewMaster(seed, &chaincfg.MainNetParams)

	pk, _ := masterKey.ECPubKey()
	pkHash := coinutil.Hash160(pk.SerializeCompressed())
	s.session.key = masterKey.String()
	s.session.id = binary.BigEndian.Uint32(pkHash[:4])
	return masterKey
}

func (s *iceberg) resetDevice() (err error) {
	// remove all files in device
	if exists(devid_path) {
		err = os.Remove(devid_path)
		if err != nil {
			return err
		}
	}
	if exists(secret_path) {
		err = os.Remove(secret_path)
		if err != nil {
			return err
		}
	}
	if exists(db_path) {
		err = os.Remove(db_path)
		if err != nil {
			return err
		}
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

	masterKey, _ := bip32.NewMaster(seed, &chaincfg.MainNetParams)
	publicKey, _ := masterKey.ECPubKey()

	// Display mnemonic and keys
	fmt.Println("Mnemonic: ", mnemonic)
	fmt.Println("Master private key: ", masterKey)
	fmt.Println("Master public key: ", publicKey)

	// encrypt private key
	key, err = masterKey.ECPrivKey2()
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

func (s *iceberg) initDB(fn string) (db *gorm.DB, err error) {
	db, err = gorm.Open("sqlite3", fn)
	if err != nil {
		errors.New("Failed to connect database")
	}

	// Migrate the schema
	db.AutoMigrate(&models.Coin{})
	db.AutoMigrate(&models.Address{})

	// Create
	db.Create(&models.Coin{T2: 0, Symbol: "btc", Name: "bitcoin"})
	db.Create(&models.Coin{T2: 1, Symbol: "test", Name: "testnet"})
	db.Create(&models.Coin{T2: 2, Symbol: "ltc", Name: "litecoin"})
	db.Create(&models.Coin{T2: 3, Symbol: "doge", Name: "dogecoin"})
	db.Create(&models.Coin{T2: 5, Symbol: "dsh", Name: "dash"})
	db.Create(&models.Coin{T2: 9, Symbol: "xcp", Name: "counterparty"})
	db.Create(&models.Coin{T2: 60, Symbol: "eth", Name: "ethereum"})
	db.Create(&models.Coin{T2: 61, Symbol: "etc", Name: "ethereum classic"})

	return db, err
}

func (s *iceberg) isInitialized() bool {
	if !exists(devid_path) {
		return false
	}
	if !exists(secret_path) {
		return false
	}
	if !exists(db_path) {
		return false
	}

	return true
}

func NewIceberg() *iceberg {
	s := &iceberg{}
	id := guid.New96()
	s.id = hex.EncodeToString(id.Bytes())
	//s.loadFeatures(*jsonDBFile)
	return s
}

