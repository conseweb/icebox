package core

import (
	"bytes"
	"conseweb.com/wallet/icebox/coinutil/bip32"
	"conseweb.com/wallet/icebox/coinutil/base58"
	"conseweb.com/wallet/icebox/coinutil/bip44"
	"conseweb.com/wallet/icebox/coinutil/bip39"
	"conseweb.com/wallet/icebox/common/crypto"
	"conseweb.com/wallet/icebox/core/models"
	"conseweb.com/wallet/icebox/common/guid"
	"encoding/hex"
	"conseweb.com/wallet/icebox/core/common"
	"fmt"
	"conseweb.com/wallet/icebox/common/address"
	"github.com/jinzhu/gorm"
	"encoding/binary"
	"os"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"github.com/btcsuite/btcd/chaincfg"
	"errors"
	"conseweb.com/wallet/icebox/coinutil"

	"golang.org/x/net/context"

	pb "conseweb.com/wallet/icebox/protos"

	"conseweb.com/wallet/icebox/common/crypto/koblitz/kelliptic"
	"github.com/btcsuite/btcd/btcec"
	"crypto/sha256"
	_ "github.com/mattn/go-sqlite3"  // must exists, or will cause -- sql: unknown driver "sqlite3"

)

//go:generate mockgen -source=helper.go -destination=../mocks/mock_Iceberg.go -package=mocks conseweb.com/wallet/icebox/core Iceberg


type Iceberg interface {
	Hello(ctx context.Context, req *pb.HiRequest) (*pb.HiReply, error)
	NegotiateKey(ctx context.Context, req *pb.NegotiateRequest) (*pb.NegotiateReply, error)
	//Chat(ctx context.Context, req *pb.IceboxMessage) (*pb.IceboxMessage, error)
	CheckDevice(ctx context.Context, req *pb.CheckRequest) (*pb.CheckReply, error)
	InitDevice(ctx context.Context, req *pb.InitRequest) (*pb.InitReply, error)
}

type iceHelper struct {
	negotiated bool
	id string
	db *gorm.DB
	session *Session
	// features
	features map[CoinID] models.Coin

	// formulas
	formulas map[CoinID][]*models.Address
}

func newHelper() *iceHelper {
	d := &iceHelper{
		negotiated: false,
		session: new(Session),
	}

	id := guid.New96()
	d.id = hex.EncodeToString(id.Bytes())
	return d
}

func (s *iceHelper) Hello(ctx context.Context, req *pb.HiRequest) (*pb.HiReply, error) {
	if common.App_magic == req.GetMagicA() {
		reply := pb.NewHiReply(common.Device_magic)
		return reply, nil
	}
	return nil, errors.New("Unknown app!")
}

func (s *iceHelper) NegotiateKey(ctx context.Context, req *pb.NegotiateRequest) (*pb.NegotiateReply, error) {

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
	//reply := pb.NewNegotiateReply(req, pk.Compress())
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
	h := sha256.New()
	h.Write(pkB.SerializeCompressed())
	reply := pb.NewNegotiateReply(bpkB, base58.Encode(h.Sum(nil)))

	return reply, nil
}

func (s *IcebergHandler) StartSession(ctx context.Context, req *pb.StartRequest) (*pb.StartReply, error) {

	return nil, errors.New("Not implemented!")
}

func handleError(err error) *pb.IceboxMessage {
	payload := []byte(err.Error())
	//logger.Fatal().Err(err).Msgf("Failed to unmarshall . Sending %s", pb.IceboxMessage_ERROR)
	msg := pb.NewIceboxMessage(pb.IceboxMessage_ERROR, payload)
	return msg
}



func (s *iceHelper) EndSession(ctx context.Context, req *pb.EndRequest) (*pb.EndReply, error) {
	return nil, errors.New("Not implemented!")
}

////////////////////////////////// Bussiness Logic ////////////////////////////////////////

func (s *iceHelper) CheckDevice(ctx context.Context, req *pb.CheckRequest) (*pb.CheckReply, error) {
	// check device is initialized

	if !s.isInitialized() {
		// return uninit
		// zero := int32(0)
		reply := pb.NewCheckReply(0,nil)
		return reply, nil
	}

	// 初步判断依据初始化了，需要获取深度数据以进行检测
	devid, _ := s.loadDeviceID(common.Devid_path)
	//one := int32(1)
	reply := pb.NewCheckReply(1, &devid)
	return reply, nil
}


func (s *iceHelper) InitDevice(ctx context.Context, req *pb.InitRequest) (*pb.InitReply, error) {
	// remove all files
	s.resetDevice()

	//fmt.Println("==> start init device")
	// new devid and privkey
	devid, err := s.newDeviceID(common.Devid_path)
	if err != nil {
		return nil, err
	}
	_, err = s.newPrivKey(common.Secret_path, *(req.Password))
	if err != nil {
		return nil, err
	}
	_, err = s.initDB(common.Db_path)
	if err != nil {
		return nil, err
	}

	reply := pb.NewInitReply(devid)
	fmt.Println("==> done init device")

	return reply, nil
}

func (s *iceHelper) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingReply, error)  {
	reply := pb.NewPingReply()
	return reply, nil
}

func (s *iceHelper) AddCoin(ctx context.Context, req *pb.AddCoinRequest) (*pb.AddCoinReply, error)  {
	tp := req.GetType()
	idx := req.GetIdx()
	symbol := req.GetSymbol()
	name := req.GetName()
	s.openDb().Create(&models.Coin{T2: tp, T3: idx, Symbol: symbol, Name: name})
	reply := pb.NewAddCoinReply()
	return reply, nil
}

func (s *iceHelper) CreateAddress(ctx context.Context, req *pb.CreateAddressRequest) (*pb.CreateAddressReply, error)  {

	tp := req.GetType()
	idx := req.GetIdx()
	name := req.GetName()
	pwd := req.GetPassword()
	// 需要首先判断是否支持该币种
	var cnt int
	s.openDb().Model(&models.Coin{}).Where("t2 = ?", tp).Count(&cnt)
	if cnt <= 0 {
		return nil, errors.New("Unsupported coin type: " + string(tp))
	}

	s.db.Create(&models.Address{T2: tp, T5: idx, Name: name})
	//p := models.GetPath(s.db, tp, idx)
	addr, err := s.generateAddress(tp, idx, pwd)
	if err != nil {
		return nil, err
	}
	reply := pb.NewCreateAddressReply(*addr)
	return reply, nil
}

func (s *iceHelper) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.CreateSecretReply, error)  {

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
	//reply := pb.NewCreateAddressReply(req, p)
	//return reply, nil
	return nil, errors.New("Not implemented!")
}

func (s *iceHelper) ListCoin(context.Context, *pb.ListCoinRequest) (*pb.ListCoinReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceHelper) ListSecret(context.Context, *pb.ListSecretRequest) (*pb.ListSecretReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceHelper) ListAddress(ctx context.Context, req *pb.ListAddressRequest) (*pb.ListAddressReply, error)  {
	tp := req.GetType()
	idx := req.GetIdx()
	pass := req.GetPassword()

	var cnt int
	s.openDb().Model(&models.Address{}).Where("t2 = ? AND t5 = ?", tp, idx).Count(&cnt)
	if cnt <= 0 {
		return nil, errors.New(fmt.Sprintf("Address %d not exists for coin type: %d", idx, tp))
	}

	x := &pb.Address{Type: pb.NewUInt32(tp), Idx: pb.NewUInt32(idx)}
	//a.SAddr
	x.SAddr, _ = s.generateAddress(tp, idx, pass)

	addrs := make([]*pb.Address, 1)
	addrs = append(addrs, x)
	reply := pb.NewListAddressReply(uint32(cnt), addrs)
	return reply, nil
}

func (s *iceHelper) SignTx(ctx context.Context, req *pb.SignTxRequest) (*pb.SignTxReply, error)  {
	tp := req.GetType()
	idx := req.GetIdx()
	amount := req.GetAmount()
	dest := req.GetDest()
	txid := req.GetTxid()
	pass := req.GetPassword()

	var cnt int
	s.openDb().Model(&models.Address{}).Where("t2 = ? AND t5 = ?", tp, idx).Count(&cnt)
	if cnt <= 0 {
		return nil, errors.New(fmt.Sprintf("Address %d not exists for coin type: %d", idx, tp))
	}

	subKey, _ := s.generateSubPrivKey(tp, idx, pass)
	xk, _ := subKey.ECPrivKey()
	wif, err := coinutil.NewWIF(xk, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, err
	}
	tx, err := CreateTransaction(wif.String(), dest, int64(amount), txid)
	if err != nil {
		return nil, err
	}
	reply := pb.NewSignTxReply(tx.SignedTx)
	return reply, nil
}

func (s *iceHelper) RemoveCoin(context.Context, *pb.RemoveCoinRequest) (*pb.RemoveCoinReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceHelper) DeleteSecret(context.Context, *pb.DeleteSecretRequest) (*pb.DeleteSecretReply, error)  {
	return nil, errors.New("Not implemented!")
}

//func (s *IcebergHandler) DeleteFormula(context.Context, *pb.DeleteFormulaRequest) (*pb.DeleteFormulaReply, error)  {
//	return nil, errors.New("Not implemented!")
//}

func (s *iceHelper) ResetDevice(ctx context.Context, req *pb.ResetRequest) (*pb.ResetReply, error)  {
	// reset device: remove all files
	err := s.resetDevice()
	if err != nil {
		return nil, err
	}

	reply := pb.NewResetReply()
	return reply, nil
}

//////////////////////////////////////////////////////////////////////////////

func (s *iceHelper) openDb() *gorm.DB {
	if s.db == nil {
		db, err := gorm.Open("sqlite3", common.Db_path)
		if err != nil {
			return nil
			//errors.New("Failed to connect database")
		}
		s.db = db
	}
	return s.db
}

func (s *iceHelper) generateSessionKey(r string) *bip32.ExtendedKey {
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

func (s *iceHelper) resetDevice() (err error) {
	// remove all files in device
	if exists(common.Devid_path) {
		err = os.Remove(common.Devid_path)
		if err != nil {
			return err
		}
	}
	if exists(common.Secret_path) {
		err = os.Remove(common.Secret_path)
		if err != nil {
			return err
		}
	}
	if exists(common.Db_path) {
		err = os.Remove(common.Db_path)
		if err != nil {
			return err
		}
	}

	fmt.Println("==> done reset device")
	return nil
}

func (s *iceHelper) newDeviceID(dfn string) (string, error) {
	id := guid.New96()
	s.id = hex.EncodeToString(id.Bytes())
	// serialize to file
	err := ioutil.WriteFile(dfn, []byte(s.id), 0644)
	return s.id, err
}

func (s *iceHelper) loadDeviceID(dfn string) (sid string, err error) {
	var data []byte
	data, err = ioutil.ReadFile(dfn)
	if err != nil {
		return "", err
	}

	sid = string(data)
	return sid, err
}

func (s *iceHelper) newPrivKey(sfn, password string) (key *address.PrivateKey, err error) {
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
		//sk := masterKey.String()
		encrypted, err := BIP32Encrypt(masterKey, password)
		if err != nil {
			return nil, err
		}
		//secret := bip38.Encrypt(key, password)
		err = ioutil.WriteFile(sfn, []byte(*encrypted), 0644)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	return nil, errors.New("Invalid private key.")
}

func (s *iceHelper) generateSubPrivKey(tp, idx uint32, password string) (*bip32.ExtendedKey, error)  {
	masterKey, err := s.loadSecretKey(common.Secret_path, password)
	if err != nil {
		return nil, err
	}
	privk, _ := masterKey.ECPrivKey2()
	logger.Debug().Msgf("priv key: %s, address: %s", privk, privk.Address())
	// 两种地址不兼容
	nk, err := bip44.NewKeyFromMasterKey(masterKey, tp, 0, 0, idx)
	if err != nil {
		return nil, err
	}

	return nk, nil
}

// 使用内部的主私钥来生成新地址
func (s *iceHelper) generateAddress(tp, idx uint32, password string) (*string, error)  {
	masterKey, err := s.loadSecretKey(common.Secret_path, password)
	if err != nil {
		return nil, err
	}
	privk, _ := masterKey.ECPrivKey2()
	logger.Debug().Msgf("priv key: %s, address: %s", privk, privk.Address())
	// 两种地址不兼容
	nk, err := bip44.NewKeyFromMasterKey(masterKey, tp, 0, 0, idx)
	if err != nil {
		return nil, err
	}
	addr, _ := nk.Address(&chaincfg.MainNetParams)
	a := addr.EncodeAddress()
	return &a, nil
}

func (s *iceHelper) loadSecretKey(fn, password string) (key *bip32.ExtendedKey, err error) {
	var data []byte
	data, err = ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	key, err = BIP32Decrypt(string(data), password)
	return key, err
}

func (s *iceHelper) initDB(fn string) (db *gorm.DB, err error) {
	db, err = gorm.Open("sqlite3", fn)
	if err != nil {
		return nil, err
		//errors.New("Failed to connect database")
	}

	// Migrate the schema
	db.AutoMigrate(&models.Coin{})
	db.AutoMigrate(&models.Address{})
	db.AutoMigrate(&models.Secret{})

	// Create
	db.Create(&models.Coin{T2: 0, Symbol: "btc", Name: "bitcoin"})
	db.Create(&models.Coin{T2: 1, Symbol: "test", Name: "testnet"})
	db.Create(&models.Coin{T2: 2, Symbol: "ltc", Name: "litecoin"})
	db.Create(&models.Coin{T2: 3, Symbol: "doge", Name: "dogecoin"})
	db.Create(&models.Coin{T2: 5, Symbol: "dsh", Name: "dash"})
	db.Create(&models.Coin{T2: 9, Symbol: "xcp", Name: "counterparty"})
	db.Create(&models.Coin{T2: 60, Symbol: "eth", Name: "ethereum"})
	db.Create(&models.Coin{T2: 61, Symbol: "etc", Name: "ethereum classic"})

	s.db = db
	return db, err
}

func (s *iceHelper) isInitialized() bool {
	if !exists(common.Devid_path) {
		return false
	}
	if !exists(common.Secret_path) {
		return false
	}
	if !exists(common.Db_path) {
		return false
	}

	return true
}

func BIP32Encrypt(p *bip32.ExtendedKey, passphrase string) (*string, error) {
	//bip38 := new(BIP38Key)

	sp := p.String()
	ah := address.Hash256([]byte(sp))[:4]
	dh, _ := scrypt.Key([]byte(passphrase), ah, 16384, 8, 8, 64)

	//bip38.Flag = byte(0xC0)
	buf := new(bytes.Buffer)
	buf.Write(ah)
	es, err := crypto.Encrypt(dh[:32], sp)
	if err != nil {
		return nil, err
	}
	buf.WriteString(es)
	bs := base58.Encode(buf.Bytes())

	return &bs, nil
}

func BIP32Decrypt(data string, passphrase string) (*bip32.ExtendedKey, error) {
	//bip38 := new(BIP38Key)

	ds := base58.Decode(data)
	//buf := bytes.NewBuffer(ds)
	ah := ds[:4]
	//sp := p.String()
	//ah := address.Hash256([]byte(sp))[:4]
	dh, _ := scrypt.Key([]byte(passphrase), ah, 16384, 8, 8, 64)

	//bip38.Flag = byte(0xC0)
	ct, err := crypto.Decrypt(dh[:32], string(ds[4:]))
	if err != nil {
		return nil, err
	}
	ks, err := bip32.NewKeyFromString(ct)
	return ks, err
}

