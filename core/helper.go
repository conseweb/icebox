package core

import (
	"bytes"
	"github.com/conseweb/coinutil/bip32"
	"github.com/conseweb/coinutil/base58"
	"github.com/conseweb/coinutil/bip44"
	"github.com/conseweb/coinutil/bip39"
	"github.com/conseweb/icebox/common/crypto"
	"github.com/conseweb/icebox/core/models"
	"github.com/conseweb/icebox/common/guid"
	"encoding/hex"
	"github.com/conseweb/icebox/core/common"
	"fmt"
	"github.com/conseweb/icebox/common/address"
	"github.com/jinzhu/gorm"
	"encoding/binary"
	"os"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"errors"
	"github.com/conseweb/coinutil"
	"golang.org/x/net/context"
	pb "github.com/conseweb/icebox/protos"
	"math/rand"
	"time"

	"github.com/conseweb/icebox/common/crypto/koblitz/kelliptic"
	"github.com/conseweb/btcd/btcec"
	"crypto/sha256"
	_ "github.com/mattn/go-sqlite3"  // must exists, or will cause -- sql: unknown driver "sqlite3"

	"github.com/gogo/protobuf/proto"
	"github.com/conseweb/icebox/core/paginator"
	"github.com/conseweb/icebox/core/env"
)

//go:generate mockgen -source=helper.go -destination=../mocks/mock_Iceberg.go -package=mocks github.com/conseweb/icebox/core Iceberg


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
	keyA := req.GetKeyA()
	hashA := req.GetHash()
	logger.Debug().Msgf("Received keyA: %s, hash is: %s", keyA, hashA)

	r := fmt.Sprintf("%d", makeTimestamp())
	ek := s.generateSessionKey(r)
	sk, err := ek.ECPrivKey()
	if err != nil {
		return nil, err
	}

	var pkA = new(address.PublicKey)
	pkA.Curve = kelliptic.S256()
	cp := base58.Decode(keyA)

	pk, err := btcec.ParsePubKey(cp, btcec.S256())
	if err != nil {
		return nil, err
	}

	s.session.peerKey = pk

	spk := pk.SerializeCompressed()
	bpk := base58.Encode(spk)
	if bpk == keyA {
		logger.Debug().Msgf("Encode ok!")
	}

	//shared := address.NewPublickKey("256")
	sk2, err := btcec.NewPrivateKey(btcec.S256())
	shared := sk2.PubKey()
	shared.X, shared.Y = shared.ScalarMult(pk.X, pk.Y, sk.Serialize())
	s.session.sharedKey = shared

	ssk := shared.SerializeCompressed()
	s.session.id = binary.LittleEndian.Uint32(ssk)
	// generate aes key
	s.session.shortKey = base58.Encode(ssk)[:common.SharedKey_Len]

	logger.Debug().Msgf("Got shared key: %s", s.session.shortKey)
	pkB := sk.PubKey()
	bpkB := base58.Encode(pkB.SerializeCompressed())
	logger.Debug().Msgf("Iceberg's public session key: %s", bpkB)
	h := sha256.New()
	h.Write(pkB.SerializeCompressed())
	reply := pb.NewNegotiateReply(bpkB, base58.Encode(h.Sum(nil)))

	return reply, nil
}

func (s *iceHelper) StartSession(ctx context.Context, req *pb.StartRequest) (*pb.StartReply, error) {

	reply := pb.NewStartReply()
	return reply, nil
}

func handleError(err error) *pb.IceboxMessage {
	xe := pb.NewError(500, err.Error())
	payload, _ := proto.Marshal(xe)
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
	//idx := req.GetIdx()
	pwd := req.GetPassword()
	// 需要首先判断是否支持该币种
	var cnt int
	s.openDb().Model(&models.Coin{}).Where("t2 = ?", tp).Count(&cnt)
	if cnt <= 0 {
		return nil, errors.New("Unknew coin type: " + string(tp))
	}

	rand.Seed(time.Now().UnixNano())
	var idx int32
	for {
		idx = rand.Int31()
		if !s.dbAddrExists(tp, idx) {
			s.db.Create(&models.Address{T2: tp, T5: uint32(idx)})
			//p := models.GetPath(s.db, tp, idx)
			addr, err := s.generateAddress(tp, uint32(idx), pwd)
			if err != nil {
				return nil, err
			}
			reply := pb.NewCreateAddressReply(tp, uint32(idx), *addr)
			return reply, nil
		}
	}

}

func (s *iceHelper) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.CreateSecretReply, error)  {

	pwd := req.GetPassword()
	site := req.GetSite()
	account := req.GetAccount()

	rand.Seed(time.Now().UnixNano())
	var idx int32
	for {
		idx = rand.Int31()
		if !s.dbSecretExists(site, account, idx) {
			s.db.Create(&models.Secret{T1: 0, T2: site, T3: account, T4: uint32(idx)})
			//p := models.GetPath(s.db, tp, idx)
			secret, err := s.generateAddress(site, uint32(idx), pwd)
			if err != nil {
				return nil, err
			}

			reply := pb.NewCreateSecretReply(0, site, account, uint32(idx), []byte(*secret))
			return reply, nil
		}
	}
}

func (s *iceHelper) ListCoin(context.Context, *pb.ListCoinRequest) (*pb.ListCoinReply, error)  {
	return nil, errors.New("Not implemented!")
}

func (s *iceHelper) ListSecret(ctx context.Context, req *pb.ListSecretRequest) (*pb.ListSecretReply, error)  {
	tp := req.GetType()
	site := req.GetSite()
	account := req.GetAccount()
	//idx := req.GetIdx()
	pass := req.GetPassword()
	offset := req.GetOffset()
	limit := req.GetLimit()
	db := s.openDb()

	var totalRecords int
	if s.dbSecretExists(site, account, -1) {
		db.Model(&models.Secret{}).Where("t2 = ?", site).Count(&totalRecords)
		if totalRecords <= 0 {
			return nil, errors.New(fmt.Sprintf("Not secret exists for type: %d", tp))
		}
	}

	totalPages := uint32(totalRecords) / limit
	if uint32(totalRecords) % limit > 0 {
		totalPages += 1
	}

	addrs2 := make([]*pb.Secret, limit)

	addrs := []models.Secret{}
	//order_by := []string{"ID asc"}
	//db = db.Order(order_by)
	db.Model(&models.Secret{}).Where("t2 = ?", site).Limit(limit).Offset(offset).Find(&addrs)

	for i, _ := range addrs {
		//db.Model(addrs[i])
		x := new(pb.Secret)
		x.Type = pb.NewUInt32(addrs[i].T1)
		x.Site = pb.NewUInt32(addrs[i].T2)
		x.Account = pb.NewUInt32(addrs[i].T3)
		x.Idx = pb.NewUInt32(addrs[i].T4)
		SSecret, err := s.generateAddress(addrs[i].T2, addrs[i].T4, pass)
		if err != nil {
			return nil, err
		}
		x.SSecret = []byte(*SSecret)
		addrs2[i] = x
	}

	if uint32(totalRecords) <= limit {
		reply := pb.NewListSecretReply(uint32(totalRecords), uint32(totalPages), uint32(totalRecords), limit, addrs2)
		return reply, nil
	} else {
		reply := pb.NewListSecretReply(uint32(totalRecords), uint32(totalPages), offset+limit, limit, addrs2)
		return reply, nil
	}
}

func (s *iceHelper) ListAddress(ctx context.Context, req *pb.ListAddressRequest) (*pb.ListAddressReply, error)  {
	tp := req.GetType()
	//idx := req.GetIdx()
	pass := req.GetPassword()
	offset := req.GetOffset()
	limit := req.GetLimit()
	db := s.openDb()

	var totalRecords int
	if s.dbAddrExists(tp, -1) {
		db.Model(&models.Address{}).Where("t2 = ?", tp).Count(&totalRecords)
		if totalRecords <= 0 {
			return nil, errors.New(fmt.Sprintf("Not address exists for coin type: %d", tp))
		}
	}

	totalPages := paginator.GetTotalPages(uint32(totalRecords), limit)

	addrs2 := make([]*pb.Address, limit)

	addrs := []models.Address{}
	//order_by := []string{"ID asc"}
	//db = db.Order(order_by)
	db.Model(&models.Address{}).Where("t2 = ?", tp).Limit(limit).Offset(offset).Find(&addrs)

	for i, _ := range addrs {
		x := new(pb.Address)
		x.Type = pb.NewUInt32(addrs[i].T2)
		x.Idx = pb.NewUInt32(addrs[i].T5)
		var err error
		x.SAddr, err = s.generateAddress(addrs[i].T2, addrs[i].T5, pass)
		if err != nil {
			return nil, err
		}
		addrs2[i] = x
	}

	if uint32(totalRecords) <= limit {
		reply := pb.NewListAddressReply(uint32(totalRecords), uint32(totalPages), uint32(totalRecords), limit, addrs2)
		return reply, nil
	} else {
		reply := pb.NewListAddressReply(uint32(totalRecords), uint32(totalPages), offset+limit, limit, addrs2)
		return reply, nil
	}
}

func (s *iceHelper) GetAddress(ctx context.Context, req *pb.GetAddressRequest) (*pb.GetAddressReply, error)  {
	tp := req.GetType()
	pass := req.GetPassword()
	idx := req.GetIdx()
	db := s.openDb()

	var totalRecords int
	if s.dbAddrExists(tp, -1) {
		db.Model(&models.Address{}).Where("t2 = ?", tp).Count(&totalRecords)
		if totalRecords <= 0 {
			return nil, errors.New(fmt.Sprintf("Not address exists for coin type: %d", tp))
		}
	}

	saddr, err := s.generateAddress(tp, idx, pass)
	if err != nil {
		return nil, err
	}

	pbAddr := pb.Address{Type:&tp, Idx:&idx, SAddr:saddr}
	reply := pb.NewGetAddressReply(pbAddr)
	return reply, nil
}

func (s *iceHelper) SignMsg(ctx context.Context, req *pb.SignMsgRequest) (*pb.SignMsgReply, error)  {
	msg := req.GetMessage()
	tp := req.GetType()
	idx := req.GetIdx()
	pass := req.GetPassword()
	db := s.openDb()

	var cnt int
	if s.dbAddrExists(tp, -1) {
		db.Model(&models.Address{}).Where("t2 = ?", tp).Count(&cnt)
		if cnt <= 0 {
			return nil, errors.New(fmt.Sprintf("Address %d not exists for coin type: %d", idx, tp))
		}
	}

	subKey, _ := s.generateSubPrivKey(tp, idx, pass)
	xk, _ := subKey.ECPrivKey()
	//logger.Debug().Msgf("PrivKey: %s, WIF: %s", hex.EncodeToString(xk.Serialize()), wif.String())
	signed, err := CreateSignedMessage(xk, msg)
	if err != nil {
		return nil, err
	}
	reply := pb.NewSignMsgReply(signed)
	return reply, nil
}

func (s *iceHelper) SignTx(ctx context.Context, req *pb.SignTxRequest) (*pb.SignTxReply, error)  {
	tp := req.GetType()
	idx := req.GetIdx()
	amount := req.GetAmount()
	dest := req.GetDest()
	txhash := req.GetTxHash()
	txidx := req.GetTxIdx()
	pass := req.GetPassword()
	db := s.openDb()

	var cnt int
	if s.dbAddrExists(tp, -1) {
		db.Model(&models.Address{}).Where("t2 = ?", tp).Count(&cnt)
		if cnt <= 0 {
			return nil, errors.New(fmt.Sprintf("Address %d not exists for coin type: %d", idx, tp))
		}
	}

	subKey, _ := s.generateSubPrivKey(tp, idx, pass)
	xk, _ := subKey.ECPrivKey()
	//net := env.RTEnv.GetNet()
	//wif, err := coinutil.NewWIF(xk, net, true)
	//if err != nil {
	//	return nil, err
	//}
	//logger.Debug().Msgf("PrivKey: %s, WIF: %s", hex.EncodeToString(xk.Serialize()), wif.String())
	// TODO: txhash should be generated from transaction

	out := TxOutput{amount, dest}
	in := TxInput{txhash, txidx}
	tx, err := CreateSignedTx(xk, &in, &out, true)
	if err != nil {
		return nil, err
	}
	stx, _ := hex.DecodeString(tx.SignedTx)
	reply := pb.NewSignTxReply(stx)
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

	net := env.RTEnv.GetNet()
	masterKey, _ := bip32.NewMaster(seed, net)

	pk, _ := masterKey.ECPubKey()
	pkHash := coinutil.Hash160(pk.SerializeCompressed())
	s.session.key, _ = masterKey.ECPrivKey()
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
	if exists(common.Debug_path) {
		err = os.Remove(common.Debug_path)
		if err != nil {
			return err
		}
	}

	fmt.Println("==> done reset device")
	return nil
}

func (s *iceHelper) newDeviceID(dfn string) ([]byte, error) {
	id := guid.New96()
	s.id = hex.EncodeToString(id.Bytes())
	// serialize to file
	err := ioutil.WriteFile(dfn, []byte(s.id), 0644)
	return id.Bytes(), err
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

	net := env.RTEnv.GetNet()
	masterKey, err := bip32.NewMaster(seed, net)
	if err != nil {
		for {
			if err == bip32.ErrUnusableSeed {
				masterKey, err = bip32.NewMaster(seed, net)
				if err == nil {
					break
				}
			} else {
				return nil, err
			}
		}
	}
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

		if env.RTEnv.IsDebug() && env.RTEnv.IsTestNet() {
			out := fmt.Sprintln("Mnemonic: ", mnemonic)
			out += fmt.Sprintln("Master private key: ", masterKey)
			out += fmt.Sprintln("Master public key: ", publicKey)

			ioutil.WriteFile(common.Debug_path, []byte(out), 0644)
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
	//privk, _ := masterKey.ECPrivKey2()
	//privk, _ := masterKey.ECPrivKey()
	//net := env.RTEnv.GetNet()
	//apkh, _ := masterKey.Address(net)

	// 两种地址不兼容
	nk, err := bip44.NewKeyFromMasterKey(masterKey, tp, 0, 0, idx)
	if err != nil {
		return nil, err
	}

	var aph *coinutil.AddressPubKeyHash
	privk, _ := nk.ECPrivKey()
	hexPrivK := hex.EncodeToString(privk.Serialize())
	pubk, _ := nk.ECPubKey()
	hexPubK := hex.EncodeToString(pubk.SerializeCompressed())
	net := env.RTEnv.GetNet()
	aph, _ = nk.Address(net)
	a := aph.EncodeAddress()
	logger.Debug().Msgf("SubprivKey: %s, pubKey: %s, address: %s, type: %d, idx: %d", hexPrivK, hexPubK, a, tp, idx)

	return nk, nil
}

// 使用内部的主私钥来生成新地址
func (s *iceHelper) generateAddress(tp, idx uint32, password string) (*string, error)  {
	masterKey, err := s.loadSecretKey(common.Secret_path, password)
	if err != nil {
		return nil, err
	}
	// 两种地址不兼容
	nk, err := bip44.NewKeyFromMasterKey(masterKey, tp, 0, 0, idx)
	if err != nil {
		return nil, err
	}
	var aph *coinutil.AddressPubKeyHash
	net := env.RTEnv.GetNet()
	aph, _ = nk.Address(net)
	a := aph.EncodeAddress()
	logger.Debug().Msgf("Generated address: %s", a)
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

func (s *iceHelper) dbCoinExists(tp uint32) bool  {
	var cnt int
	s.openDb().Model(&models.Coin{}).Where("t2 = ?", tp).Count(&cnt)
	if cnt <= 0 {
		return false
	}
	return true
}

func (s *iceHelper) dbAddrExists(tp uint32, idx int32) bool  {
	var cnt int
	if idx < 0 {
		s.openDb().Model(&models.Address{}).Where("t2 = ?", tp).Count(&cnt)
		if cnt <= 0 {
			return false
		}
		return true
	}
	s.openDb().Model(&models.Address{}).Where("t2 = ? AND t5 = ?", tp, idx).Count(&cnt)
	if cnt <= 0 {
		return false
	}
	return true
}

func (s *iceHelper) dbSecretExists(site, account uint32, idx int32) bool  {
	var cnt int
	if idx < 0 {
		s.openDb().Model(&models.Secret{}).Where("t2 = ? AND t3 = ?", site, account).Count(&cnt)
		if cnt <= 0 {
			return false
		}
		return true
	}
	s.openDb().Model(&models.Secret{}).Where("t2 = ? AND t3 = ? AND t4 = ?", site, account, idx).Count(&cnt)
	if cnt <= 0 {
		return false
	}
	return true
}

func BIP32Encrypt(p *bip32.ExtendedKey, passphrase string) (*string, error) {
	//bip38 := new(BIP38Key)

	sp := p.String()
	ah := address.DHash256([]byte(sp))[:4]
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
	//ah := address.DHash256([]byte(sp))[:4]
	dh, _ := scrypt.Key([]byte(passphrase), ah, 16384, 8, 8, 64)

	//bip38.Flag = byte(0xC0)
	ct, err := crypto.Decrypt(dh[:32], string(ds[4:]))
	if err != nil {
		return nil, err
	}
	ks, err := bip32.NewKeyFromString(ct)
	return ks, err
}

func Hash256(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte(b))
	return h.Sum(nil)
}


func DoubleHash256(b []byte) []byte {
	h1 := sha256.New()
	h1.Write([]byte(b))

	h2 := sha256.New()
	h2.Write(h1.Sum(nil))

	return h2.Sum(nil)
}
