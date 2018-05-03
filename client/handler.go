package main

import (
	"conseweb.com/wallet/icebox/common/fsm"
	pb "conseweb.com/wallet/icebox/protos"
	"google.golang.org/grpc"
	"time"
	"conseweb.com/wallet/icebox/coinutil/bip32"
	"conseweb.com/wallet/icebox/core/common"
	"fmt"
	"conseweb.com/wallet/icebox/common/address"
	"google.golang.org/grpc/grpclog"
	"context"
	"conseweb.com/wallet/icebox/coinutil/base58"
	"github.com/btcsuite/btcd/btcec"
	"conseweb.com/wallet/icebox/coinutil/bip39"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/gogo/protobuf/proto"
	"crypto/sha256"
)

const (
	sessionKeyFn = "session_key.dat"
)

type Session struct {
	id 	uint32 			// session id
	key string			// private key
	peerKey []byte		// peer's public key
	sharedKey []byte	// shared public key
	shortKey string
}

// example FSM for demonstration purposes.
type Handler struct {
	opts   []grpc.DialOption
	session *Session
	To     string
	FSM    *fsm.FSM
	Conn   *grpc.ClientConn
	Client pb.IceboxClient
}


func newUInt32(v uint32) *uint32 {
	var i = v
	return &i
}

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func NewHandler(to string, opts []grpc.DialOption) *Handler {
	d := &Handler{
		To: to,
		opts: opts,
		session: new(Session),
	}

	// est_unchecked : established and unchecked
	// est_uninited : established and uninited
	// est_inited : established and inited
	d.FSM = fsm.NewFSM(
		"created",
		fsm.Events{
			{Name: "CREATE", Src: []string{"created"}, Dst: "unplugged"},
			{Name: "IN", Src: []string{"unplugged"}, Dst: "plugged"},
			{Name: "OUT", Src: []string{"plugged", "confirmed", "negotiated", "est_unchecked", "est_inited", "est_uninited"}, Dst: "unplugged"},
			{Name: "HELLO", Src: []string{"plugged"}, Dst: "confirmed"},
			{Name: "NEGOTIATE", Src: []string{"confirmed"}, Dst: "negotiated"},
			{Name: "START", Src: []string{"negotiated"}, Dst: "est_unchecked"},
			{Name: "CK_INITED", Src: []string{"est_unchecked"}, Dst: "est_inited"},
			{Name: "CK_UNINITED", Src: []string{"est_unchecked"}, Dst: "est_uninited"},
			{Name: "INIT", Src: []string{"est_uninited"}, Dst: "est_inited"},
			{Name: "EXECUTE", Src: []string{"est_inited"}, Dst: "est_inited"},
			{Name: "END", Src: []string{"est_unchecked", "est_inited", "est_uninited"}, Dst: "plugged"},
			{Name: "TIMEOUT", Src: []string{"est_unchecked", "est_inited", "est_uninited"}, Dst: "plugged"},
		},
		fsm.Callbacks{
			"enter_state":  func(e *fsm.Event) { d.enterState(e, d.FSM.Current()) },
			"enter_created":  func(e *fsm.Event) { d.enterCreated(e, d.FSM.Current()) },
			"enter_unplugged":  func(e *fsm.Event) { d.enterUnplugged(e, d.FSM.Current()) },
			"before_HELLO": func(e *fsm.Event) { d.beforeHello(e, d.FSM.Current()) },
			"after_HELLO":  func(e *fsm.Event) { d.afterHello(e, d.FSM.Current()) },
			"before_PING":  func(e *fsm.Event) { d.beforePing(e, d.FSM.Current()) },
			"after_PING":   func(e *fsm.Event) { d.afterPing(e, d.FSM.Current()) },
		},
	)

	return d
}

func (d *Handler) Connect() error {
	var err error
	d.Conn, err = grpc.Dial(*serverAddr, d.opts...)
	if err != nil {
		return err
	}
	//defer d.Conn.Close()

	d.Client = pb.NewIceboxClient(d.Conn)

	return nil
}

func (d *Handler) enterState(e *fsm.Event, state string) {

	logger.Debug().Msgf("Enter %s from %s, fired by event %s\n", e.Dst, e.Src, e.Event)
}

func (d *Handler) enterCreated(e *fsm.Event, state string) {

	logger.Debug().Msgf("Enter %s from %s, fired by event %s\n", e.Dst, e.Src, e.Event)
}

func (d *Handler) enterUnplugged(e *fsm.Event, state string) {

	logger.Debug().Msgf("Enter %s from %s, fired by event %s\n", e.Dst, e.Src, e.Event)
}

func (d *Handler) beforeHello(e *fsm.Event, state string) {
	logger.Debug().Msgf("Before %s, dest is %s, current is %s", e.Event, e.Dst, state)
	//logger.Debugf("Before reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
}

func (d *Handler) afterHello(e *fsm.Event, state string) {
	logger.Debug().Msgf("After %s, dest is %s, current is %s", e.Event, e.Dst, state)
	//logger.Debugf("After reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
}

func (d *Handler) afterPing(e *fsm.Event, state string) {
	logger.Debug().Msgf("After %s, dest is %s, current is %s", e.Event, e.Dst, state)
}

func (d *Handler) beforePing(e *fsm.Event, state string) {
	logger.Debug().Msgf("Before %s, dest is %s, current is %s", e.Event, e.Dst, state)
}

func (d *Handler) handleMessage() error {
	return nil
}

func (d *Handler) processStream() error {
	return nil
}


func (d *Handler) generateSessionKey(r string) *bip32.ExtendedKey {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)

	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	// 此处password只是需要外部提供一个不确定的输入，以增强安全性，并不用做加密
	seed := bip39.NewSeed(mnemonic, r)

	masterKey, _ := bip32.NewMaster(seed, &chaincfg.MainNetParams)
	publicKey, _ := masterKey.ECPubKey()

	// Display mnemonic and keys
	logger.Info().Msgf("Mnemonic: %s", mnemonic)
	logger.Info().Msgf("Master private key: %s", masterKey.String())
	pkb := publicKey.SerializeCompressed()

	logger.Info().Msgf("Length: %d, Master public key: %s", len(pkb), base58.Encode(pkb))
	logger.Info().Msgf("Master public key: %s", address.ToBase58(pkb, len(pkb)))

	//secret := masterKey.String()
	//_ = ioutil.WriteFile(sessionKeyFn, []byte(secret), 0644)
	d.session.key = masterKey.String()
	return masterKey
}


func (d *Handler) Hello() *pb.HiReply {
	var err error
	req := pb.NewHiRequest(common.App_magic)
	payload, _ := proto.Marshal(req)
	ct := pb.NewIceboxMessage(pb.IceboxMessage_HELLO, payload)

	res, err := d.Client.Chat(context.Background(), ct)
	if err != nil {
		//grpclog.Fatalln(err)
		grpclog.Fatalf("%v.Chat(_) = _, %v: ", d.Client, err)
	}
	grpclog.Infoln("HiReply: ", res)

	var result = &pb.HiReply{}
	err = proto.Unmarshal(res.GetPayload(), result)
	if err != nil {
		return nil
	}
	return result
}

func (d *Handler) Negotiate() (*pb.NegotiateReply, error) {
	var err error
	// generate public key
	r := fmt.Sprintf("%d", makeTimestamp())
	mk := d.generateSessionKey(r)
	sk, _ := mk.ECPrivKey()
	pk, err := mk.ECPubKey()
	if err != nil {
		logger.Fatal().Err(err).Msg("")
		return nil, err
	}
	b := pk.SerializeCompressed()
	//bs := address.ToBase58(b, len(b))
	bs := base58.Encode(b)
	logger.Debug().Msgf("Base58 raw public string: '%s'", bs)
	h := sha256.New()
	h.Write([]byte(b))
	hb := h.Sum(nil)
	req := pb.NewNegotiateRequest(bs, base58.Encode(hb))
	payload, _ := proto.Marshal(req)
	x := pb.NewIceboxMessage(pb.IceboxMessage_NEGOTIATE, payload)
	res, err := d.Client.Chat(context.Background(), x)
	if err != nil {
		grpclog.Fatalf("%v.Negotiate(_) = _, %v: ", d.Client, err)
		return nil, err
	}

	var result = &pb.NegotiateReply{}
	err = proto.Unmarshal(res.GetPayload(), result)
	if err != nil {
		logger.Fatal().Err(err).Msg("")
		return nil, err
	}
	logger.Debug().Msgf("NegotiateReply: %s", result)
	kb := result.GetKeyB()
	pkb := base58.Decode(kb)
	pkB, err := btcec.ParsePubKey(pkb, btcec.S256())
	if err != nil {
		logger.Fatal().Err(err).Msg("")
		return nil, err
	}

	shared := address.NewPublickKey("256")
	shared.X, shared.Y = shared.ScalarMult(pkB.X, pkB.Y, sk.Serialize())
	skb := shared.Bytes()
	d.session.sharedKey = skb

	aesKey := base58.Encode(skb[:16])
	d.session.shortKey = aesKey

	logger.Debug().Msgf("Shared key: %s", aesKey)

	return result, nil
}

func (d *Handler) CheckDevice() (*pb.CheckReply, error) {
	var err error
	req := pb.NewCheckRequest()
	payload, _ := proto.Marshal(req)
	ct := pb.NewIceboxMessage(pb.IceboxMessage_CHECK, payload)

	res, err := d.Client.Chat(context.Background(), ct)
	if err != nil {
		grpclog.Fatalf("%v.Chat(_) = _, %v: ", d.Client, err)
	}

	var result = &pb.CheckReply{}
	err = proto.Unmarshal(res.GetPayload(), result)
	if err != nil {
		return nil, err
	}
	grpclog.Infoln("CheckReply: ", result)
	return result, nil
}

func (d *Handler) InitDevice(pas string) (*pb.InitReply, error) {
	// send initrequest
	ireq := pb.NewInitRequest(pas)
	payload, _ := proto.Marshal(ireq)
	ct := pb.NewIceboxMessage(pb.IceboxMessage_INIT, payload)
	irep, xe := d.Client.Chat(context.Background(), ct)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	var intRep = &pb.InitReply{}
	err := proto.Unmarshal(irep.GetPayload(), intRep)
	if err != nil {
		return nil, err
	}

	grpclog.Infoln("InitReply: ", intRep)
	return intRep, nil
}

func (d *Handler) PingDevice() {
	req := pb.NewPingRequest()
	payload, _ := proto.Marshal(req)
	ct := pb.NewIceboxMessage(pb.IceboxMessage_PING, payload)
	res, err := d.Client.Chat(context.Background(), ct)
	if err != nil {
		grpclog.Fatalln(err)
	}

	var pr = &pb.PingReply{}
	err = proto.Unmarshal(res.GetPayload(), pr)
	if err != nil {
		grpclog.Fatalln(err)
	}

	grpclog.Infoln("PingReply: ", pr)
}

func (d *Handler) ResetDevice() {
	var err error
	resetReq := pb.NewResetRequest()
	payload, _ := proto.Marshal(resetReq)
	ct := pb.NewIceboxMessage(pb.IceboxMessage_RESET, payload)
	res, err := d.Client.Chat(context.Background(), ct)
	if err != nil {
		grpclog.Fatalln(err)
	}

	var res1 = &pb.ResetReply{}
	err = proto.Unmarshal(res.GetPayload(), res1)
	if err != nil {
		grpclog.Fatalln(err)
	}
	grpclog.Infoln("ResetReply: ", res1)
}

func (d *Handler) CreateAddress(tp, idx uint32, name, pwd string) (*pb.CreateAddressReply, error) {
	var err error
	req := pb.NewCreateAddressRequest(tp, idx, name, pwd)
	payload, _ := proto.Marshal(req)
	msg := pb.NewIceboxMessage(pb.IceboxMessage_CREATE_ADDRESS, payload)
	irep, xe := d.Client.Chat(context.Background(), msg)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	if irep.GetType() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", irep.GetPayload())
	}

	var caRep = &pb.CreateAddressReply{}
	err = proto.Unmarshal(irep.GetPayload(), caRep)
	if err != nil {
		grpclog.Fatalln(err)
		return nil, err
	}

	grpclog.Infoln("CreateAddressReply: ", caRep)
	return caRep, nil

}

func (d *Handler) ListAddress(tp, idx uint32, pwd string) (*pb.ListAddressReply, error) {
	var err error
	req := pb.NewListAddressRequest(tp, idx, pwd)
	payload, _ := proto.Marshal(req)
	msg := pb.NewIceboxMessage(pb.IceboxMessage_LIST_ADDRESS, payload)
	irep, xe := d.Client.Chat(context.Background(), msg)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	if irep.GetType() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", irep.GetPayload())
	}

	var caRep = &pb.ListAddressReply{}
	err = proto.Unmarshal(irep.GetPayload(), caRep)
	if err != nil {
		grpclog.Fatalln(err)
		return nil, err
	}

	grpclog.Infoln("ListAddressReply: ", caRep)
	return caRep, nil

}

func (d *Handler) SignTx(tp, idx uint32, amount uint64, dest, txid, pwd string) (*pb.SignTxReply, error) {
	var err error
	req := pb.NewSignTxRequest(tp, idx, amount, dest, txid, pwd)
	payload, _ := proto.Marshal(req)
	msg := pb.NewIceboxMessage(pb.IceboxMessage_SIGN_TX, payload)
	irep, xe := d.Client.Chat(context.Background(), msg)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	if irep.GetType() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", irep.GetPayload())
	}

	var caRep = &pb.SignTxReply{}
	err = proto.Unmarshal(irep.GetPayload(), caRep)
	if err != nil {
		grpclog.Fatalln(err)
		return nil, err
	}

	grpclog.Infoln("SignTxReply: ", caRep)
	return caRep, nil

}