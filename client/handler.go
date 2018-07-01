package client

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/conseweb/btcd/btcec"
	"github.com/conseweb/coinutil/base58"
	"github.com/conseweb/coinutil/bip32"
	"github.com/conseweb/coinutil/bip39"
	"github.com/conseweb/icebox/client/util"
	"github.com/conseweb/icebox/common/address"
	"github.com/conseweb/icebox/common/crypto"
	"github.com/conseweb/icebox/common/flogging"
	"github.com/conseweb/icebox/common/fsm"
	"github.com/conseweb/icebox/core/common"
	pb "github.com/conseweb/icebox/protos"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/jsonpb"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
	"time"
)

const (
	sessionKeyFn = "session_key.dat"
	timeout      = 500 * time.Millisecond
)

var (
	logger = flogging.MustGetLogger("client", zerolog.DebugLevel)
	errmsg string
)

type Session struct {
	id        uint32            // session id
	key       *btcec.PrivateKey // private key
	peerKey   *btcec.PublicKey  // peer's public key
	sharedKey *btcec.PublicKey  // shared public key
	shortKey  string
}

// example FSM for demonstration purposes.
type Handler struct {
	opts    []grpc.DialOption
	session *Session
	To      string
	FSM     *fsm.FSM
	Conn    *grpc.ClientConn
	Client  pb.IceboxClient
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
		To:      to,
		opts:    opts,
		session: new(Session),
	}

	// est_unchecked : established and unchecked
	// est_uninited : established and uninited
	// est_inited : established and inited
	d.FSM = fsm.NewFSM(
		"created",
		fsm.Events{
			{Name: "CREATE", Src: []string{"created"}, Dst: "disconnected"},
			{Name: "CONNECT", Src: []string{"disconnected"}, Dst: "pending"},
			{Name: "CONNECTED", Src: []string{"pending"}, Dst: "connected"},
			{Name: "DISCONNECT", Src: []string{"connected", "confirmed", "negotiated", "est_unchecked", "est_inited", "est_uninited"}, Dst: "pending"},
			{Name: "DISCONNECTED", Src: []string{"pending"}, Dst: "disconnected"},
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
			"enter_state":     func(e *fsm.Event) { d.enterState(e, d.FSM.Current()) },
			"enter_created":   func(e *fsm.Event) { d.enterCreated(e, d.FSM.Current()) },
			"enter_unplugged": func(e *fsm.Event) { d.enterUnplugged(e, d.FSM.Current()) },
			"before_HELLO":    func(e *fsm.Event) { d.beforeHello(e, d.FSM.Current()) },
			"after_HELLO":     func(e *fsm.Event) { d.afterHello(e, d.FSM.Current()) },
			"before_PING":     func(e *fsm.Event) { d.beforePing(e, d.FSM.Current()) },
			"after_PING":      func(e *fsm.Event) { d.afterPing(e, d.FSM.Current()) },
		},
	)

	return d
}

func (d *Handler) Connect() error {
	var err error
	d.Conn, err = grpc.Dial(d.To, d.opts...)
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

	net := RTEnv.GetNet()
	masterKey, _ := bip32.NewMaster(seed, net)
	publicKey, _ := masterKey.ECPubKey()

	// Display mnemonic and keys
	logger.Info().Msgf("Mnemonic: %s", mnemonic)
	logger.Info().Msgf("Master private key: %s", masterKey.String())
	pkb := publicKey.SerializeCompressed()

	logger.Info().Msgf("Length: %d, Master public key: %s", len(pkb), base58.Encode(pkb))
	logger.Info().Msgf("Master public key: %s", address.ToBase58(pkb, len(pkb)))

	//secret := masterKey.String()
	//_ = ioutil.WriteFile(sessionKeyFn, []byte(secret), 0644)
	//d.session.key, _ = masterKey.ECPrivKey()
	return masterKey
}

func (d *Handler) Hello() (*pb.HelloReply, error) {
	var err error

	payload, _ := pb.EncodeHelloRequest(common.App_magic)

	ct := pb.NewIceboxMessage(pb.IceboxMessage_HELLO, payload)

	d.beforeExecute(pb.IceboxMessage_HELLO, ct)

	res, err := d.Client.Execute(context.Background(), ct)
	if err != nil {
		//grpclog.Fatalln(err)
		grpclog.Fatalf("%v.Chat(_) = _, %v: ", d.Client, err)
	}
	grpclog.Infoln("HelloReply: ", res)

	hdr := res.GetHeader()
	if hdr.GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", res.GetPayload())
		return nil, fmt.Errorf("Device error: %s", res.GetPayload())
	}

	d.afterExecute(pb.IceboxMessage_HELLO, res)

	var result = &pb.HelloReply{}
	err = proto.Unmarshal(res.GetPayload(), result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (d *Handler) Negotiate() (*pb.NegotiateReply, error) {
	var err error
	// generate public key
	r := fmt.Sprintf("%d", makeTimestamp())
	mk := d.generateSessionKey(r)
	d.session.key, _ = mk.ECPrivKey()
	pk, err := mk.ECPubKey()
	if err != nil {
		logger.Fatal().Err(err).Msg("")
		return nil, err
	}
	b := pk.SerializeCompressed()
	//bs := address.ToBase58(b, len(b))
	bs := base58.Encode(b)
	logger.Debug().Msgf("Base58 raw public string: '%s'", bs)
	hb := util.Hash256(b)
	//req := pb.NewNegotiateRequest(bs, base58.Encode(hb))
	payload, _ := pb.EncodeNegotiateRequest(b, hb)
	ct := pb.NewIceboxMessage(pb.IceboxMessage_NEGOTIATE, payload)

	d.beforeExecute(pb.IceboxMessage_NEGOTIATE, ct)

	res, err := d.Client.Execute(context.Background(), ct)
	if err != nil {
		grpclog.Fatalf("Negotiate(_) = _, %v: ", err)
		return nil, err
	}

	if res.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", res.GetPayload())
		return nil, errors.New(fmt.Sprintf("Device error : %s", res.GetPayload()))
	}

	var result = &pb.NegotiateReply{}
	err = proto.Unmarshal(res.GetPayload(), result)
	if err != nil {
		logger.Fatal().Err(err).Msg("")
		return nil, err
	}

	d.afterExecute(pb.IceboxMessage_NEGOTIATE, res)

	logger.Debug().Msgf("NegotiateReply: %s", result)
	kb := result.GetKeyB()
	//pkb := base58.Decode(kb)
	pkB, err := btcec.ParsePubKey(kb, btcec.S256())
	if err != nil {
		logger.Fatal().Err(err).Msg("")
		return nil, err
	}
	// remember peer's public key
	d.session.peerKey = pkB

	//shared := address.NewPublickKey("256")
	privk, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}
	//d.session.key = privk
	shared := privk.PubKey()
	shared.X, shared.Y = shared.ScalarMult(pkB.X, pkB.Y, d.session.key.Serialize())
	//skb := shared.Bytes()
	d.session.sharedKey = shared
	skb := d.session.sharedKey.SerializeCompressed()
	d.session.id = binary.LittleEndian.Uint32(skb)
	aesKey := base58.Encode(skb)[:common.SharedKey_Len]
	d.session.shortKey = aesKey

	logger.Debug().Msgf("Shared key: %s", aesKey)

	return result, nil
}

func (d *Handler) StartSession() (*pb.StartReply, error) {
	var err error
	req := pb.NewStartRequest()
	payload, _ := proto.Marshal(req)
	sid := d.session.id

	var msg *pb.IceboxMessage = nil
	if RTEnv.IsEncrypt() {
		// encrypt payload
		ed, err := crypto.EncryptAsByte([]byte(d.session.shortKey), payload)
		if err != nil {
			return nil, err
		}

		msg = pb.NewIceboxMessageWithSID(pb.IceboxMessage_START_SESSION, sid, ed)

		// calc signature
		err = pb.AddSignatureToMsg(msg, d.session.key)
		if err != nil {
			grpclog.Fatalf("%v: ", err)
		}
	} else {
		msg = pb.NewIceboxMessageWithSID(pb.IceboxMessage_START_SESSION, sid, payload)
	}

	d.beforeExecute(pb.IceboxMessage_START_SESSION, msg)

	res, err := d.Client.Execute(context.Background(), msg)
	if err != nil {
		grpclog.Fatalf("%v: ", err)
	}
	printHeader(res, "StartReply")
	printBody(res, "StartReply")

	if res.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", res.GetPayload())
		// should exit
		return nil, errors.New(fmt.Sprintf("Device error : %s", res.GetPayload()))
	}

	var reply = &pb.StartReply{}
	if RTEnv.IsEncrypt() {
		// verify signature
		ok := pb.VerifySig(res, d.session.peerKey)
		if !ok {
			return nil, errors.New("Invalid signature.")
		}
		// decrypt payload first
		decrypted, err := crypto.DecryptAsByte([]byte(d.session.shortKey), res.GetPayload())
		if err != nil {
			return nil, err
		}
		// then unmarshal
		err = proto.Unmarshal(decrypted, reply)
		if err != nil {
			return nil, err
		}
	} else {
		// then unmarshal
		err = proto.Unmarshal(res.GetPayload(), reply)
		if err != nil {
			return nil, err
		}
	}

	d.afterExecute(pb.IceboxMessage_START_SESSION, res)

	return reply, nil
}

//func (d *Handler) CheckDevice() (*pb.CheckReply, error) {
//	var err error
//	req := pb.NewCheckRequest()
//	payload, _ := proto.Marshal(req)
//	sid := d.session.id
//	var msg *pb.IceboxMessage = nil
//	if RTEnv.IsEncrypt() {
//		// encrypt payload
//		ed, err := crypto.EncryptAsByte([]byte(d.session.shortKey), payload)
//		if err != nil {
//			return nil, err
//		}
//		msg = pb.NewIceboxMessageWithSID(pb.IceboxMessage_CHECK, sid, ed)
//
//		// calc signature
//		err = pb.AddSignatureToMsg(msg, d.session.key)
//		if err != nil {
//			grpclog.Fatalf("%v: ", err)
//		}
//	} else {
//		msg = pb.NewIceboxMessageWithSID(pb.IceboxMessage_CHECK, sid, payload)
//	}
//
//	d.beforeExecute(pb.IceboxMessage_CHECK, msg)
//
//	//ctx, cancel := context.WithTimeout(context.Background(), timeout)
//	//defer cancel()
//
//	res, err := d.Client.Execute(context.Background(), msg)
//	if err != nil {
//		grpclog.Fatalf("%v: ", err)
//	}
//
//	if res.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
//		logger.Debug().Msgf("Device error: %s", res.GetPayload())
//		return nil, fmt.Errorf("Device error: %s", res.GetPayload())
//	}
//
//	var reply = &pb.CheckReply{}
//
//	if RTEnv.IsEncrypt() {
//		// verify sig
//		ok := pb.VerifySig(res, d.session.peerKey)
//		if !ok {
//			return nil, errors.New("Invalid signature.")
//		}
//
//		// decrypt payload first
//		decrypted, err := crypto.DecryptAsByte([]byte(d.session.shortKey), res.GetPayload())
//		if err != nil {
//			return nil, err
//		}
//		// then unmarshal
//		err = proto.Unmarshal(decrypted, reply)
//		if err != nil {
//			return nil, err
//		}
//	} else {
//		// then unmarshal
//		err = proto.Unmarshal(res.GetPayload(), reply)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	d.afterExecute(pb.IceboxMessage_CHECK, res)
//
//	grpclog.Infoln("CheckReply: ", reply)
//	return reply, nil
//}

//func (d *Handler) InitDevice(pas string) (*pb.InitReply, error) {
//	// send initrequest
//	ireq := pb.NewInitRequest(pas)
//	payload, _ := proto.Marshal(ireq)
//	sid := d.session.id
//	msg := pb.NewIceboxMessageWithSID(pb.IceboxMessage_INIT, sid, payload)
//
//	d.beforeExecute(pb.IceboxMessage_INIT, msg)
//
//	res, xe := d.Client.Execute(context.Background(), msg)
//	if xe != nil {
//		grpclog.Fatalln(xe)
//		return nil, xe
//	}
//
//	if res.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
//		logger.Debug().Msgf("Device error: %s", res.GetPayload())
//		return nil, fmt.Errorf("Device error: %s", res.GetPayload())
//	}
//
//	var intRep = &pb.InitReply{}
//	err := proto.Unmarshal(res.GetPayload(), intRep)
//	if err != nil {
//		return nil, err
//	}
//
//	d.afterExecute(pb.IceboxMessage_INIT, res)
//
//	grpclog.Infoln("InitReply: ", intRep)
//	return intRep, nil
//}

func (d *Handler) PingDevice() error {
	req := pb.NewPingRequest()
	payload, _ := proto.Marshal(req)
	sid := d.session.id
	msg := pb.NewIceboxMessageWithSID(pb.IceboxMessage_PING, sid, payload)

	d.beforeExecute(pb.IceboxMessage_PING, msg)

	res, err := d.Client.Execute(context.Background(), msg)
	if err != nil {
		grpclog.Fatalln(err)
	}

	if res.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", res.GetPayload())
		return fmt.Errorf("Device error: %s", res.GetPayload())
	}

	var pr = &pb.PingReply{}
	err = proto.Unmarshal(res.GetPayload(), pr)
	if err != nil {
		grpclog.Fatalln(err)
	}

	d.afterExecute(pb.IceboxMessage_PING, res)

	grpclog.Infoln("PingReply: ", pr)
	return nil
}

func (d *Handler) ResetDevice() error {
	var err error
	resetReq := pb.NewResetRequest()
	payload, _ := proto.Marshal(resetReq)
	sid := d.session.id
	msg := pb.NewIceboxMessageWithSID(pb.IceboxMessage_RESET, sid, payload)

	d.beforeExecute(pb.IceboxMessage_RESET, msg)

	res, err := d.Client.Execute(context.Background(), msg)
	if err != nil {
		grpclog.Fatalln(err)
	}

	if res.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", res.GetPayload())
		return fmt.Errorf("Device error: %s", res.GetPayload())
	}

	var reply = &pb.ResetReply{}
	err = proto.Unmarshal(res.GetPayload(), reply)
	if err != nil {
		grpclog.Fatalln(err)
	}

	d.afterExecute(pb.IceboxMessage_RESET, res)

	grpclog.Infoln("ResetReply: ", reply)
	return nil
}

func (d *Handler) CreateAddress(tp uint32, pwd string) (*pb.CreateAddressReply, error) {
	var err error
	req := pb.NewCreateAddressRequest(tp, pwd)
	payload, _ := proto.Marshal(req)
	sid := d.session.id
	msg := pb.NewIceboxMessageWithSID(pb.IceboxMessage_CREATE_ADDRESS, sid, payload)

	d.beforeExecute(pb.IceboxMessage_CREATE_ADDRESS, msg)

	chatRep, xe := d.Client.Execute(context.Background(), msg)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	if chatRep.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", chatRep.GetPayload())
		return nil, fmt.Errorf("Device error: %s", chatRep.GetPayload())
	}

	var reply = &pb.CreateAddressReply{}
	err = proto.Unmarshal(chatRep.GetPayload(), reply)
	if err != nil {
		grpclog.Fatalln(err)
		return nil, err
	}

	d.afterExecute(pb.IceboxMessage_CREATE_ADDRESS, chatRep)

	grpclog.Infoln("CreateAddressReply: ", reply)
	return reply, nil

}

func (d *Handler) GetAddressByIdx(tp, idx uint32, pwd string) (*pb.GetAddressReply, error) {
	var err error
	req := pb.NewGetAddressRequest(tp, idx, pwd)
	payload, _ := proto.Marshal(req)
	sid := d.session.id
	msg := pb.NewIceboxMessageWithSID(pb.IceboxMessage_GET_ADDRESS, sid, payload)

	d.beforeExecute(pb.IceboxMessage_GET_ADDRESS, msg)

	chatRep, xe := d.Client.Execute(context.Background(), msg)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	if chatRep.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", chatRep.GetPayload())
		return nil, fmt.Errorf("Device error: %s", chatRep.GetPayload())
	}

	var reply = &pb.GetAddressReply{}
	err = proto.Unmarshal(chatRep.GetPayload(), reply)
	if err != nil {
		//grpclog.Fatalln(err)
		logger.Fatal().Err(err).Msgf("reply: %s", reply)
		return nil, err
	}

	ary := reply.GetAddr()
	logger.Debug().Msgf("Address: %d, %d, %s", ary.GetType(), ary.GetIdx(), ary.GetSAddr())

	if RTEnv.isPrintMsg {
		resp, _ := proto.Marshal(chatRep)
		logger.Debug().Msgf("Encoded IceboxMessage for reply: %s", base58.Encode(resp));
	}

	d.beforeExecute(pb.IceboxMessage_GET_ADDRESS, chatRep)

	return reply, nil
}

func (d *Handler) ListAddress(tp, offset, limit uint32, pwd string) (*pb.ListAddressReply, error) {
	var err error
	req := pb.NewListAddressRequest(tp, offset, limit, pwd)
	payload, _ := proto.Marshal(req)
	sid := d.session.id
	msg := pb.NewIceboxMessageWithSID(pb.IceboxMessage_LIST_ADDRESS, sid, payload)

	d.beforeExecute(pb.IceboxMessage_LIST_ADDRESS, msg)

	chatRep, xe := d.Client.Execute(context.Background(), msg)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	if chatRep.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", chatRep.GetPayload())
		return nil, fmt.Errorf("Device error: %s", chatRep.GetPayload())
	}

	var reply = &pb.ListAddressReply{}
	err = proto.Unmarshal(chatRep.GetPayload(), reply)
	if err != nil {
		//grpclog.Fatalln(err)
		logger.Fatal().Err(err).Msgf("reply: %s", reply)
		return nil, err
	}

	cnt := reply.GetTotalRecords()
	page := reply.GetTotalPages()
	ary := reply.GetAddr()
	logger.Debug().Msgf("There are %d addresses, %d pages, received %d addresses.", cnt, page, len(ary))
	for i, _ := range ary {
		logger.Debug().Msgf("%d, %d, %s", ary[i].GetType(), ary[i].GetIdx(), ary[i].GetSAddr())
	}

	d.afterExecute(pb.IceboxMessage_LIST_ADDRESS, chatRep)

	return reply, nil
}

func (d *Handler) DeleteAddress(tp, idx uint32, pwd string) (*pb.DeleteAddressReply, error) {
	var err error
	req := pb.NewDeleteAddressRequest(tp, idx, pwd)
	payload, _ := proto.Marshal(req)
	sid := d.session.id
	msg := pb.NewIceboxMessageWithSID(pb.IceboxMessage_DELETE_ADDRESS, sid, payload)

	d.beforeExecute(pb.IceboxMessage_DELETE_ADDRESS, msg)

	irep, xe := d.Client.Execute(context.Background(), msg)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	if irep.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", irep.GetPayload())
		return nil, fmt.Errorf("Device error: %s", irep.GetPayload())
	}

	var reply = &pb.DeleteAddressReply{}
	err = proto.Unmarshal(irep.GetPayload(), reply)
	if err != nil {
		grpclog.Fatalln(err)
		return nil, err
	}

	d.afterExecute(pb.IceboxMessage_DELETE_ADDRESS, irep)

	grpclog.Infoln("DeleteAddressReply: ", reply)
	return reply, nil

}

func (d *Handler) CreateSecret(site, account uint32, pwd string) (*pb.CreateSecretReply, error) {
	var err error
	req := pb.NewCreateSecretRequest(0, site, account, pwd)
	payload, _ := proto.Marshal(req)
	sid := d.session.id
	msg := pb.NewIceboxMessageWithSID(pb.IceboxMessage_CREATE_SECRET, sid, payload)

	d.beforeExecute(pb.IceboxMessage_CREATE_SECRET, msg)

	irep, xe := d.Client.Execute(context.Background(), msg)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	if irep.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", irep.GetPayload())
		return nil, fmt.Errorf("Device error: %s", irep.GetPayload())
	}

	var reply = &pb.CreateSecretReply{}
	err = proto.Unmarshal(irep.GetPayload(), reply)
	if err != nil {
		grpclog.Fatalln(err)
		return nil, err
	}

	d.afterExecute(pb.IceboxMessage_CREATE_SECRET, irep)

	grpclog.Infoln("CreateSecretReply: ", reply)
	return reply, nil

}

func (d *Handler) ListSecret(tp, site, offset, limit uint32, pwd string) (*pb.ListSecretReply, error) {
	var err error
	req := pb.NewListSecretRequest(tp, site, offset, limit, pwd)
	payload, _ := proto.Marshal(req)
	sid := d.session.id
	msg := pb.NewIceboxMessageWithSID(pb.IceboxMessage_LIST_SECRET, sid, payload)

	d.beforeExecute(pb.IceboxMessage_LIST_SECRET, msg)

	chatRep, xe := d.Client.Execute(context.Background(), msg)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	if chatRep.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", chatRep.GetPayload())
		return nil, fmt.Errorf("Device error: %s", chatRep.GetPayload())
	}

	var reply = &pb.ListSecretReply{}
	err = proto.Unmarshal(chatRep.GetPayload(), reply)
	if err != nil {
		//grpclog.Fatalln(err)
		logger.Fatal().Err(err).Msgf("reply: %s", reply)
		return nil, err
	}

	cnt := reply.GetTotalRecords()
	page := reply.GetTotalPages()
	ary := reply.GetSecret()
	logger.Debug().Msgf("There are %d addresses, %d pages, received %d addresses.", cnt, page, len(ary))
	for i, _ := range ary {
		logger.Debug().Msgf("%d, %d, %s", ary[i].GetType(), ary[i].GetIdx(), ary[i].GetSSecret())
	}

	d.afterExecute(pb.IceboxMessage_LIST_SECRET, chatRep)

	return reply, nil
}

// txhash: should be hex string, 64 char, byte len = 32
func (d *Handler) SignTx(tp, idx uint32, amount uint64, dest, txhash string, txidx uint32, pwd string) (*pb.SignTxReply, error) {
	var err error
	byteTxHash, err := hex.DecodeString(txhash)
	if err != nil {
		grpclog.Fatalln(err)
		return nil, err
	}
	req := pb.NewSignTxRequest(tp, idx, amount, dest, byteTxHash, txidx, pwd)
	payload, _ := proto.Marshal(req)
	sid := d.session.id
	msg := pb.NewIceboxMessageWithSID(pb.IceboxMessage_SIGN_TX, sid, payload)

	d.beforeExecute(pb.IceboxMessage_SIGN_TX, msg)

	chatRep, xe := d.Client.Execute(context.Background(), msg)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	if chatRep.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", chatRep.GetPayload())
		return nil, fmt.Errorf("Device error: %s", chatRep.GetPayload())
	}

	var caRep = &pb.SignTxReply{}
	err = proto.Unmarshal(chatRep.GetPayload(), caRep)
	if err != nil {
		grpclog.Fatalln(err)
		return nil, err
	}

	d.afterExecute(pb.IceboxMessage_SIGN_TX, chatRep)

	//grpclog.Infoln("SignTxReply: ", caRep)
	return caRep, nil

}

func (d *Handler) SignMsg(tp, idx uint32, msg []byte, pwd string) (*pb.SignMsgReply, error) {
	var err error
	//req := pb.NewSignMsgRequest(tp, idx, msg, pwd)
	payload, _ := pb.EncodeSignMsgRequest(tp, idx, msg, pwd)
	sid := d.session.id
	chatMsg := pb.NewIceboxMessageWithSID(pb.IceboxMessage_SIGN_MSG, sid, payload)

	d.beforeExecute(pb.IceboxMessage_SIGN_MSG, chatMsg)

	chatRep, xe := d.Client.Execute(context.Background(), chatMsg)
	if xe != nil {
		grpclog.Fatalln(xe)
		return nil, xe
	}

	if chatRep.GetHeader().GetCmd() == pb.IceboxMessage_ERROR {
		logger.Debug().Msgf("Device error: %s", chatRep.GetPayload())
		return nil, fmt.Errorf("Device error: %s", chatRep.GetPayload())
	}

	var caRep = &pb.SignMsgReply{}
	err = proto.Unmarshal(chatRep.GetPayload(), caRep)
	if err != nil {
		grpclog.Fatalln(err)
		return nil, err
	}

	d.afterExecute(pb.IceboxMessage_SIGN_MSG, chatRep)

	return caRep, nil
}

func (d *Handler) DispMsg(title, content string, icon []byte) (*pb.DispMsgReply, error) {

	//d.beforeExecute(pb.IceboxMessage_SIGN_MSG, msg)

	//d.afterExecute(pb.IceboxMessage_SIGN_MSG, chatRep)

	return nil, nil
}



func (d *Handler) beforeExecute(command pb.IceboxMessage_Command, msg *pb.IceboxMessage) {
	if RTEnv.isPrintMsg {
		ctp, _ := proto.Marshal(msg)
		ma := jsonpb.Marshaler{}
		sMsg, _ := ma.MarshalToString(msg)


		payload := msg.GetPayload()
		cmd := msg.Header.GetCmd()
		switch cmd {
		case pb.IceboxMessage_LIST_ADDRESS:
			result := &pb.ListAddressRequest{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- beforeExecute - Msg for req %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(ctp), hex.EncodeToString(ctp), sMsg, ps)
			break
		case pb.IceboxMessage_CREATE_ADDRESS:
			result := &pb.CreateAddressRequest{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- beforeExecute - Msg for req %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(ctp), hex.EncodeToString(ctp), sMsg, ps)
			break
		case pb.IceboxMessage_SIGN_MSG:
			result := &pb.SignMsgReply{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- beforeExecute - Msg for req %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(ctp), hex.EncodeToString(ctp), sMsg, ps)
			break
		case pb.IceboxMessage_NEGOTIATE:
			result := &pb.NegotiateReply{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- beforeExecute - Msg for req %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(ctp), hex.EncodeToString(ctp), sMsg, ps)
			break
		case pb.IceboxMessage_LIST_SECRET:
			result := &pb.ListSecretReply{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- beforeExecute - Msg for req %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(ctp), hex.EncodeToString(ctp), sMsg, ps)
			break
		case pb.IceboxMessage_CREATE_SECRET:
			result := &pb.CreateSecretReply{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- beforeExecute - Msg for req %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(ctp), hex.EncodeToString(ctp), sMsg, ps)
			break
		default:
			logger.Debug().Msgf("-- beforeExecute - Msg for req %s: (len: %d), hex(%s), json(%s)", command, len(ctp), hex.EncodeToString(ctp), sMsg)
			return

		}

	}

	return
}

func (d *Handler) afterExecute(command pb.IceboxMessage_Command, msg *pb.IceboxMessage) {
	if RTEnv.isPrintMsg {
		resp, _ := proto.Marshal(msg)
		ma := jsonpb.Marshaler{}
		sMsg, _ := ma.MarshalToString(msg)

		payload := msg.GetPayload()
		cmd := msg.Header.GetCmd()
		switch cmd {
		case pb.IceboxMessage_LIST_ADDRESS:
			result := &pb.ListAddressReply{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- afterExecute - Msg for reply %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(resp), hex.EncodeToString(resp), sMsg, ps)
			break
		case pb.IceboxMessage_CREATE_ADDRESS:
			result := &pb.CreateAddressReply{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- afterExecute - Msg for reply %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(resp), hex.EncodeToString(resp), sMsg, ps)
			break
		case pb.IceboxMessage_SIGN_MSG:
			result := &pb.SignMsgReply{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- afterExecute - Msg for reply %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(resp), hex.EncodeToString(resp), sMsg, ps)
			break
		case pb.IceboxMessage_NEGOTIATE:
			result := &pb.NegotiateReply{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- afterExecute - Msg for reply %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(resp), hex.EncodeToString(resp), sMsg, ps)
			break
		case pb.IceboxMessage_LIST_SECRET:
			result := &pb.ListSecretReply{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- afterExecute - Msg for reply %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(resp), hex.EncodeToString(resp), sMsg, ps)
			break
		case pb.IceboxMessage_CREATE_SECRET:
			result := &pb.CreateSecretReply{}
			proto.Unmarshal(payload, result)
			ps, _ := ma.MarshalToString(result)
			logger.Debug().Msgf("-- afterExecute - Msg for reply %s: (len: %d), hex(%s), json(%s), payload(%s)", command, len(resp), hex.EncodeToString(resp), sMsg, ps)
			break
		default:
			logger.Debug().Msgf("-- afterExecute - Msg for reply %s: (len: %d), hex(%s), json(%s)", command, len(resp), hex.EncodeToString(resp), sMsg)
			return

		}
	}

	return
}



func checkError(e error) error {
	if e != nil {
		grpclog.Fatalln(e)
		return e
	}
	return nil
}

func printHeader(msg *pb.IceboxMessage, tip string) {
	logger.Debug().Msgf("%s: version:%d type:%s session_id:%d", tip,
		msg.GetHeader().GetVersion(), msg.GetHeader().GetCmd(), msg.GetHeader().GetSessionId())
}

func printBody(msg *pb.IceboxMessage, tip string) {
	logger.Debug().Msgf("%s: payload:%s signature:%s", tip,
		base58.Encode(msg.GetPayload()), base58.Encode(msg.GetSignature()))
}
