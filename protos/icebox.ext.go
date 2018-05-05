package protos

import (

	"time"
	mrand "math/rand"
	"bytes"
	"encoding/binary"

	"crypto/sha256"
	"math/big"
	"crypto/ecdsa"
	"github.com/btcsuite/btcd/btcec"
	"crypto/rand"
)

const (
	Version = 1
)

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func NewUInt32(v uint32) *uint32 {
	var i = v
	return &i
}

func NewInt64(v int64) *int64 {
	var i = v
	return &i
}

func NewInt32(v int32) *int32 {
	var i = v
	return &i
}

func NewIceboxMessage(t IceboxMessage_Type, p []byte) *IceboxMessage  {
	m := new(IceboxMessage)
	v := NewUInt32(Version)
	m.Version = v
	var sid = mrand.Uint32()
	m.SessionId = &sid
	m.Type = &t
	if p != nil {
		m.Payload = p
	}
	m.Signature = []byte{'g', 'o', 'l', 'a', 'n', 'g'}

	return m
}

func Hash256(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte(b))
	return h.Sum(nil)
}

func NewIceboxMessageWithSID(t IceboxMessage_Type, sid uint32, p []byte) *IceboxMessage  {
	m := new(IceboxMessage)
	v := NewUInt32(Version)
	m.Version = v
	m.SessionId = &sid
	m.Type = &t
	if p != nil {
		m.Payload = p
	}

	// just for remember message's hash
	m.Signature = GetMessageHash(*v, t, sid, p)

	return m
}

func GetMessageHash(v uint32, t IceboxMessage_Type, sid uint32, p []byte) []byte {
	buf := new(bytes.Buffer)
	b := make([]byte, 4)
	// version: 4 byte
	binary.LittleEndian.PutUint32(b, v)
	buf.Write(b)
	// type: 4 byte
	binary.LittleEndian.PutUint32(b, uint32(t))
	buf.Write(b)
	// sessionid: 4 byte
	binary.LittleEndian.PutUint32(b, sid)
	buf.Write(b)
	// payload
	buf.Write(p)
	// calc hash
	return Hash256(buf.Bytes())
}

func VerifySig(req *IceboxMessage, k *btcec.PublicKey) bool {
	sig := req.GetSignature()
	r, g := new(big.Int), new(big.Int)
	l := len(sig) // should be 64
	r.SetBytes(sig[:l/2])
	g.SetBytes(sig[l/2:])
	xpk := ecdsa.PublicKey(*k)
	h := GetMessageHash(req.GetVersion(), req.GetType(), req.GetSessionId(), req.GetPayload())
	ok := ecdsa.Verify(&xpk, h, r, g)
	return ok
}

func AddSignatureToMsg(msg *IceboxMessage, privKey *btcec.PrivateKey) error {
	pk := ecdsa.PrivateKey(*privKey)
	r, s, err := ecdsa.Sign(rand.Reader, &pk, msg.Signature)
	if err != nil {
		return err
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	msg.Signature = signature

	return nil
}


//func NewHeader() *Header {
//	v := NewUInt32(Version)
//	ts := uint32(makeTimestamp())
//
//	h := new(Header)
//	h.Ver = v
//	h.Sn = &ts
//	return h
//}

//func CloneHeader(h *Header) *ReplyHeader {
//	zero := NewUInt32(0)
//
//	header := new(ReplyHeader)
//	header.Sn = h.Sn
//	header.Ver = h.Ver
//	header.Code = zero
//	return header
//}

func NewError(code int32, msg string) *Error  {
	xe := new(Error)
	xe.Code = &code
	xe.Message = &msg
	return xe
}

func NewHiRequest(magic int64) *HiRequest {
	req := new(HiRequest)
	//req.Header = NewHeader()
	req.MagicA = &magic
	return req
}

// key: KeyA, public key of requester side
func NewNegotiateRequest(key, hash string) *NegotiateRequest {
	req := new(NegotiateRequest)
	req.Hash = &hash
	//req.Header = NewHeader()
	req.KeyA = &key
	return req
}

func NewStartRequest() *StartRequest {
	req := new(StartRequest)
	return req
}

func NewCheckRequest() *CheckRequest {
	req := new(CheckRequest)
	//req.Header = NewHeader()
	return req
}

func NewInitRequest(password string) *InitRequest {
	req := new(InitRequest)
	//req.Header = NewHeader()
	req.Password = &password
	return req
}

func NewPingRequest() *PingRequest {
	req := new(PingRequest)
	//req.Header = NewHeader()
	return req
}

func NewAddCoinRequest(tp, idx uint32, symbol, name string) *AddCoinRequest {
	req := new(AddCoinRequest)
	req.Type = &tp
	req.Idx = &idx
	req.Symbol = &symbol
	req.Name = &name
	return req
}

func NewCreateAddressRequest(tp, idx uint32, name, pass string) *CreateAddressRequest {
	req := new(CreateAddressRequest)
	req.Type = &tp
	req.Idx = &idx
	req.Password = &pass
	req.Name = &name
	return req
}

func NewListAddressRequest(tp, idx uint32, pass string) *ListAddressRequest {
	req := new(ListAddressRequest)
	req.Type = &tp
	req.Idx = &idx
	req.Password = &pass
	return req
}

func NewDeleteAddressRequest(tp, idx uint32, pass string) *DeleteAddressRequest {
	req := new(DeleteAddressRequest)
	req.Type = &tp
	req.Idx = &idx
	req.Password = &pass
	return req
}

func NewSignTxRequest(tp, idx uint32, amount uint64, dest, txid, pass string) *SignTxRequest {
	req := new(SignTxRequest)
	req.Type = &tp
	req.Idx = &idx
	req.Amount = &amount
	req.Dest = &dest
	req.Txid = &txid
	req.Password = &pass
	return req
}

func NewResetRequest() *ResetRequest {
	req := new(ResetRequest)
	//req.Header = NewHeader()
	return req
}

func NewHiReply(magic int64) *HiReply {

	reply := new(HiReply)
	//reply.Header = CloneHeader(req.Header)
	reply.MagicB = &magic

	return reply
}

func NewNegotiateReply(key, hash string) *NegotiateReply {

	reply := new(NegotiateReply)
	//reply.Header = CloneHeader(req.Header)
	reply.KeyB = &key
	reply.Hash = &hash

	return reply
}

func NewCheckReply(state int32, devid *string) *CheckReply {

	reply := new(CheckReply)
	//reply.Header = CloneHeader(req.Header)
	reply.State = &state
	if devid != nil {
		reply.DevId = devid
	}
	return reply
}

func NewInitReply(devid string) *InitReply {

	reply := new(InitReply)
	//reply.Header = CloneHeader(req.Header)
	reply.DevId = &devid
	return reply
}

func NewPingReply() *PingReply {
	reply := new(PingReply)
	//reply.Header = CloneHeader(req.Header)
	ts := makeTimestamp()
	reply.Timestamp = &ts
	return reply
}

func NewStartReply() *StartReply {
	reply := new(StartReply)
	return reply
}

func NewAddCoinReply() *AddCoinReply {
	reply := new(AddCoinReply)
	//reply.Header = CloneHeader(req.Header)
	//reply.Path =
	return reply
}

func NewCreateAddressReply(addr string) *CreateAddressReply {
	reply := new(CreateAddressReply)
	reply.Address = &addr
	return reply
}

func NewListAddressReply(cnt uint32, addrs []*Address) *ListAddressReply {
	reply := new(ListAddressReply)
	reply.Addr = make([]*Address, len(addrs))
	copy(reply.Addr, addrs)
	reply.Max = &cnt
	return reply
}

func NewDeleteAddressReply(addr string) *DeleteAddressReply {
	reply := new(DeleteAddressReply)
	return reply
}

func NewSignTxReply(tx string) *SignTxReply {
	reply := new(SignTxReply)
	reply.SignedTx = &tx
	return reply
}

func NewResetReply() *ResetReply {
	reply := new(ResetReply)
	//reply.Header = CloneHeader(req.Header)
	return reply
}

