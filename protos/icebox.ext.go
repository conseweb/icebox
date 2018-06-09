package protos

import (
	"time"
	mrand "math/rand"
	"bytes"
	"encoding/binary"

	"crypto/sha256"
	"math/big"
	"crypto/ecdsa"
	"github.com/conseweb/btcd/btcec"
	"crypto/rand"
	"github.com/golang/protobuf/proto"

	"C"
)

const (
	Version = 1
)

var (
	ErrInfo string
)

//export GetErrInfo
func GetErrInfo() string {
	return ErrInfo
}

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

func NewIceboxMessage(t IceboxMessage_Command, p []byte) *IceboxMessage  {
	m := new(IceboxMessage)
	m.Header = new(IceboxMessage_Header)
	m.Header.Version = NewUInt32(Version)
	var sid = mrand.Uint32()
	m.Header.SessionId = &sid
	m.Header.Cmd = &t

	now := time.Now()
	s := int64(now.Second()) // from 'int'
	n := int32(now.Nanosecond()) // from 'int'
	m.Header.Timestamp = &Timestamp{Seconds:&s, Nanos:&n}

	if p != nil {
		m.Payload = p
	}
	m.Signature = []byte{'g', 'o', 'l', 'a', 'n', 'g'}

	return m
}

//export EncodeIceboxMessage
func EncodeIceboxMessage(t IceboxMessage_Command, p []byte) ([]byte)  {
	req := NewIceboxMessage(t, p)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func Hash256(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte(b))
	return h.Sum(nil)
}

func NewIceboxMessageWithSID(t IceboxMessage_Command, sid uint32, p []byte) *IceboxMessage  {
	m := new(IceboxMessage)
	m.Header = new(IceboxMessage_Header)
	v := NewUInt32(Version)
	m.Header.Version = v
	m.Header.SessionId = &sid
	m.Header.Cmd = &t
	now := time.Now()
	s := int64(now.Second()) // from 'int'
	n := int32(now.Nanosecond()) // from 'int'
	ts := Timestamp{Seconds:&s, Nanos:&n}
	m.Header.Timestamp = &ts
	if p != nil {
		m.Payload = p
	}

	// just for remember message's hash
	m.Signature = GetMessageHash(m.Header, p)

	return m
}

//export EncodeIceboxMessageWithSID
func EncodeIceboxMessageWithSID(t IceboxMessage_Command, sid uint32, p []byte) []byte {
	req := NewIceboxMessageWithSID(t, sid, p)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func GetMessageHash(h *IceboxMessage_Header, p []byte) []byte {
	buf := new(bytes.Buffer)
	// version: 4 byte, type: 4 byte, timestamp: 8 + 4 bytes, sessionid: 4 byte
	//size := 4 + 4 + 8 + 4 + 4 = 24
	b4 := make([]byte, 4)
	b8 := make([]byte, 8)

	binary.LittleEndian.PutUint32(b4, h.GetVersion())
	buf.Write(b4)
	// type: 4 byte
	binary.LittleEndian.PutUint32(b4, uint32(h.GetCmd()))
	buf.Write(b4)
	// timestamp: 8 + 4 bytes
	binary.LittleEndian.PutUint64(b8, uint64(h.GetTimestamp().GetSeconds()))
	buf.Write(b8)
	binary.LittleEndian.PutUint32(b4, uint32(h.GetTimestamp().GetNanos()))
	buf.Write(b4)
	// sessionid: 4 byte
	binary.LittleEndian.PutUint32(b4, h.GetSessionId())
	buf.Write(b4)
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
	h := GetMessageHash(req.GetHeader(), req.GetPayload())
	ok := ecdsa.Verify(&xpk, h, r, g)
	return ok
}

func AddSignatureToMsg(msg *IceboxMessage, privKey *btcec.PrivateKey) error {
	pk := ecdsa.PrivateKey(*privKey)
	// now msg.Signature stores msg's hash
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

//export EncodeHiRequest
func EncodeHiRequest(magic int64) ([]byte) {
	req := NewHiRequest(magic)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

// key: KeyA, public key of requester side
func NewNegotiateRequest(key, hash string) *NegotiateRequest {
	req := new(NegotiateRequest)
	req.Hash = &hash
	//req.Header = NewHeader()
	req.KeyA = &key
	return req
}

//export EncodeNegotiateRequest
func EncodeNegotiateRequest(key, hash string) ([]byte) {
	req := NewNegotiateRequest(key, hash)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewStartRequest() *StartRequest {
	req := new(StartRequest)
	return req
}

//export EncodeStartRequest
func EncodeStartRequest() ([]byte) {
	req := NewStartRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


func NewCheckRequest() *CheckRequest {
	req := new(CheckRequest)
	//req.Header = NewHeader()
	return req
}

//export EncodeCheckRequest
func EncodeCheckRequest() ([]byte) {
	req := NewCheckRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewInitRequest(password string) *InitRequest {
	req := new(InitRequest)
	//req.Header = NewHeader()
	req.Password = &password
	return req
}

//export EncodeInitRequest
func EncodeInitRequest(password string) ([]byte) {
	req := NewInitRequest(password)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewPingRequest() *PingRequest {
	req := new(PingRequest)
	//req.Header = NewHeader()
	return req
}

//export EncodePingRequest
func EncodePingRequest() ([]byte) {
	req := NewPingRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewAddCoinRequest(tp, idx uint32, symbol, name string) *AddCoinRequest {
	req := new(AddCoinRequest)
	req.Type = &tp
	req.Idx = &idx
	req.Symbol = &symbol
	req.Name = &name
	return req
}

//export EncodeAddCoinRequest
func EncodeAddCoinRequest(tp, idx uint32, symbol, name string) ([]byte) {
	req := NewAddCoinRequest(tp, idx, symbol, name)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewCreateAddressRequest(tp uint32, pass string) *CreateAddressRequest {
	req := new(CreateAddressRequest)
	req.Type = &tp
	//req.Idx = &idx
	req.Password = &pass
	//req.Name = &name
	return req
}

//export EncodeCreateAddressRequest
func EncodeCreateAddressRequest(tp uint32, pass string) ([]byte) {
	req := NewCreateAddressRequest(tp, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewCreateSecretRequest(tp, site, account uint32, pass string) *CreateSecretRequest {
	req := new(CreateSecretRequest)
	req.Type = &tp
	req.Site = &site
	req.Account = &account
	req.Password = &pass
	return req
}

//export EncodeCreateSecretRequest
func EncodeCreateSecretRequest(tp, site, account uint32, pass string) ([]byte) {
	req := NewCreateSecretRequest(tp, site, account, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewGetAddressRequest(tp, idx uint32,  pass string) *GetAddressRequest {
	req := new(GetAddressRequest)
	req.Type = &tp
	req.Idx = &idx
	req.Password = &pass
	return req
}

//export EncodeGetAddressRequest
func EncodeGetAddressRequest(tp, idx uint32,  pass string) ([]byte) {
	req := NewGetAddressRequest(tp, idx, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewListAddressRequest(tp, offset, limit uint32,  pass string) *ListAddressRequest {
	req := new(ListAddressRequest)
	req.Type = &tp
	req.Offset = &offset
	req.Limit = &limit
	//req.Idx = &idx
	req.Password = &pass
	return req
}

//export EncodeListAddressRequest
func EncodeListAddressRequest(tp, offset, limit uint32,  pass string) ([]byte) {
	req := NewListAddressRequest(tp, offset, limit, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewListSecretRequest(tp, site, offset, limit uint32,  pass string) *ListSecretRequest {
	req := new(ListSecretRequest)
	req.Type = &tp
	req.Site = &site
	req.Offset = &offset
	req.Limit = &limit
	//req.Idx = &idx
	req.Password = &pass
	return req
}

//export EncodeListSecretRequest
func EncodeListSecretRequest(tp, site, offset, limit uint32,  pass string) ([]byte) {
	req := NewListSecretRequest(tp, site, offset, limit, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewDeleteAddressRequest(tp, idx uint32, pass string) *DeleteAddressRequest {
	req := new(DeleteAddressRequest)
	req.Type = &tp
	req.Idx = &idx
	req.Password = &pass
	return req
}

//export EncodeDeleteAddressRequest
func EncodeDeleteAddressRequest(tp, idx uint32, pass string) ([]byte) {
	req := NewDeleteAddressRequest(tp, idx, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

// txhash: should be 32 byte; prev tx hash
func NewSignTxRequest(tp, idx uint32, amount uint64, dest string, txhash []byte, txidx uint32, pass string) *SignTxRequest {
	req := new(SignTxRequest)
	req.Type = &tp
	req.Idx = &idx
	req.Amount = &amount
	req.Dest = &dest
	req.TxHash = txhash
	req.TxIdx = &txidx
	req.Password = &pass
	return req
}

//export EncodeSignTxRequest
func EncodeSignTxRequest(tp, idx uint32, amount uint64, dest string, txhash []byte, txidx uint32, pass string) ([]byte) {
	req := NewSignTxRequest(tp, idx, amount, dest, txhash, txidx, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewSignMsgRequest(tp, idx uint32, msg []byte, pass string) *SignMsgRequest {
	req := new(SignMsgRequest)
	req.Type = &tp
	req.Idx = &idx
	req.Message = msg
	req.Password = &pass
	return req
}

//export EncodeSignMsgRequest
func EncodeSignMsgRequest(tp, idx uint32, msg []byte, pass string) ([]byte) {
	req := NewSignMsgRequest(tp, idx, msg, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewResetRequest() *ResetRequest {
	req := new(ResetRequest)
	//req.Header = NewHeader()
	return req
}

//export EncodeResetRequest
func EncodeResetRequest() ([]byte) {
	req := NewResetRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewHiReply(magic int64) *HiReply {
	reply := new(HiReply)
	//reply.Header = CloneHeader(req.Header)
	reply.MagicB = &magic
	return reply
}

//export EncodeHiReply
func EncodeHiReply(magic int64) ([]byte) {
	req := NewHiReply(magic)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewNegotiateReply(key, hash string) *NegotiateReply {
	reply := new(NegotiateReply)
	//reply.Header = CloneHeader(req.Header)
	reply.KeyB = &key
	reply.Hash = &hash
	return reply
}

//export EncodeNegotiateReply
func EncodeNegotiateReply(key, hash string) ([]byte) {
	reply := NewNegotiateReply(key, hash)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
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

//export EncodeCheckReply
func EncodeCheckReply(state int32, devid *string) ([]byte) {
	reply := NewCheckReply(state, devid)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewInitReply(devid []byte) *InitReply {

	reply := new(InitReply)
	//reply.Header = CloneHeader(req.Header)
	reply.DevId = devid
	return reply
}

//export EncodeInitReply
func EncodeInitReply(devid []byte) ([]byte) {
	reply := NewInitReply(devid)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewPingReply() *PingReply {
	reply := new(PingReply)
	//reply.Header = CloneHeader(req.Header)
	ts := makeTimestamp()
	reply.Timestamp = &ts
	return reply
}

//export EncodePingReply
func EncodePingReply() ([]byte) {
	reply := NewPingReply()
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewStartReply() *StartReply {
	reply := new(StartReply)
	return reply
}

//export EncodeStartReply
func EncodeStartReply() ([]byte) {
	reply := NewStartReply()
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewAddCoinReply() *AddCoinReply {
	reply := new(AddCoinReply)
	//reply.Header = CloneHeader(req.Header)
	//reply.Path =
	return reply
}

//export EncodeAddCoinReply
func EncodeAddCoinReply() ([]byte) {
	reply := NewAddCoinReply()
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewCreateAddressReply(tp, idx uint32, addr string) *CreateAddressReply {
	reply := new(CreateAddressReply)
	reply.Type = &tp
	reply.Idx = &idx
	reply.Address = &addr
	return reply
}

//export EncodeCreateAddressReply
func EncodeCreateAddressReply(tp, idx uint32, addr string) ([]byte) {
	reply := NewCreateAddressReply(tp, idx, addr)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewCreateSecretReply(tp, site, account, idx uint32, secret []byte) *CreateSecretReply {
	reply := new(CreateSecretReply)
	reply.Type = &tp
	reply.Site = &site
	reply.Account = &account
	reply.Index = &idx
	reply.Secret = secret
	return reply
}

//export EncodeCreateSecretReply
func EncodeCreateSecretReply(tp, site, account, idx uint32, secret []byte) ([]byte) {
	reply := NewCreateSecretReply(tp, site, account, idx, secret)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewGetAddressReply(addr Address) *GetAddressReply {
	reply := new(GetAddressReply)
	reply.Addr = &addr

	return reply
}

//export EncodeGetAddressReply
func EncodeGetAddressReply(addr Address) ([]byte) {
	reply := NewGetAddressReply(addr)

	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewListAddressReply(num, page, offset, limit uint32, addrs []*Address) *ListAddressReply {
	reply := new(ListAddressReply)
	reply.TotalRecords = &num
	reply.TotalPages = &page
	reply.Limit = &limit
	reply.Offset = &offset

	reply.Addr = make([]*Address, len(addrs))
	for i, _ := range addrs {
		reply.Addr[i] = addrs[i]
	}

	return reply
}

//export EncodeListAddressReply
func EncodeListAddressReply(num, page, offset, limit uint32, addrs []*Address) ([]byte) {
	reply := NewListAddressReply(num, page, offset, limit, addrs)

	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewListSecretReply(num, page, offset, limit uint32, secrets []*Secret) *ListSecretReply {
	reply := new(ListSecretReply)
	reply.TotalRecords = &num
	reply.TotalPages = &page
	reply.Limit = &limit
	reply.Offset = &offset

	reply.Secret = make([]*Secret, len(secrets))
	for i, _ := range secrets {
		reply.Secret[i] = secrets[i]
	}

	return reply
}

//export EncodeListSecretReply
func EncodeListSecretReply(num, page, offset, limit uint32, secrets []*Secret) ([]byte) {
	reply := NewListSecretReply(num, page, offset, limit, secrets)

	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewDeleteAddressReply(addr string) *DeleteAddressReply {
	reply := new(DeleteAddressReply)
	return reply
}

//export EncodeDeleteAddressReply
func EncodeDeleteAddressReply(addr string) []byte {
	reply := NewDeleteAddressReply(addr)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewSignTxReply(tx []byte) *SignTxReply {
	reply := new(SignTxReply)
	reply.SignedTx = tx
	return reply
}

//export EncodeSignTxReply
func EncodeSignTxReply(tx []byte) []byte {
	reply := NewSignTxReply(tx)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewSignMsgReply(msg []byte) *SignMsgReply {
	reply := new(SignMsgReply)
	reply.Signed = msg
	return reply
}

//export EncodeSignMsgReply
func EncodeSignMsgReply(msg []byte) []byte {
	reply := NewSignMsgReply(msg)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

func NewResetReply() *ResetReply {
	reply := new(ResetReply)
	//reply.Header = CloneHeader(req.Header)
	return reply
}

//export EncodeResetReply
func EncodeResetReply() []byte {
	reply := NewResetReply()
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

