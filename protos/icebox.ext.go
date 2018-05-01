package protos

import (

	"time"
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

func NewInt32(v int32) *int32 {
	var i = v
	return &i
}


func NewHeader() *Header {
	v := NewUInt32(Version)
	ts := uint32(makeTimestamp())

	h := new(Header)
	h.Ver = v
	h.Sn = &ts
	return h
}

func CloneHeader(h *Header) *ReplyHeader {
	zero := NewUInt32(0)

	header := new(ReplyHeader)
	header.Sn = h.Sn
	header.Ver = h.Ver
	header.Code = zero
	return header
}

func NewHiRequest(magic int64) *HiRequest {
	req := new(HiRequest)
	req.Header = NewHeader()
	req.MagicA = &magic
	return req
}

// key: KeyA, public key of requester side
func NewNegotiateRequest(key string) *NegotiateRequest {
	req := new(NegotiateRequest)
	req.Header = NewHeader()
	req.KeyA = &key
	return req
}

func NewCheckRequest() *CheckRequest {
	req := new(CheckRequest)
	req.Header = NewHeader()
	return req
}

func NewInitRequest(password string) *InitRequest {
	req := new(InitRequest)
	req.Header = NewHeader()
	req.Password = &password
	return req
}

func NewHelloRequest() *HelloRequest {
	req := new(HelloRequest)
	req.Header = NewHeader()
	return req
}

func NewAddCoinRequest(tp, idx uint32, symbol, name string) *AddCoinRequest {
	req := new(AddCoinRequest)
	req.Header = NewHeader()
	req.Type = &tp
	req.Idx = &idx
	req.Symbol = &symbol
	req.Name = &name
	return req
}

func NewResetRequest() *ResetRequest {
	req := new(ResetRequest)
	req.Header = NewHeader()
	return req
}

func MakeHiReply(req *HiRequest, magic int64) *HiReply {

	reply := new(HiReply)
	reply.Header = CloneHeader(req.Header)
	reply.MagicB = &magic

	return reply
}

func MakeNegotiateReply(req *NegotiateRequest, key string) *NegotiateReply {

	reply := new(NegotiateReply)
	reply.Header = CloneHeader(req.Header)
	reply.KeyB = &key

	return reply
}

func MakeCheckReply(req *CheckRequest, state int32, devid *string) *CheckReply {

	reply := new(CheckReply)
	reply.Header = CloneHeader(req.Header)
	reply.State = &state
	if devid != nil {
		reply.DevId = devid
	}
	return reply
}

func MakeInitReply(req *InitRequest, devid string) *InitReply {

	reply := new(InitReply)
	reply.Header = CloneHeader(req.Header)
	reply.DevId = &devid
	return reply
}

func MakeHelloReply(req *HelloRequest) *HelloReply {
	reply := new(HelloReply)
	reply.Header = CloneHeader(req.Header)
	ts := makeTimestamp()
	reply.Timestamp = &ts
	return reply
}

func MakeAddCoinReply(req *AddCoinRequest) *AddCoinReply {
	reply := new(AddCoinReply)
	reply.Header = CloneHeader(req.Header)
	//reply.Path =
	return reply
}

func MakeCreateAddressReply(req *CreateAddressRequest, addr string) *CreateAddressReply {

	reply := new(CreateAddressReply)
	reply.Header = CloneHeader(req.Header)
	reply.Address = &addr
	return reply
}

func MakeResetReply(req *ResetRequest) *ResetReply {
	reply := new(ResetReply)
	reply.Header = CloneHeader(req.Header)
	return reply
}

