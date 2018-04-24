package protos

import (

	"time"
)

const (
	Version = 1
)

func NewUInt32(v uint32) *uint32 {
	var i = v
	return &i
}

func NewInt32(v int32) *int32 {
	var i = v
	return &i
}


func NewHeader(ver, sn uint32) *Header {
	h := new(Header)
	h.Ver = &ver
	h.Sn = &sn
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

func NewCheckRequest(ver, n uint32) *CheckRequest {
	req := new(CheckRequest)
	req.Header = NewHeader(ver, n)
	return req
}

func NewInitRequest(ver, n uint32, password string) *InitRequest {
	req := new(InitRequest)
	req.Header = NewHeader(ver, n)
	req.Password = &password
	return req
}

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
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