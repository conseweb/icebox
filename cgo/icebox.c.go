package main

import "C"

import (

	"crypto/sha256"
	"github.com/golang/protobuf/proto"
	pb "github.com/conseweb/icebox/protos"
)

const (
	Version = 1
)

var (
	ErrInfo string
)

//export CGetErrInfo
func CGetErrInfo() string {
	return ErrInfo
}

//func makeTimestamp() int64 {
//	return time.Now().UnixNano() / int64(time.Millisecond)
//}

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


//export CEncodeIceboxMessage
func CEncodeIceboxMessage(cmd int32, p []byte) ([]byte)  {
	req := pb.NewIceboxMessage(pb.IceboxMessage_Command(cmd), p)
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

//export CEncodeIceboxMessageWithSID
func CEncodeIceboxMessageWithSID(cmd int32, sid uint32, p []byte) []byte {
	req := pb.NewIceboxMessageWithSID(pb.IceboxMessage_Command(cmd), sid, p)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeHiRequest
func CEncodeHiRequest(magic int64) ([]byte) {
	req := pb.NewHiRequest(magic)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeNegotiateRequest
func CEncodeNegotiateRequest(key, hash string) ([]byte) {
	req := pb.NewNegotiateRequest(key, hash)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeStartRequest
func CEncodeStartRequest() ([]byte) {
	req := pb.NewStartRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeCheckRequest
func CEncodeCheckRequest() ([]byte) {
	req := pb.NewCheckRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeInitRequest
func CEncodeInitRequest(password string) ([]byte) {
	req := pb.NewInitRequest(password)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodePingRequest
func CEncodePingRequest() ([]byte) {
	req := pb.NewPingRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeAddCoinRequest
func CEncodeAddCoinRequest(tp, idx uint32, symbol, name string) ([]byte) {
	req := pb.NewAddCoinRequest(tp, idx, symbol, name)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeCreateAddressRequest
func CEncodeCreateAddressRequest(tp uint32, pass string) ([]byte) {
	req := pb.NewCreateAddressRequest(tp, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeCreateSecretRequest
func CEncodeCreateSecretRequest(tp, site, account uint32, pass string) ([]byte) {
	req := pb.NewCreateSecretRequest(tp, site, account, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeGetAddressRequest
func CEncodeGetAddressRequest(tp, idx uint32,  pass string) ([]byte) {
	req := pb.NewGetAddressRequest(tp, idx, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeListAddressRequest
func CEncodeListAddressRequest(tp, offset, limit uint32,  pass string) ([]byte) {
	req := pb.NewListAddressRequest(tp, offset, limit, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeListSecretRequest
func CEncodeListSecretRequest(tp, site, offset, limit uint32,  pass string) ([]byte) {
	req := pb.NewListSecretRequest(tp, site, offset, limit, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeDeleteAddressRequest
func CEncodeDeleteAddressRequest(tp, idx uint32, pass string) ([]byte) {
	req := pb.NewDeleteAddressRequest(tp, idx, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeSignTxRequest
func CEncodeSignTxRequest(tp, idx uint32, amount uint64, dest string, txhash []byte, txidx uint32, pass string) ([]byte) {
	req := pb.NewSignTxRequest(tp, idx, amount, dest, txhash, txidx, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeSignMsgRequest
func CEncodeSignMsgRequest(tp, idx uint32, msg []byte, pass string) ([]byte) {
	req := pb.NewSignMsgRequest(tp, idx, msg, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeResetRequest
func CEncodeResetRequest() ([]byte) {
	req := pb.NewResetRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeHiReply
func CEncodeHiReply(magic int64) ([]byte) {
	req := pb.NewHiReply(magic)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeNegotiateReply
func CEncodeNegotiateReply(key, hash string) ([]byte) {
	reply := pb.NewNegotiateReply(key, hash)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeCheckReply
func CEncodeCheckReply(state int32, devid *string) ([]byte) {
	reply := pb.NewCheckReply(state, devid)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}



//export CEncodeInitReply
func CEncodeInitReply(devid []byte) ([]byte) {
	reply := pb.NewInitReply(devid)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodePingReply
func CEncodePingReply() ([]byte) {
	reply := pb.NewPingReply()
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeStartReply
func CEncodeStartReply() ([]byte) {
	reply := pb.NewStartReply()
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeAddCoinReply
func CEncodeAddCoinReply() ([]byte) {
	reply := pb.NewAddCoinReply()
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeCreateAddressReply
func CEncodeCreateAddressReply(tp, idx uint32, addr string) ([]byte) {
	reply := pb.NewCreateAddressReply(tp, idx, addr)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}



//export CEncodeCreateSecretReply
func CEncodeCreateSecretReply(tp, site, account, idx uint32, secret []byte) ([]byte) {
	reply := pb.NewCreateSecretReply(tp, site, account, idx, secret)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeGetAddressReply
//func CEncodeGetAddressReply(addr Address) ([]byte) {
//	reply := NewGetAddressReply(addr)
//
//	payload, err := proto.Marshal(reply)
//	if err != nil {
//		ErrInfo = err.Error()
//		return nil
//	}
//	return payload
//}


//export CEncodeListAddressReply
//func CEncodeListAddressReply(num, page, offset, limit uint32, addrs []*pb.Address) ([]byte) {
//	reply := pb.NewListAddressReply(num, page, offset, limit, addrs)
//
//	payload, err := proto.Marshal(reply)
//	if err != nil {
//		ErrInfo = err.Error()
//		return nil
//	}
//	return payload
//}



//export CEncodeListSecretReply
//func CEncodeListSecretReply(num, page, offset, limit uint32, secrets []*pb.Secret) ([]byte) {
//	reply := pb.NewListSecretReply(num, page, offset, limit, secrets)
//
//	payload, err := proto.Marshal(reply)
//	if err != nil {
//		ErrInfo = err.Error()
//		return nil
//	}
//	return payload
//}


//export CEncodeDeleteAddressReply
func CEncodeDeleteAddressReply(addr string) []byte {
	reply := pb.NewDeleteAddressReply(addr)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeSignTxReply
func CEncodeSignTxReply(tx []byte) []byte {
	reply := pb.NewSignTxReply(tx)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}



//export CEncodeSignMsgReply
func CEncodeSignMsgReply(msg []byte) []byte {
	reply := pb.NewSignMsgReply(msg)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


//export CEncodeResetReply
func CEncodeResetReply() []byte {
	reply := pb.NewResetReply()
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}


func main() {}