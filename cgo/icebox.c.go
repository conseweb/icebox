package main

/*
#include "callback.h"

// This typedef is used by Go
typedef void (*callback_fn2) (void*, int);

extern void my_callback(void*);
extern int execute_cb(void*, int);
//extern GoSlice Hello(void*);

static void my_job(void *p) {
  my_callback(p);
  execute_cb(p, 20);
}

*/
import "C"
import "unsafe"

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/conseweb/icebox/client"
	"github.com/conseweb/icebox/core/common"
	pb "github.com/conseweb/icebox/protos"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
)

const (
	Version = 1
)

var (
	ErrInfo string
	handler *client.Handler
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
func CEncodeIceboxMessage(cmd int32, p []byte) []byte {
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
func CEncodeHiRequest(magic int64) []byte {
	req := pb.NewHiRequest(magic)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeNegotiateRequest
func CEncodeNegotiateRequest(key, hash string) []byte {
	req := pb.NewNegotiateRequest(key, hash)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeStartRequest
func CEncodeStartRequest() []byte {
	req := pb.NewStartRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeCheckRequest
func CEncodeCheckRequest() []byte {
	req := pb.NewCheckRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeInitRequest
func CEncodeInitRequest(password string) []byte {
	req := pb.NewInitRequest(password)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodePingRequest
func CEncodePingRequest() []byte {
	req := pb.NewPingRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeAddCoinRequest
func CEncodeAddCoinRequest(tp, idx uint32, symbol, name string) []byte {
	req := pb.NewAddCoinRequest(tp, idx, symbol, name)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeCreateAddressRequest
func CEncodeCreateAddressRequest(tp uint32, pass string) []byte {
	req := pb.NewCreateAddressRequest(tp, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeCreateSecretRequest
func CEncodeCreateSecretRequest(tp, site, account uint32, pass string) []byte {
	req := pb.NewCreateSecretRequest(tp, site, account, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeGetAddressRequest
func CEncodeGetAddressRequest(tp, idx uint32, pass string) []byte {
	req := pb.NewGetAddressRequest(tp, idx, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeListAddressRequest
func CEncodeListAddressRequest(tp, offset, limit uint32, pass string) []byte {
	req := pb.NewListAddressRequest(tp, offset, limit, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeListSecretRequest
func CEncodeListSecretRequest(tp, site, offset, limit uint32, pass string) []byte {
	req := pb.NewListSecretRequest(tp, site, offset, limit, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeDeleteAddressRequest
func CEncodeDeleteAddressRequest(tp, idx uint32, pass string) []byte {
	req := pb.NewDeleteAddressRequest(tp, idx, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeSignTxRequest
func CEncodeSignTxRequest(tp, idx uint32, amount uint64, dest string, txhash []byte, txidx uint32, pass string) []byte {
	req := pb.NewSignTxRequest(tp, idx, amount, dest, txhash, txidx, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeSignMsgRequest
func CEncodeSignMsgRequest(tp, idx uint32, msg []byte, pass string) []byte {
	req := pb.NewSignMsgRequest(tp, idx, msg, pass)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeResetRequest
func CEncodeResetRequest() []byte {
	req := pb.NewResetRequest()
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeHiReply
func CEncodeHiReply(magic int64) []byte {
	req := pb.NewHiReply(magic)
	payload, err := proto.Marshal(req)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeNegotiateReply
func CEncodeNegotiateReply(key, hash string) []byte {
	reply := pb.NewNegotiateReply(key, hash)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeCheckReply
func CEncodeCheckReply(state int32, devid *string) []byte {
	reply := pb.NewCheckReply(state, devid)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeInitReply
func CEncodeInitReply(devid []byte) []byte {
	reply := pb.NewInitReply(devid)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodePingReply
func CEncodePingReply() []byte {
	reply := pb.NewPingReply()
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeStartReply
func CEncodeStartReply() []byte {
	reply := pb.NewStartReply()
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeAddCoinReply
func CEncodeAddCoinReply() []byte {
	reply := pb.NewAddCoinReply()
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeCreateAddressReply
func CEncodeCreateAddressReply(tp, idx uint32, addr string) []byte {
	reply := pb.NewCreateAddressReply(tp, idx, addr)
	payload, err := proto.Marshal(reply)
	if err != nil {
		ErrInfo = err.Error()
		return nil
	}
	return payload
}

//export CEncodeCreateSecretReply
func CEncodeCreateSecretReply(tp, site, account, idx uint32, secret []byte) []byte {
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

//export InitHandler
func InitHandler() {
	if handler != nil {
		return
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	handler = client.NewHandler("127.0.0.1:50052", opts)
	handler.FSM.Event("CREATE")

	err := handler.Connect()
	if err != nil {
		//logger.Fatal().Err(err).Msgf("fail to dial")
		fmt.Printf("Go says: failed to dial..\n")
	}
	handler.FSM.Event("IN")
	return
}

//export Hello
func Hello() []byte {
	// convert unsafe pointer to golang object
	//handler := (*client.Handler)(hand)

	fmt.Printf("Go says: Enter Hello..\n")

	payload, _ := pb.EncodeHiRequest(common.App_magic)
	ct := pb.NewIceboxMessage(pb.IceboxMessage_HELLO, payload)

	if handler == nil {
		fmt.Printf("Go says: invalide handler..\n")
	} else {
		var err error
		res, err := handler.Client.Execute(context.Background(), ct)
		if err != nil {
			//grpclog.Fatalln(err)
			grpclog.Fatalf("%v.Chat(_) = _, %v: ", handler.Client, err)
			return nil
		}
		grpclog.Infoln("HiReply: ", res)

		hdr := res.GetHeader()
		if hdr.GetCmd() == pb.IceboxMessage_ERROR {
			//logger.Debug().Msgf("Device error: %s", res.GetPayload())
			fmt.Errorf("Device error: %s", res.GetPayload())
			return nil
		}

		fmt.Printf("Go says: Before exit ...\n")
		return res.GetPayload()
	}

	return nil
}

type message struct {
	text string
}

func main() {
	C.my_job(unsafe.Pointer(&message{
		text: "I love golang",
	}))

	//C.Hello()

	fmt.Printf("Go says: calling C callback add..\n")

	// With cgo you can't call C function pointers directly,
	// but you can pass then to C functions that can call them
	C.add(40, 2, C.callback_fn(C.c_to_go_callback))
	fmt.Printf("Go says: 1st result is %d\n\n", total)

	fmt.Printf("Go says: calling add with Go callback..\n")
	C.add_with_go_callback(100, 1)
	fmt.Printf("Go says: 2nd result is %d\n", total)
}

var total int

//export GoTotalCallback
func GoTotalCallback(callbackTotal C.int) {
	fmt.Printf("Go callback got total %d\n", callbackTotal)
	total = int(callbackTotal)
}

//export my_callback
func my_callback(p unsafe.Pointer) {
	println(((*message)(p)).text)
}

//export execute_cb
func execute_cb(p unsafe.Pointer, size C.int) C.int {
	println(((*message)(p)).text)
	println("len: ", size)
	return 0
}
