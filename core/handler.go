package core

import (
	"golang.org/x/net/context"

	pb "conseweb.com/wallet/icebox/protos"

	"errors"
	"os"
	"time"
	"conseweb.com/wallet/icebox/common/flogging"
	"github.com/rs/zerolog"
	"conseweb.com/wallet/icebox/common/fsm"
	_ "github.com/mattn/go-sqlite3"  // must exists, or will cause -- sql: unknown driver "sqlite3"
	"github.com/golang/protobuf/proto"
)

var (
	logger = flogging.MustGetLogger("core", zerolog.DebugLevel)
)

type CoinID struct {
	T1	   uint32 			// for bip44: purpose = 44;
	T2     uint32           // for bip44: coin_type;
}

type AddressID struct {
	Coin 	CoinID
	T5     	uint32			// for bip44: address_index;
}

func exists(fn string) bool {
	var _, err = os.Stat(fn)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

type Session struct {
	id 	uint32 		// session id
	key string			// private key
	peerKey []byte		// peer's public key
	sharedKey []byte	// shared public key
}

type IcebergHandler struct {
	FSM 	*fsm.FSM
	helper *iceHelper
}

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}


func NewIcebergHandler() *IcebergHandler  {
	d := &IcebergHandler{

		helper:newHelper(),
	}

	// est_unchecked : established and unchecked
	// est_uninited : established and uninited
	// est_inited : established and inited
	d.FSM = fsm.NewFSM(
		"unplugged",
		fsm.Events{
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
			"before_HELLO": func(e *fsm.Event) { d.beforeHelloEvent(e, d.FSM.Current()) },
			"after_HELLO":  func(e *fsm.Event) { d.afterHelloEvent(e, d.FSM.Current()) },
			"before_PING":  func(e *fsm.Event) { d.beforePingEvent(e, d.FSM.Current()) },
			"after_PING":   func(e *fsm.Event) { d.afterPingEvent(e, d.FSM.Current()) },
		},
	)

	return d
}


func (d *IcebergHandler) enterState(e *fsm.Event, state string) {
	logger.Debug().Msgf("Enter %s from %s, fired by event %s\n", e.Dst, e.Src, e.Event)
}

func (d *IcebergHandler) beforeHelloEvent(e *fsm.Event, state string) {
	logger.Debug().Msgf("Before %s, dest is %s, current is %s", e.Event, e.Dst, state)
	//logger.Debugf("Before reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
}

func (d *IcebergHandler) afterHelloEvent(e *fsm.Event, state string) {
	logger.Debug().Msgf("After %s, dest is %s, current is %s", e.Event, e.Dst, state)
}

func (d *IcebergHandler) afterPingEvent(e *fsm.Event, state string) {
	logger.Debug().Msgf("After %s, dest is %s, current is %s", e.Event, e.Dst, state)
}

func (d *IcebergHandler) beforePingEvent(e *fsm.Event, state string) {
	logger.Debug().Msgf("Before %s, dest is %s, current is %s", e.Event, e.Dst, state)
}

func (s *IcebergHandler) Chat(ctx context.Context, req *pb.IceboxMessage) (*pb.IceboxMessage, error)  {
	v := req.GetVersion()
	sid := req.GetSessionId()
	t := req.GetType()
	logger.Debug().Msgf("Header version: %d, session id: %d, type: %s", v, sid, t)
	switch t {
	case pb.IceboxMessage_ERROR:
		return nil, errors.New("Some errors happend, should never be here!")
	case pb.IceboxMessage_HELLO:
		// unmarshal message
		x := &pb.HiRequest{}
		unmarshalErr := proto.Unmarshal(req.GetPayload(), x)
		if unmarshalErr != nil {
			logger.Fatal().Err(unmarshalErr).Msgf("Failed to unmarshall . Sending %s", pb.IceboxMessage_ERROR)
			msg := handleError(unmarshalErr)
			return msg, nil
		}
		reply, err := s.helper.Hello(ctx, x)
		if err != nil {
			return nil, err
		}
		payload, _ := proto.Marshal(reply)
		ret := pb.NewIceboxMessage(pb.IceboxMessage_HELLO, payload)
		return ret, nil
	case pb.IceboxMessage_NEGOTIATE:
		x := &pb.NegotiateRequest{}
		unmarshalErr := proto.Unmarshal(req.GetPayload(), x)
		if unmarshalErr != nil {
			logger.Fatal().Err(unmarshalErr).Msgf("Failed to unmarshall . Sending %s", pb.IceboxMessage_ERROR)
			msg := handleError(unmarshalErr)
			return msg, nil
		}
		reply, err := s.helper.NegotiateKey(ctx, x)
		if err != nil {
			msg := handleError(err)
			return msg, nil
		}
		payload, _ := proto.Marshal(reply)
		ret := pb.NewIceboxMessage(pb.IceboxMessage_NEGOTIATE, payload)
		return ret, nil
		//return nil, errors.New("Negotiate not implemented!")
	case pb.IceboxMessage_CHECK:
		x := &pb.CheckRequest{}
		unmarshalErr := proto.Unmarshal(req.GetPayload(), x)
		if unmarshalErr != nil {
			logger.Fatal().Err(unmarshalErr).Msgf("Failed to unmarshall . Sending %s", pb.IceboxMessage_ERROR)
			msg := handleError(unmarshalErr)
			return msg, nil
		}
		reply, err := s.helper.CheckDevice(ctx, x)
		if err != nil {
			msg := handleError(err)
			return msg, nil
		}
		payload, _ := proto.Marshal(reply)
		ret := pb.NewIceboxMessage(pb.IceboxMessage_CHECK, payload)
		return ret, nil
	case pb.IceboxMessage_INIT:
		x := &pb.InitRequest{}
		unmarshalErr := proto.Unmarshal(req.GetPayload(), x)
		if unmarshalErr != nil {
			logger.Fatal().Err(unmarshalErr).Msgf("Failed to unmarshall . Sending %s", pb.IceboxMessage_ERROR)
			msg := handleError(unmarshalErr)
			return msg, nil
		}
		reply, err := s.helper.InitDevice(ctx, x)
		if err != nil {
			msg := handleError(err)
			return msg, nil
		}
		payload, _ := proto.Marshal(reply)
		ret := pb.NewIceboxMessage(pb.IceboxMessage_INIT, payload)
		return ret, nil
	case pb.IceboxMessage_CREATE_ADDRESS:
		x := &pb.CreateAddressRequest{}
		unmarshalErr := proto.Unmarshal(req.GetPayload(), x)
		if unmarshalErr != nil {
			logger.Fatal().Err(unmarshalErr).Msgf("Failed to unmarshall. Sending %s", pb.IceboxMessage_ERROR)
			msg := handleError(unmarshalErr)
			return msg, nil
		}
		reply, err := s.helper.CreateAddress(ctx, x)
		if err != nil {
			msg := handleError(err)
			return msg, nil
		}
		payload, _ := proto.Marshal(reply)
		ret := pb.NewIceboxMessage(pb.IceboxMessage_CREATE_ADDRESS, payload)
		return ret, nil
	case pb.IceboxMessage_LIST_ADDRESS:
		x := &pb.ListAddressRequest{}
		unmarshalErr := proto.Unmarshal(req.GetPayload(), x)
		if unmarshalErr != nil {
			logger.Fatal().Err(unmarshalErr).Msgf("Failed to unmarshall. Sending %s", pb.IceboxMessage_ERROR)
			msg := handleError(unmarshalErr)
			return msg, nil
		}
		reply, err := s.helper.ListAddress(ctx, x)
		if err != nil {
			msg := handleError(err)
			return msg, nil
		}
		payload, _ := proto.Marshal(reply)
		ret := pb.NewIceboxMessage(pb.IceboxMessage_LIST_ADDRESS, payload)
		return ret, nil
	case pb.IceboxMessage_SIGN_TX:
		x := &pb.SignTxRequest{}
		unmarshalErr := proto.Unmarshal(req.GetPayload(), x)
		if unmarshalErr != nil {
			logger.Fatal().Err(unmarshalErr).Msgf("Failed to unmarshall. Sending %s", pb.IceboxMessage_ERROR)
			msg := handleError(unmarshalErr)
			return msg, nil
		}
		reply, err := s.helper.SignTx(ctx, x)
		if err != nil {
			msg := handleError(err)
			return msg, nil
		}
		payload, _ := proto.Marshal(reply)
		ret := pb.NewIceboxMessage(pb.IceboxMessage_SIGN_TX, payload)
		return ret, nil
	}
	//return s.HandleIceboxStream(stream.Context(), stream)
	return nil, errors.New("Not implemented!")
}





