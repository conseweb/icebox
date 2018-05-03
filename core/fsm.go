package core

import (
	"conseweb.com/wallet/icebox/common/fsm"
	pb "conseweb.com/wallet/icebox/protos"
)

// example FSM for demonstration purposes.
type DeviceConnectionFSM struct {
	To  string
	FSM *fsm.FSM
	Client *pb.IceboxClient
}

