package core

import (
	"github.com/conseweb/icebox/common/fsm"
	pb "github.com/conseweb/icebox/protos"
)

// example FSM for demonstration purposes.
type DeviceConnectionFSM struct {
	To     string
	FSM    *fsm.FSM
	Client *pb.IceboxClient
}
