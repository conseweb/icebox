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

func NewDeviceConnectionFSM(to string) *DeviceConnectionFSM {
	d := &DeviceConnectionFSM{
		To: to,
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
			"enter_state":  func(e *fsm.Event) { d.enterState(e) },
			//"before_HELLO": func(e *fsm.Event) { d.beforeHello(e) },
			//"after_HELLO":  func(e *fsm.Event) { d.afterHello(e) },
			//"before_PING":  func(e *fsm.Event) { d.beforePing(e) },
			//"after_PING":   func(e *fsm.Event) { d.afterPing(e) },
		},
	)

	return d
}

func (d *DeviceConnectionFSM) enterState(e *fsm.Event) {
	logger.Debug().Msgf("The bi-directional stream to %s is %s, from event %s\n", d.To, e.Dst, e.Event)
}

func (d *DeviceConnectionFSM) beforeHello(e *fsm.Event) {
	logger.Debug().Msgf("Before reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
	//logger.Debugf("Before reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
}

func (d *DeviceConnectionFSM) afterHello(e *fsm.Event) {
	logger.Debug().Msgf("After reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
	//logger.Debugf("After reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
}

func (d *DeviceConnectionFSM) afterPing(e *fsm.Event) {
	logger.Debug().Msgf("After reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
}

func (d *DeviceConnectionFSM) beforePing(e *fsm.Event) {
	logger.Debug().Msgf("Before %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
}