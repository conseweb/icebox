package core

import (
	//"github.com/looplab/fsm"
	//"go.uber.org/zap"
	//"github.com/rs/zerolog"
	//"github.com/rs/zerolog/log"
	"github.com/rs/zerolog"
	//"os"
	"flag"
	//"go.uber.org/zap"
	"conseweb.com/wallet/icebox/common/fsm"
)


// example FSM for demonstration purposes.
type AppFSM struct {
	To  string
	FSM *fsm.FSM
}

var (
	//logger zerolog.Logger
)

func init() {
	//x, _ := zap.NewProduction()
	//defer x.Sync() // flushes buffer, if any
	//logger = x.Sugar()
	zerolog.TimeFieldFormat = ""
	debug := flag.Bool("debug", false, "sets log level to debug")

	flag.Parse()

	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	//logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

	//if isConsole {
	//	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	//}
}

func NewAppFSM(to string) *AppFSM {
	d := &AppFSM{
		To: to,
	}

	// est_unchecked : established and unchecked
	// est_uninited : established and uninited
	// est_inited : established and inited
	d.FSM = fsm.NewFSM(
		"started",
		fsm.Events{
			{Name: "DT_EXISTS", Src: []string{"started"}, Dst: "plugged"},
			{Name: "DT_NOTEXISTS", Src: []string{"started"}, Dst: "unplugged"},
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

func (d *AppFSM) enterState(e *fsm.Event) {

	logger.Debug().Msgf("The bi-directional stream to %s is %s, from event %s\n", d.To, e.Dst, e.Event)
	//logger.Debugf("The bi-directional stream to %s is %s, from event %s\n", d.To, e.Dst, e.Event)
}

func (d *AppFSM) beforeHello(e *fsm.Event) {
	logger.Debug().Msgf("Before reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
	//logger.Debugf("Before reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
}

func (d *AppFSM) afterHello(e *fsm.Event) {
	logger.Debug().Msgf("After reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
	//logger.Debugf("After reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
}

func (d *AppFSM) afterPing(e *fsm.Event) {
	logger.Debug().Msgf("After reception of %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
}

func (d *AppFSM) beforePing(e *fsm.Event) {
	logger.Debug().Msgf("Before %s, dest is %s, current is %s", e.Event, e.Dst, d.FSM.Current())
}