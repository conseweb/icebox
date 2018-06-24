package env

import "github.com/conseweb/btcd/chaincfg"

type Env struct {
	isDebug   bool
	isEncrypt bool
	isPrintMsg bool
	isTestNet bool
	net       *chaincfg.Params
}

var (
	RTEnv Env
)

func (e *Env) IsDebug() bool {
	return e.isDebug
}

func (e *Env) IsEncrypt() bool {
	return e.isEncrypt
}

func (e *Env) IsTestNet() bool {
	return e.isTestNet
}

func (e *Env) IsPrintMsg() bool {
	return e.isPrintMsg
}

func (e *Env) GetNet() *chaincfg.Params {
	var net *chaincfg.Params
	if e.IsTestNet() {
		net = &chaincfg.TestNet3Params
	} else {
		net = &chaincfg.MainNetParams
	}
	return net
}

func (e *Env) SetNet(enable bool) {
	e.isTestNet = enable
}

func init() {
	RTEnv.isDebug = true
	RTEnv.isEncrypt = true
	RTEnv.isPrintMsg = true
	RTEnv.isTestNet = true
}
