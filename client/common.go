package client

import "github.com/conseweb/btcd/chaincfg"

//const (
//	isDebug = true;
//	isEncrypt = true;
//)

type Env struct {
	isDebug   bool
	isPrintMsg bool
	isEncrypt bool
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

func (e *Env) GetNet() *chaincfg.Params {
	var net *chaincfg.Params
	if e.IsTestNet() {
		net = &chaincfg.TestNet3Params
	} else {
		net = &chaincfg.MainNetParams
	}
	return net
}

func init() {
	RTEnv.isDebug = true
	RTEnv.isPrintMsg = true
	RTEnv.isEncrypt = true
	RTEnv.isTestNet = true
}
