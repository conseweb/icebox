package main

//const (
//	isDebug = true;
//	isEncrypt = true;
//)

type Env struct {
	isDebug bool
	isEncrypt bool
}

var (
	RTEnv Env
)

func (e *Env) IsDebug() bool  {
	return e.isDebug
}

func (e *Env) IsEncrypt() bool  {
	return e.isEncrypt
}

func init() {
	RTEnv.isDebug = true
	RTEnv.isEncrypt = true
}