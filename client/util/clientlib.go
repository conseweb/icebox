package util

import (

	"crypto/sha256"
)


var (
	//logger = flogging.MustGetLogger("clientlib", zerolog.InfoLevel)
)

func Hash256(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte(b))
	return h.Sum(nil)
}


func DoubleHash256(b []byte) []byte {
	h1 := sha256.New()
	h1.Write([]byte(b))

	h2 := sha256.New()
	h2.Write(h1.Sum(nil))

	return h2.Sum(nil)
}

