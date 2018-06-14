package util

import (
	"crypto/sha256"
	"github.com/blockcypher/gobcy"
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

func ReverseByteOrder(inputBytes []byte) (outputBytes []byte) {
	outputBytes = make([]byte, len(inputBytes))
	for i := 0; i < len(inputBytes); i++ {
		outputBytes[i] = inputBytes[len(inputBytes)-i-1]
	}
	return outputBytes
}

//curl https://api.blockcypher.com/v1/btc/test3/addrs/mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse/balance
//{
//	"address": "mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse",
//	"total_received": 407870086,
//	"total_sent": 80010300,
//	"balance": 327859786,
//	"unconfirmed_balance": 0,
//	"final_balance": 327859786,
//	"n_tx": 8,
//	"unconfirmed_n_tx": 0,
//	"final_n_tx": 8
//}%

func FindFirstSuitableUTXO(bcy gobcy.API, target string, amount int) (*string, int, error) {
	var params = map[string]string{"unspentOnly": "true"}
	addr, err := bcy.GetAddr(target, params)
	if err != nil {
		return nil, -1, err
	}
	for i, _ := range addr.TXRefs {
		txref := addr.TXRefs[i]
		if txref.Value >= int(amount) {
			return &txref.TXHash, txref.TXOutputN, nil
		}
	}
	return nil, -1, nil
}
