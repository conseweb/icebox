package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io/ioutil"
)

const (
	rawData = "01000000018f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e000000006441ee57686955886b9a6d90f9d561164aa8986d8e41c45fd175f0b4313784ade2f03f038e37a14e64de6682f9013875cfc6427ac1477c50208083a9d95002f3d7b101210259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8cffffffff0130abdf03000000001976a91482e81438d7fa15ce205a9683dc786c241bc820f288ac00000000"
)

func main() {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(rawData)); err != nil {
		panic(err)
	}
	if err := gz.Flush(); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	fmt.Printf("raw len: %d\n", len(rawData))
	str := base64.StdEncoding.EncodeToString(b.Bytes())
	fmt.Printf("len: %d, %s\n", len(str), str)
	data, _ := base64.StdEncoding.DecodeString(str)
	fmt.Printf("len: %d, %v\n", len(data), data)
	rdata := bytes.NewReader(data)
	r, _ := gzip.NewReader(rdata)
	s, _ := ioutil.ReadAll(r)
	fmt.Printf("len: %d, %v\n", len(s), string(s))

}
