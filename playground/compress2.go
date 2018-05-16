package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"time"

	"github.com/gogo/protobuf/proto"
	//"github.com/zvelo/msg"

	pb "conseweb.com/wallet/icebox/protos"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	var (
		buf     bytes.Buffer
		n       int
		s       time.Time
		elapsed time.Duration
		err     error
		obj     []byte

		//test =  msg.Request{
		//	Id: randSeq(1024 * 2),
		//}
	)

	xmsg := randSeq(200 )
	test := pb.Error {
		Code: pb.NewInt32(1),
		Message: &xmsg,
	}

	t, err := proto.Marshal(&test)
	check(err)
	fmt.Printf("size of protobuf: %d\n\n", len(t))

	buf.Reset()
	fw, err := flate.NewWriter(&buf, 9)
	check(err)
	defer fw.Close()

	s = time.Now()
	n, err = fw.Write(t)
	check(err)
	fw.Close() // need to explicitly close and not just flush to prevent EOF error
	elapsed = time.Since(s)

	obj = buf.Bytes()
	fmt.Printf("written to flated: %d\n", n)
	fmt.Printf("size of flated: %d\n", len(obj))
	fmt.Printf("ratio of shink: %f\n", float32(len(obj))/float32(n))
	fmt.Printf("elapsed flated: %v\n\n", elapsed)
	err = decompressFlate(obj, &test)
	check(err)

	buf.Reset()
	zw := zlib.NewWriter(&buf)
	defer zw.Close()

	s = time.Now()
	n, err = zw.Write(t)
	check(err)
	zw.Flush()
	elapsed = time.Since(s)

	obj = buf.Bytes()
	fmt.Printf("written to zipped: %d\n", n)
	fmt.Printf("size of zlib: %d\n", len(obj))
	fmt.Printf("elapsed zlib: %v\n\n", elapsed)

	buf.Reset()
	gw := gzip.NewWriter(&buf)
	defer gw.Close()

	s = time.Now()
	n, err = gw.Write(t)
	check(err)
	gw.Flush()
	elapsed = time.Since(s)

	obj = buf.Bytes()
	fmt.Printf("written to gzipped: %d\n", n)
	fmt.Printf("size of gzip: %d\n", len(obj))
	fmt.Printf("elapsed gzip: %v\n\n", elapsed)

}

func decompressFlate(obj []byte, expected *pb.Error) error {
	fmt.Println("Decompressing")

	data := bytes.NewReader(obj)
	r := flate.NewReader(data)

	enflate, err := ioutil.ReadAll(r)
	if err != nil {
		panic(err)
	}

	result := pb.Error{}
	proto.Unmarshal(enflate, &result)

	if result.GetCode() != expected.GetCode() {
		fmt.Printf("RESULT[%s] != EXPECTED[%s]\n", result.GetCode(), expected.GetCode())
		return errors.New("not equal")
	}

	fmt.Println("DECOMPRESSION EQUAL")
	return nil
}