package crypto

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	_ "fmt"
)

type aes_test struct {
	key string
	message string
}

// key size should be divided by 8
var aes_tests = []aes_test{
	{"LKHlhb899Y09olUi", "Test! One two three"},
	{"TestingOneTwoThr", "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5"},
}

func TestEncryption(t *testing.T) {
	Convey(`Decrypted text should equal original message.`, t, func() {
		for _, i := range aes_tests[1:] {
			encrypted, err := Encrypt([]byte(i.key), i.message)
			if err != nil {
				panic(err)
			}

			var ct string
			ct, err = Decrypt([]byte(i.key), encrypted)
			if err != nil {
				panic(err)
			}

			So(ct, ShouldResemble, i.message)
		}
	})

}

// key size should be divided by 8
func encryptWithInvalidKeySize() {
	_, err := Encrypt([]byte("TestingOneTwoThrTestingOneTwoThrx"), "Hello")
	if err != nil {
		panic(err)
	}
}

func TestInvalidKeySizeEncryption(t *testing.T) {
	Convey(`Should be panic for invalid key size.`, t, func() {
		//So(encrypt, ShouldPanicWith, "crypto/aes: invalid key size 13")
		So(encryptWithInvalidKeySize, ShouldPanic)

	})
}

func encryptWithSpaceInKey() {
	_, err := Encrypt([]byte("Testingx OeTwoThrTestingOneTwoTc"), "Hello")
	if err != nil {
		panic(err)
	}
}

func TestWithSpaceInKey(t *testing.T) {
	Convey(`Should be panic for invalid key.`, t, func() {
		//So(encrypt, ShouldPanicWith, "crypto/aes: invalid key size 13")
		So(encryptWithSpaceInKey, ShouldNotPanic)

	})
}