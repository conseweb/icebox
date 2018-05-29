package iceboxer

import (
	"log"
	"fmt"
)

//OutputKeys formats and prints relevant outputs to the user.
func OutputKeys(flagKeyCount int, flagConcise bool) {
	if flagKeyCount < 1 || flagKeyCount > 100 {
		log.Fatal("--count <count> must be between 1 and 100")
	}

	if !flagConcise {
		fmt.Println("----------------------------------------------------------------------")
		fmt.Println("Disclaimer: These key pairs are cryptographically secure to the limits of the crypto/rand cryptography package in Golang. They should not be used without further security audit in production systems.")
		fmt.Println("----------------------------------------------------------------------")
		fmt.Println("Each generated key pair includes: ")
		fmt.Println("* Your private key\t\t\t-- Keep this private, needed to spend received Bitcoins.")
		fmt.Println("* Your public key\t\t\t-- in HEX format. This is required to generate multisig destination address.")
		fmt.Println("* Your public destination address\t-- Give this to other people to send you Bitcoins.")
		fmt.Println("----------------------------------------------------------------------")
	}

	privateKeyWIFs, publicKeyHexs, publicAddresses := generateKeys(flagKeyCount)

	for i := 0; i <= flagKeyCount-1; i++ {

		//Output private key in WIF format, public key as hex and P2PKH public address
		fmt.Println("-------------------------------------------------------------")
		fmt.Printf("KEY #%d\n", i+1)
		if !flagConcise {
			fmt.Println("")
		}
		fmt.Println("Private key: ")
		fmt.Println(privateKeyWIFs[i])
		if !flagConcise {
			fmt.Println("")
		}
		fmt.Println("Public key hex: ")
		fmt.Println(publicKeyHexs[i])
		if !flagConcise {
			fmt.Println("")
		}
		fmt.Println("Public Bitcoin address: ")
		fmt.Println(publicAddresses[i])
		fmt.Println("-------------------------------------------------------------")
	}
}
