package core

import (
	"fmt"
	"encoding/json"
)

func test() {
	transaction, err := CreateTransaction("5HusYj2b2x4nroApgfvaSfKYZhRbKFH41bVyPooymbC6KfgSXdD", "msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb", 15000000, "3ef58f2581ed01ab1ba231aeb77846d3340367e651fa6bb1022cdc2790e0698f", 0)
	if err != nil {
		fmt.Println(err)
		return
	}
	data, _ := json.Marshal(transaction)
	fmt.Println(string(data))
}
