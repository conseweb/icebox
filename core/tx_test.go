package core

import (
	"fmt"
	"encoding/json"
)

func test() {
	transaction, err := CreateTransaction("5HusYj2b2x4nroApgfvaSfKYZhRbKFH41bVyPooymbC6KfgSXdD", "1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa", 91234, "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48")
	if err != nil {
		fmt.Println(err)
		return
	}
	data, _ := json.Marshal(transaction)
	fmt.Println(string(data))
}
