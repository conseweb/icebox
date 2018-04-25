
package models

import (
	_ "github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"fmt"
)

type Secret struct {
	ID     uint32 `gorm:"AUTO_INCREMENT, PRIMARY_KEY"` // set id to auto incrementable
	T1	   uint32 `gorm:"DEFAULT:44"`				   // for bip44: purpose = 44
	T2     uint32 `gorm:"unique;not null"`             // for bip44: coin_type
	T3     uint32 `gorm:"default:0"`				   // for bip44: account=0
	Symbol string              // 对应币种的代号, 如比特币是: btc
	Name   string              // 对应币种的全称, 如比特币是: bitcoin
	//Path   string `gorm:"not null"`                    // 对应币种的account derivation path
}

func (p Secret) GetEquality() (res string) {
	res = fmt.Sprintf("m/%i'/%i'/%i'/", p.T1, p.T2, p.T3)
	return res
}


