package models

import (
	"fmt"
	"github.com/jinzhu/gorm"
	//"conseweb.com/wallet/icebox/models"
)

type Address struct {
	ID      uint32 `gorm:"AUTO_INCREMENT, PRIMARY_KEY"` // set id to auto incrementable
	T2      uint32 `gorm:"not null"`                    // for bip44: coin_type
	T4 		uint32 `gorm:"default:0"`					// for bip44: change/chain
	T5      uint32 `gorm:"not null"`					// for bip44: address_index
	Name    string
}

func (p Address) GetEquality() (res string) {
	res = fmt.Sprintf("%i/%i", p.T4, p.T5)
	return res
}

func GetPath(db *gorm.DB, tp, idx uint32) string {
	var addr Address
	var coin Coin
	db.Where("t2 = ? AND t5 = ?", tp, idx).First(&addr)
	db.First(&coin, "t2 = ?", tp)

	path := coin.GetEquality() + addr.GetEquality()
	return path
}


