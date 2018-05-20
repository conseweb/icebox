package models

import (
	"fmt"
	"github.com/jinzhu/gorm"
	//"github.com/conseweb/icebox/models"
)

// T1: 44, T2: coin type, T3: account=0, T4: change/chain=0, T5: index
type Address struct {
	ID      uint32 `gorm:"AUTO_INCREMENT, PRIMARY_KEY"` // set id to auto incrementable
	T2      uint32 `gorm:"not null"`                    // for bip44: coin_type
	T4 		uint32 `gorm:"default:0"`					// for bip44: change/chain
	T5      uint32 `gorm:"not null"`					// for bip44: address_index
	Name    string
}

func (p Address) GetEquality() (res string) {
	res = fmt.Sprintf("%d/%d", p.T4, p.T5)
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


