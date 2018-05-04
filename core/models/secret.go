
package models

import (
	"fmt"
)

type Secret struct {
	ID      uint32 `gorm:"AUTO_INCREMENT, PRIMARY_KEY"` // set id to auto incrementable
	T1      uint32 `gorm:"not null"`                    // domain or site
	T2 		uint32 `gorm:"not:null"`					// username or account
	T3      uint32 `gorm:"not null"`					// index
	Site	string
	Account string
	Name    string
	Key 	string	// TOTP secret key
}

func (p Secret) GetEquality() (res string) {
	res = fmt.Sprintf("%d/%d/%d", p.T1, p.T2, p.T3)
	return res
}


