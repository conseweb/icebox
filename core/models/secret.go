
package models

import (
	"fmt"
)

type Secret struct {
	ID      uint32 `gorm:"AUTO_INCREMENT, PRIMARY_KEY"` // set id to auto incrementable
	T1      uint32 `gorm:"not null"`                    // domain or site
	T2 		uint32 `gorm:"not:null"`					// username or account
	T3      uint32 `gorm:"not null"`					// index
	Account string
	Name    string
}

func (p Secret) GetEquality() (res string) {
	res = fmt.Sprintf("%i/%i/%i", p.T1, p.T2, p.T3)
	return res
}


