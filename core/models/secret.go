
package models

import (
	"fmt"
)

// {T1: type, T2: site id, T3: account id, T4: index}
type Secret struct {
	ID      uint32 `gorm:"AUTO_INCREMENT, PRIMARY_KEY"` // set id to auto incrementable
	T1 		uint32 `gorm:"not null"`					// type: 0: use user's password, 1: generated password
	T2      uint32 `gorm:"not null"`                    // site id
	T3 		uint32 `gorm:"not null"`					// account id
	T4      uint32 `gorm:"not null"`					// index
	Secret  string 										// user's password
	Key 	string	// TOTP secret key
}

func (p Secret) GetEquality() (res string) {
	res = fmt.Sprintf("%d/%d/%d/%d", p.T1, p.T2, p.T3, p.T4)
	return res
}


