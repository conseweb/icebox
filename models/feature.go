package models

import (
	// _ "github.com/mattn/go-sqlite3"
	_ "github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"fmt"
)

type Feature struct {
	ID     uint32 `gorm:"AUTO_INCREMENT, PRIMARY_KEY"` // set id to auto incrementable
	T1	   uint32 `gorm:"DEFAULT:44"`				   // for bip44: purpose = 44
	T2     uint32 `gorm:"unique;not null"`             // for bip44: coin_type
	T3     uint32 `gorm:"default:0"`				   // for bip44: account=0
	Symbol string `gorm:"unique;not null"`             // 对应币种的代号, 如比特币是: btc
	Name   string `gorm:"unique;not null"`             // 对应币种的全称, 如比特币是: bitcoin
	//Path   string `gorm:"not null"`                    // 对应币种的account derivation path
}

func (p Feature) GetEquality() (res string) {
	res = fmt.Sprintf("m/%i'/%i'/%i'/", p.T1, p.T2, p.T3)
	return res
}

// func (p Feature) CreateTable(db *sql.DB) {
// 	// create table if not exists
// 	sql_table := `
// 	CREATE TABLE IF NOT EXISTS "products" (
// 		"Id" integer PRIMARY KEY AUTOINCREMENT NOT NULL,
// 		"Code" char(8) NOT NULL,
// 		"Name" char(16) NOT NULL,
// 		"Path" char(256) NOT NULL
// 	);
// 	`

// 	_, err := db.Exec(sql_table)
// 	if err != nil {
// 		panic(err)
// 	}
// }

// func (p Feature) StoreItem(db *sql.DB, items []Feature) {
// 	sql_additem := `
// 	INSERT OR REPLACE INTO products(
// 		Code,
// 		Name,
// 		Path
// 	) values(?, ?, ?)
// 	`

// 	stmt, err := db.Prepare(sql_additem)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer stmt.Close()

// 	for _, item := range items {
// 		_, err2 := stmt.Exec(item.Code, item.Name, item.Path)
// 		if err2 != nil {
// 			panic(err2)
// 		}
// 	}
// }

// func (p Feature) ReadItem(db *sql.DB) []Feature {
// 	sql_readall := `
// 	SELECT Code, Name, Path FROM products
// 	ORDER BY Code DESC
// 	`

// 	rows, err := db.Query(sql_readall)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer rows.Close()

// 	var result []Feature
// 	for rows.Next() {
// 		item := Feature{}
// 		err2 := rows.Scan(&item.Code, &item.Name, &item.Path)
// 		if err2 != nil {
// 			panic(err2)
// 		}
// 		result = append(result, item)
// 	}
// 	return result
// }
