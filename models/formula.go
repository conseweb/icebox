package models

import (
	_ "github.com/jinzhu/gorm"

	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"fmt"
)

type Formula struct {
	ID      uint32 `gorm:"AUTO_INCREMENT, PRIMARY_KEY"` // set id to auto incrementable
	T2      uint32 `gorm:"not null"`                    // for bip44: coin_type
	T4 		uint32 `gorm:"default:0"`					// for bip44: change/chain
	T5      uint32 `gorm:"not null"`					// for bip44: address_index
	Name    string
}

func (p Formula) GetEquality() (res string) {
	res = fmt.Sprintf("%i/%i", p.T4, p.T5)
	return res
}

//func (a Formula) CreateAddrTable(db *sql.DB) {
//	// create table if not exists
//	sql_table := `
//	CREATE TABLE IF NOT EXISTS "addrs"(
//		Id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
//		Type integer NOT NULL,
//		Index integer NOT NULL,
//		Path char(256) NOT NULL,
//		Name char(32)
//	);
//	`
//
//	_, err := db.Exec(sql_table)
//	if err != nil {
//		panic(err)
//	}
//}
//
//func (a Formula) StoreItem(db *sql.DB, items []Formula) {
//	sql_additem := `
//	INSERT OR REPLACE INTO addrs(
//		Type,
//		Index,
//		Path,
//		Name
//	) values(?, ?, ?, ?)
//	`
//
//	stmt, err := db.Prepare(sql_additem)
//	if err != nil {
//		panic(err)
//	}
//	defer stmt.Close()
//
//	for _, item := range items {
//		_, err2 := stmt.Exec(item.Id, item.Type, item.Index, item.Path, item.Name)
//		if err2 != nil {
//			panic(err2)
//		}
//	}
//}
//
//func (a Formula) ReadItem(db *sql.DB) []Formula {
//	sql_readall := `
//		SELECT Id, Type, Index, Path, Name FROM addrs
//		ORDER BY Id DESC
//	`
//
//	rows, err := db.Query(sql_readall)
//	if err != nil {
//		panic(err)
//	}
//	defer rows.Close()
//
//	var result []Formula
//	for rows.Next() {
//		item := Formula{}
//		err2 := rows.Scan(&item.Id, &item.Type, &item.Index, &item.Path, &item.Name)
//		if err2 != nil {
//			panic(err2)
//		}
//		result = append(result, item)
//	}
//	return result
//}
