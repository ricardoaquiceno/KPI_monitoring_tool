package mydb

import (
	"database/sql"
	"errors"
	"fmt"
	"gopacket_analysis/models"
	"log"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const dbString = "./network.db"

func InitSql() {
	db, err := sql.Open("sqlite", dbString)
	if err != nil {
		log.Fatal(err)
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			log.Fatal(err)
			return
		}
	}(db)

	sqlStmt := `
	create table if not exists found_ports (
	    port integer not null, 
	    protocol text not null, 
	    application text, 
	    comment text,
	   constraint pk1
        primary key (port, protocol)
	);
	`

	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Printf("%q: %s\n", err, sqlStmt)
		return
	}

	sql2 := `create table if not exists last_packets
(
    packet_num integer
        constraint last_packets_pk
            primary key,
    layer0     		varchar,
    layer1     		varchar,
    layer2     		varchar,
    layer3     		varchar,
    data       		varchar,
    packet_string 	varchar,
    layer4	   		varchar
);
`
	_, err = db.Exec(sql2)
	if err != nil {
		log.Printf("%q: %s\n", err, sql2)
		return
	}
}

func InsertSql(pp models.PortProtocol, mi models.MappingInfo, tries int) bool {
	db, err := sql.Open("sqlite", dbString)
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	// Prepare the statement
	stmt, err := db.Prepare("insert into found_ports(port, protocol, application, comment) values(?,?,?,?)")
	if err != nil {
		panic(err)
	}
	defer stmt.Close()

	// Execute the statement with the variables
	_, err = stmt.Exec(pp.Port, pp.Protocol, mi.Application, mi.Comment)
	if err == nil {
		fmt.Println("Found Port:", pp.Port, "Protocol:", pp.Protocol, "Application:", mi.Application)
		return true
	}
	var liteErr *sqlite.Error
	if errors.As(err, &liteErr) {
		code := liteErr.Code()
		log.Println(pp.Port, pp.Protocol, mi.Application)

		if code == sqlite3.SQLITE_CONSTRAINT_UNIQUE || code == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY {
			log.Println("Already in database!")
			return true
		} else if code == sqlite3.SQLITE_LOCKED {
			if tries > 0 {
				tries--
				return InsertSql(pp, mi, tries)
			} else {
				log.Println("DB LOCK!")
				return false
			}
		} else {
			log.Println("Unknown SQLITE Error happen with Code", liteErr.Code(), "and message", liteErr.Error())
			return false
		}
	} else {
		log.Println(pp.Port, pp.Protocol, mi.Application)
		log.Println("Unknown error happened", err)
		return false
	}
}

func RetrieveSql() map[models.PortProtocol]models.MappingInfo {
	db, err := sql.Open("sqlite", dbString)
	if err != nil {
		log.Fatal(err)
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			log.Fatal(err)
			return
		}
	}(db)

	rows, err := db.Query("select port, protocol, application, comment from found_ports")
	if err != nil {
		log.Fatal(err)
	}

	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			log.Fatal(err)
			return
		}
	}(rows)

	type portInfo struct {
		protocol  string
		otherInfo string
	}

	var portMappings []models.PortMapping
	_ = portMappings
	portMap := map[int]portInfo{}

	portMap[443] = portInfo{protocol: "TCP", otherInfo: ""}
	found := map[models.PortProtocol]models.MappingInfo{}
	_ = found
	foundLen := 0
	for rows.Next() {
		foundLen++
		var pp models.PortProtocol
		var mi models.MappingInfo
		err = rows.Scan(&pp.Port, &pp.Protocol, &mi.Application, &mi.Comment)
		if err != nil {
			log.Fatal(err)
		} else {
			found[pp] = mi
		}
	}
	log.Println("Found", foundLen)
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	return found
}

func LastPacketsReset() {
	db, err := sql.Open("sqlite", dbString)
	if err != nil {
		log.Fatal(err)
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			log.Fatal(err)
			return
		}
	}(db)

	sqlStmt := `
	delete from last_packets;
	;
	`

	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Printf("%q: %s\n", err, sqlStmt)
		return
	}
}

func LastPacketsInsert(packetNum int, layer0 string, layer1 string, layer2 string, layer3 string, layer4 string, data string, full string, tries int) bool {
	db, err := sql.Open("sqlite", dbString)
	if err != nil {
		log.Fatal(err)
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			log.Fatal(err)
			return
		}
	}(db)

	// Prepare the statement
	stmt, err := db.Prepare("insert into last_packets (packet_num, layer0, layer1, layer2, layer3, layer4, data, packet_string) VALUES (?,?,?,?,?,?,?,?)")
	if err != nil {
		panic(err)
	}
	defer stmt.Close()

	// Execute the statement with the variables
	_, err = stmt.Exec(packetNum, layer0, layer1, layer2, layer3, layer4, data, full)
	if err == nil {
		return true
	}
	var liteErr *sqlite.Error
	if errors.As(err, &liteErr) {
		code := liteErr.Code()

		if code == sqlite3.SQLITE_CONSTRAINT_UNIQUE || code == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY {
			log.Println("Already in database!")
			return true
		} else if code == sqlite3.SQLITE_LOCKED {
			if tries > 0 {
				tries--
				return LastPacketsInsert(packetNum, layer0, layer1, layer2, layer3, layer4, data, full, tries)
			} else {
				log.Println("DB LOCK!")
				return false
			}
		} else {
			log.Println("Unknown SQLITE Error happen with Code", liteErr.Code(), "and message", liteErr.Error())
			return false
		}
	} else {
		log.Println("Unknown error happened", err)
		return false
	}
	return false
}
