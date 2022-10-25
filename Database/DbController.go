package Database

import (
	"basic-website-back/Types"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"os"
)

func isDBConnectionAlive() (*sql.DB, bool) {
	DBUser := os.Getenv("DB_USER")
	DBPassword := os.Getenv("DB_USER_PASSWORD")
	DBIP := os.Getenv("DB_IP")
	DBName := os.Getenv("DB_Name")
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", DBUser, DBPassword, DBIP, DBName))
	if err != nil {
		fmt.Errorf("An error connecting to the DB has ocurred %s", err.Error())
		return nil, false
	}
	return db, true
}

func UpdateUser(user Types.User) bool {
	db, dbIsAlive := isDBConnectionAlive()
	if dbIsAlive == false {
		panic("DB connection failed")
	}
	defer db.Close()

	insertStmnt, err := db.Prepare("UPDATE users SET EMAIL=?, NAME=?, PHONE=?, PASSWORD=? WHERE UUID=?")
	if err != nil {
		fmt.Errorf("An error updating the record on DB has ocurred ", err.Error())
		return false
	}
	_, err = insertStmnt.Exec(user.Email, user.Name, user.Phone, user.Password, user.UUID)

	if err != nil {
		fmt.Errorf("An error updating the record on DB has ocurred ", err.Error())
		return false
	}
	return true
}

func SaveUser(user Types.User) bool {
	db, dbIsAlive := isDBConnectionAlive()
	if dbIsAlive == false {
		panic("DB connection failed")
	}
	defer db.Close()

	insert, err := db.Query(fmt.Sprintf("INSERT INTO users (UUID, NAME, EMAIL, PHONE, PASSWORD, IS_GOOGLE_AUTHENTICATED) VALUES ('%s', '%s', '%s', '%s', '%s', '%s')", user.UUID, user.Name, user.Email, user.Phone, user.Password, user.IsGoogleAuthenticated))
	if err != nil {
		panic(err.Error())
		return false
	}
	defer insert.Close()
	return true
}

func DoesUserExists(email string) bool {
	db, dbIsAlive := isDBConnectionAlive()
	if dbIsAlive == false {
		panic("DB connection failed")
	}
	defer db.Close()
	results, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email))
	if err != nil {
		fmt.Println(err)
		panic("Query to DB failed")
	}
	i := 0
	for results.Next() {
		i++
	}
	defer results.Close()
	if i == 0 {
		return false
	}
	return true
}

func GetUserByUUID(uniqueId string) *Types.User {
	db, dbIsAlive := isDBConnectionAlive()
	if dbIsAlive == false {
		panic("DB connection failed")
	}
	defer db.Close()

	results, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE UUID = '%s'", uniqueId))
	if err != nil {
		fmt.Println(err)
		panic("Query to DB failed")
	}
	var user Types.User
	i := 0
	for results.Next() {
		i++
		var id, uuid, name, email, phone, password, isGoogleAuthenticated string
		err = results.Scan(&id, &uuid, &name, &email, &phone, &password, &isGoogleAuthenticated)
		if err != nil {
			panic("failed to query")
		}
		user = Types.User{
			UUID:                  uuid,
			Name:                  name,
			Phone:                 phone,
			Email:                 email,
			Password:              password,
			IsGoogleAuthenticated: isGoogleAuthenticated,
		}
	}
	defer results.Close()
	if i == 0 {
		return nil
	}
	return &user
}

func GetUserById(email string) Types.User {
	db, dbIsAlive := isDBConnectionAlive()
	if dbIsAlive == false {
		panic("DB connection failed")
	}
	defer db.Close()

	results, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email))
	if err != nil {
		fmt.Println(err)
		panic("Query to DB failed")
	}
	var user Types.User
	for results.Next() {
		var id, uuid, name, email, phone, password, isGoogleAuthenticated string
		err = results.Scan(&id, &uuid, &name, &email, &phone, &password, &isGoogleAuthenticated)
		if err != nil {
			panic("failed to query")
		}
		user = Types.User{
			UUID:                  uuid,
			Name:                  name,
			Phone:                 phone,
			Email:                 email,
			Password:              password,
			IsGoogleAuthenticated: isGoogleAuthenticated,
		}
	}

	return user
}
