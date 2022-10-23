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

func Dummy() {
	db, dbIsAlive := isDBConnectionAlive()
	if dbIsAlive != true {
		panic("No conecto")
	}
	defer db.Close()
	results, err := db.Query("SELECT * FROM users")
	if err != nil {
		panic("Query to DB failed")
	}
	for results.Next() {
		var name string
		var id string
		var email, phone string
		err = results.Scan(&id, &name, &email, &phone)
		if err != nil {
			panic("failed to query")
		}
		fmt.Println(fmt.Sprintf("The data is: %s, %s, %s, %s", id, name, email, phone))
	}
}
