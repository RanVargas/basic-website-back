package main

import (
	"basic-website-back/Database"
	"basic-website-back/Types"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	googleOauthConfig *oauth2.Config
	oauthStateString  = generateRandomString()
	oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
)

var cookieStore = sessions.NewCookieStore([]byte(oauthStateString))

func init() {
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:5000/login/logingoogle/callback",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}
func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login/logingoogle/callback", handleGoogleCallback)
	r.HandleFunc("/login/logingoogle", handleGoogleLogin)
	r.HandleFunc("/completeprofile", handleProfileCompletion).Methods("POST")
	r.HandleFunc("/healthcheck", healthcheck).Methods("GET")
	r.HandleFunc("/login", handleVanillaLogin).Methods("POST")
	r.HandleFunc("/signup", handleVanillaSignUp).Methods("POST")
	r.HandleFunc("/logout", handleLogout)
	r.HandleFunc("/", handleRoot)

	httpServer := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf(os.Getenv("BASE_URL") + os.Getenv("PORT")),
		WriteTimeout: 15 * time.Second,
	}
	log.Fatal(httpServer.ListenAndServe())
}

func handleProfileCompletion(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(writer, "Method Not Supported", http.StatusMethodNotAllowed)
		return
	}
	uuidCookie, _ := request.Cookie("uuidCookie")
	if uuidCookie == nil {
		http.Error(writer, "Not authenticated", http.StatusForbidden)
		return
	}
	session, _ := cookieStore.Get(request, "session.id")
	if session != nil && session.Values["authenthicated"] == true {
		var resultUser Types.User
		password := request.FormValue("password")
		name := request.FormValue("name")
		phone := request.FormValue("phone")
		email := request.FormValue("email")
		userInDb := Database.GetUserByUUID(uuidCookie.Value)
		if password != "" && password != userInDb.Password {
			resultUser.Password = password
		}
		if email != "" && email != userInDb.Email {
			doesEmailExists := Database.DoesUserExists(email)
			if !doesEmailExists {
				resultUser.Email = email
			}
		}
		if name != "" && name != userInDb.Name {
			resultUser.Name = name
		}
		if phone != "" && phone != userInDb.Phone {
			resultUser.Phone = phone
		}
		Database.UpdateUser(*userInDb)
		json.NewEncoder(writer).Encode(resultUser)

	}

}

func healthcheck(writer http.ResponseWriter, request *http.Request) {
	session, _ := cookieStore.Get(request, "session.id")
	authenticated := session.Values["authenticated"]
	if authenticated != nil && authenticated != false {
		json.NewEncoder(writer).Encode(true)
		return
	} else {
		http.Error(writer, "Forbidden", http.StatusForbidden)
		json.NewEncoder(writer).Encode(false)
		return
	}
}

func handleVanillaSignUp(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(writer, "Method Not Supported", http.StatusMethodNotAllowed)
		return
	}

	err := request.ParseForm()
	if err != nil {
		http.Error(writer, "Try again", http.StatusInternalServerError)
	}
	email := request.FormValue("email")
	password := request.FormValue("password")

	if email == "" || password == "" {
		http.Error(writer, "Please try again", http.StatusBadRequest)
		return
	}
	userRegistered := Database.DoesUserExists(email)
	if userRegistered {
		log.Printf("User has already registered")
		http.Error(writer, "You already have an account", http.StatusBadRequest)
		http.Redirect(writer, request, "/login", http.StatusTemporaryRedirect)
		return
	}
	userToSave := Types.User{
		UUID:                  uuid.New().String(),
		Email:                 email,
		Password:              password,
		IsGoogleAuthenticated: "NO",
	}
	Database.SaveUser(userToSave)
	session, _ := cookieStore.Get(request, "session.id")
	session.Values["authenticated"] = true
	session.Options.HttpOnly = true
	session.Save(request, writer)
	generateSpecialCookie("uuidCookie", userToSave.UUID, writer)
}

func handleVanillaLogin(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(writer, "Method Not Supported", http.StatusMethodNotAllowed)
		return
	}

	err := request.ParseForm()
	if err != nil {
		http.Error(writer, "Please pass the data as URL form encoded", http.StatusBadRequest)
		return
	}

	email := request.FormValue("email")
	password := request.FormValue("password")
	user := Database.GetUserById(email)
	if user.Email == "" {
		http.Error(writer, "You have not signed up yet", http.StatusUnauthorized)
	} else {
		if user.IsGoogleAuthenticated == "NO" {
			if password == user.Password {
				session, _ := cookieStore.Get(request, "session.id")
				session.Values["authenticated"] = true
				generateSpecialCookie("uuidCookie", user.UUID, writer)
				session.Options.HttpOnly = true
				session.Save(request, writer)
			} else {
				http.Error(writer, "Invalud Credentials", http.StatusUnauthorized)
			}
		} else if user.IsGoogleAuthenticated == "YES" {
			http.Redirect(writer, request, "/login/logingoogle", http.StatusTemporaryRedirect)
		}
	}

}

func handleRoot(writer http.ResponseWriter, request *http.Request) {
	//TODO return the profile with data
	cookieInMemory, err := request.Cookie("uuidCookie")
	if (cookieInMemory == nil || cookieInMemory.Value == "") && err != nil {
		http.Error(writer, "You have not logged in yet", http.StatusUnauthorized)
		return
	}
	user := Database.GetUserByUUID(cookieInMemory.Value)
	json.NewEncoder(writer).Encode(user)
}

func handleLogout(writer http.ResponseWriter, request *http.Request) {
	tokenCookie, _ := request.Cookie("stringT")
	if tokenCookie != nil {
		http.Redirect(writer, request, fmt.Sprintf("https://accounts.google.com/o/oauth2/revoke?token=%s", tokenCookie.Value), http.StatusTemporaryRedirect)
	}
	session, _ := cookieStore.Get(request, "session.id")
	session.Values["authenticated"] = false
	session.Save(request, writer)

	uuidCookie, _ := request.Cookie("uuidCookie")
	if uuidCookie == nil {
		writer.Write([]byte("You are not logged in"))
		return
	}
	uuidCookie.Value = ""
	writer.Write([]byte("Logout Successful"))
}

func handleGoogleCallback(writer http.ResponseWriter, request *http.Request) {
	oauthStateCookie, _ := request.Cookie("oauthstate")
	if request.FormValue("state") != oauthStateCookie.Value {
		log.Printf("Invalid oauth google state")
		http.Redirect(writer, request, "/logout", http.StatusTemporaryRedirect)
	}

	data, err := getUserDataFromGoogle(request.FormValue("code"), writer, request)
	if err != nil {
		log.Println(err.Error())
		http.Redirect(writer, request, "/logout", http.StatusTemporaryRedirect)
		return
	}

	var user Types.User
	err = json.Unmarshal(data, &user)
	if err != nil {
		log.Printf(err.Error())
	}

	userExistance := Database.DoesUserExists(user.Email)
	if !userExistance {
		userInDb := Types.User{
			UUID:                  uuid.New().String(),
			Email:                 user.Email,
			IsGoogleAuthenticated: "YES",
		}
		generateSpecialCookie("uuidCookie", userInDb.UUID, writer)
		Database.SaveUser(userInDb)
		json.NewEncoder(writer).Encode(userInDb)
	} else {
		tempUser := Database.GetUserById(user.Email)
		tempUser.Password = ""
		generateSpecialCookie("uuidCookie", tempUser.UUID, writer)
		json.NewEncoder(writer).Encode(tempUser)
	}

	session, _ := cookieStore.Get(request, "session.id")
	session.Options.HttpOnly = true
	session.Values["authenticated"] = true
	session.Save(request, writer)
}

func getUserDataFromGoogle(code string, writer http.ResponseWriter, request *http.Request) ([]byte, error) {
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	generateSpecialCookie("stringT", token.AccessToken, writer)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	//session.Save(request, writer)
	googleResponse, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if googleResponse == nil || err != nil {
		return nil, fmt.Errorf("failed getting user info %s", err.Error())
	}
	defer googleResponse.Body.Close()
	contents, err := ioutil.ReadAll(googleResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}

func handleGoogleLogin(writer http.ResponseWriter, request *http.Request) {
	generateStateOauthCookie(writer)
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(writer, request, url, http.StatusTemporaryRedirect)
}

func generateStateOauthCookie(writer http.ResponseWriter) {
	expiration := time.Now().Add(20 * time.Minute)

	cookie := http.Cookie{
		Name:     "oauthstate",
		Value:    oauthStateString,
		Expires:  expiration,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(writer, &cookie)
}

func generateSpecialCookie(cookieName string, cookieValue string, writer http.ResponseWriter) {
	//expiration := time.Now().Add(60 * time.Minute)

	cookie := http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		MaxAge:   60,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(writer, &cookie)
}

func generateRandomString() string {
	stringBuilt := strings.Builder{}
	var randomizedString strings.Builder
	charset := "abcdefghijklmnopqrstuvwxyz"
	stringBuilt.WriteString(charset)
	stringBuilt.WriteString(strings.ToUpper(charset))
	stringBuilt.WriteString("_-!@#$%^&*")
	completeString := stringBuilt.String()
	charactersInString := []rune(completeString)

	for i := 0; i < len(completeString); i++ {
		randomizedString.WriteRune(charactersInString[rand.Intn(len(charactersInString))])
	}

	return randomizedString.String()
}
