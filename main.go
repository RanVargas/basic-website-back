package main

import (
	"basic-website-back/Database"
	"basic-website-back/Types"
	"context"
	"encoding/json"
	"fmt"
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
	http.HandleFunc("/login/logingoogle", handleGoogleLogin)
	http.HandleFunc("/login/logingoogle/callback", handleGoogleCallback)
	http.HandleFunc("")
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/", handleRoot)
	if err := http.ListenAndServe(":5000", nil); err != nil {
		fmt.Errorf("The server has encountered an error %s", err.Error())
	}

}

func handleRoot(writer http.ResponseWriter, request *http.Request) {
	//TODO return the profile with data
	Database.GetUser()
}

func handleLogout(writer http.ResponseWriter, request *http.Request) {
	tokenCookie, _ := request.Cookie("stringT")
	if tokenCookie != nil {
		http.Redirect(writer, request, fmt.Sprintf("https://accounts.google.com/o/oauth2/revoke?token=%s", tokenCookie.Value), http.StatusTemporaryRedirect)
	}

}

func handleGoogleCallback(writer http.ResponseWriter, request *http.Request) {
	fmt.Println(request.FormValue("state"))
	oauthStateCookie, _ := request.Cookie("oauthstate")
	if request.FormValue("state") != oauthStateCookie.Value {
		log.Printf("Invalid oauth google state")
		http.Redirect(writer, request, "/logout", http.StatusTemporaryRedirect)
	}

	data, err := getUserDataFromGoogle(request.FormValue("code"), writer)
	if err != nil {
		log.Println(err.Error())
		http.Redirect(writer, request, "/logout", http.StatusTemporaryRedirect)
		return
	}
	//persist data of user to DB.
	//fmt.Fprintf(writer, " UserInfo: %s\n", data)
	var user Types.User
	err = json.Unmarshal(data, &user)
	if err != nil {
		log.Printf(err.Error())
	}
	userInDb := Database.GetUser(user.Email)
	if userInDb.Email == "" {
		Database.SaveUser(&user)
	}
	http.Redirect(writer, request, "/", http.StatusTemporaryRedirect)
}

func getUserDataFromGoogle(code string, writer http.ResponseWriter) ([]byte, error) {
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	generateSpecialCookie("stringT", token.AccessToken, writer)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	googleResponse, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
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
		HttpOnly: true,
	}
	http.SetCookie(writer, &cookie)
}

func generateSpecialCookie(cookieName string, cookieValue string, writer http.ResponseWriter) {
	expiration := time.Now().Add(30 * time.Minute)

	cookie := http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		Expires:  expiration,
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
