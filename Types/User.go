package Types

type User struct {
	UUID                  string `json:"UUID"`
	Email                 string `json:"email"`
	Name                  string `json:"name"`
	Phone                 string `json:"phone"`
	Password              string `json:"password"`
	IsGoogleAuthenticated string `json:"isGoogleAuthenticated"`
}
