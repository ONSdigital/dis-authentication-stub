package models

type User struct {
	AccessToken string   `json:"-"`
	Email       string   `json:"email"`
	Username    string   `json:"username"` // uuid
	Forename    string   `json:"forename"`
	Surname     string   `json:"surname"`
	Groups      []string `json:"groups"` // array of group IDs e.g. ["role-admin"]
	Expiry      string   `json:"expiry"`
}
