package models

type User struct {
	Email    string   `json:"email"`
	Username string   `json:"username"` // uuid
	Forename string   `json:"forename"`
	Surname  string   `json:"surname"`
	Groups   []string `json:"groups"` // array of group IDs e.g. ["role-admin"]
}

type TemplateData struct {
	Users       []User
	RedirectURL string
}
