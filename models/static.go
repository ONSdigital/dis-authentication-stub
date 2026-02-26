package models

type TemplateData struct {
	PageTitle   string
	Users       []User
	User        *User
	RedirectURL string
}

type JWK struct {
	Kid string `json:"kid"`
	Key string `json:"key"`
}
