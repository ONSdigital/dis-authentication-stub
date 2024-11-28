package models

type TemplateData struct {
	Users       []User
	RedirectURL string
}

type JWK struct {
	Kid string `json:"kid"`
	Key string `json:"key"`
}
