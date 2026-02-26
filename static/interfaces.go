package static

import (
	"crypto/rsa"
	"html/template"

	"github.com/ONSdigital/dis-authentication-stub/models"
)

//go:generate moq -out mock/store.go -pkg mock . Store
type Store interface {
	GetDeleteTokenTemplate() (*template.Template, error)
	GetJWKs() map[string]string
	GetKids() []string
	GetPrivateKey() *rsa.PrivateKey
	GetPublicKey() *rsa.PublicKey
	GetUser(email string) (*models.User, error)
	GetCollectionTemplate() (*template.Template, error)
	GetUserLoginTemplate() (*template.Template, error)
	GetUsers() ([]models.User, error)
}
