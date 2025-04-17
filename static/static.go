package static

import (
	"crypto/rsa"
	_ "embed"
	"encoding/json"
	"errors"

	"github.com/ONSdigital/dis-authentication-stub/models"
)

type FileStore struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	jwks       map[string]string
	kids       []string
}

func NewFilestore() (*FileStore, error) {
	var f FileStore
	bitSize := 2048

	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		return nil, err
	}

	f.privateKey = privateKey
	f.publicKey = &privateKey.PublicKey

	jwks, err := generateJWKs(f.publicKey, 2)
	if err != nil {
		return nil, err
	}

	f.jwks = jwks

	kids := make([]string, len(jwks))
	i := 0

	for kid := range jwks {
		kids[i] = kid
		i++
	}

	f.kids = kids

	return &f, nil
}

//go:embed json/users.json
var usersJSONBytes []byte

//go:embed json/groups.json
var groupsJSONBytes []byte

func (f *FileStore) GetUsers() ([]models.User, error) {
	var users []models.User

	err := json.Unmarshal(usersJSONBytes, &users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (f *FileStore) GetUser(email string) (*models.User, error) {
	// Load users from the file
	users, err := f.GetUsers()
	if err != nil {
		return nil, err
	}

	// Find user with the given email
	for _, user := range users {
		if user.Email == email {
			return &user, nil
		}
	}

	// If no user was found
	return nil, errors.New("user not found")
}

func (f *FileStore) GetGroups() ([]models.Group, error) {
	var groups []models.Group

	err := json.Unmarshal(groupsJSONBytes, &groups)
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (f *FileStore) GetGroup(id string) (*models.Group, error) {
	// Load groups from the file
	groups, err := f.GetGroups()
	if err != nil {
		return nil, err
	}

	// Find group with the given ID
	for _, group := range groups {
		if group.ID == id {
			return &group, nil
		}
	}

	// If no group was found
	return nil, errors.New("group not found")
}
