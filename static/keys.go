package static

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"

	"github.com/ONSdigital/dis-authentication-stub/models"
	"github.com/google/uuid"
)

func (f *FileStore) GetPrivateKey() *rsa.PrivateKey {
	return f.privateKey
}

func (f *FileStore) GetPublicKey() *rsa.PublicKey {
	return f.publicKey
}

func (f *FileStore) GetJWKs() map[string]string {
	return f.jwks
}

func (f *FileStore) GetKids() []string {
	return f.kids
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func generateJWKs(publicKey *rsa.PublicKey, n int) (map[string]string, error) {
	keys := make(map[string]string)
	var err error

	for i := 0; i < n; i++ {
		jwk, err := generateJWK(publicKey)
		if err != nil {
			break
		}
		keys[jwk.Kid] = jwk.Key
	}

	return keys, err
}

func generateJWK(publicKey *rsa.PublicKey) (models.JWK, error) {
	kid := uuid.New().String()

	pkixKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return models.JWK{}, err
	}

	stringKey := base64.StdEncoding.EncodeToString(pkixKey)

	jwk := models.JWK{
		Kid: kid,
		Key: stringKey,
	}

	return jwk, nil
}
