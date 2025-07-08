// handlers/auth.go
package handlers

import (
	"net/http"
	"strings"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/utils"
	"github.com/ONSdigital/log.go/v2/log"
)

const BearerPrefix = "Bearer "

// checkServiceToken returns the identifier plus a zero status on success,
// or an empty string and an HTTP status code to write on failure.
func checkServiceToken(r *http.Request) (string, int) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		log.Error(r.Context(), "Authorization header missing", nil)
		return "", http.StatusUnauthorized
	}

	cfg, _ := config.Get()
	serviceAuthTokens := utils.GetServiceAuthTokens(*cfg)
	serviceToken := strings.TrimPrefix(authorizationHeader, BearerPrefix)
	xFlorence := strings.TrimPrefix(r.Header.Get("X-Florence-Token"), BearerPrefix)

	if id := serviceAuthTokens[serviceToken]; id != "" && xFlorence == serviceToken {
		return id, 0
	}

	// Service token did not match with any in config
	return "", http.StatusForbidden
}
