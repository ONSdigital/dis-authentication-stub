package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/models"
	"github.com/ONSdigital/dis-authentication-stub/static"
	"github.com/ONSdigital/dis-authentication-stub/utils"

	"github.com/ONSdigital/log.go/v2/log"
	"github.com/golang-jwt/jwt"
)

const (
	BearerPrefix = "Bearer "
)

func JWTKeysHandler(ctx context.Context, store static.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		keys := store.GetJWKs()

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(keys)
		if err != nil {
			log.Error(ctx, "Unable to encode JWKs", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func FlorenceLoginHandler(ctx context.Context, store static.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		redirectURL := req.URL.Query().Get("redirect")
		if redirectURL == "" {
			redirectURL = "/florence/collections"
		}

		users, err := store.GetUsers()
		if err != nil {
			log.Error(ctx, "Unable to load users", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		tmpl, err := store.GetUserLoginTemplate()
		if err != nil {
			log.Error(ctx, "Could not parse template file", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var data = models.TemplateData{
			Users:       users,
			RedirectURL: redirectURL,
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			log.Error(ctx, "Could not apply template", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func FlorenceLoginHandlerPOST(ctx context.Context, store static.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			log.Error(ctx, "Unable to parse form", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Check both form and query parameters
		username := req.FormValue("username")

		if username == "" {
			log.Error(ctx, "No username in request", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		redirect := req.FormValue("redirect")
		if redirect == "" {
			redirect = req.URL.Query().Get("redirect")
		}
		// Get the user by email
		user, err := store.GetUser(username)
		if err != nil {
			log.Error(ctx, "Couldn't get user", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		cfg, _ := config.Get()

		// generate the tokens
		accessToken, err := generateAccessTokenJWT(store, *user, cfg.AccessTokenValidityDuration)
		if err != nil {
			log.Error(ctx, "Failed to generate access token JWT", err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		idToken, err := generateIDTokenJWT(store, *user, cfg.IDTokenValidityDuration)
		if err != nil {
			log.Error(ctx, "Failed to generate access token JWT", err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		refreshToken := "testrefreshtokennn" // Random opaque token string

		// Store refresh token details in the in-memory map
		models.RefreshTokenStore[refreshToken] = models.RefreshTokenInfo{
			Username:      username,
			AuthTime:      time.Now(),
			SessionExpiry: time.Now().Add(cfg.RefreshTokenValidityDuration), // Use your config for duration
		}

		// add to header
		setAccessTokenCookie(w, accessToken)
		setIDTokenCookie(w, idToken)
		setRefreshTokenCookie(w, refreshToken)

		http.Redirect(w, req, redirect, http.StatusSeeOther)
	}
}

// FlorenceLogoutHandler invalidates the access, ID and refresh tokens and redirects to the login page
func FlorenceLogoutHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		invalidateAccessTokenCookie(w)
		invalidateIDTokenCookie(w)
		invalidateRefreshTokenCookie(w)

		url := "/florence/login"
		redirect := req.URL.Query().Get("redirect")
		if redirect != "" {
			url += fmt.Sprintf("?redirect=%s", redirect)
		}

		http.Redirect(w, req, url, http.StatusSeeOther)
	}
}

func generateAccessTokenJWT(store static.Store, user models.User, validity time.Duration) (string, error) {
	accessTokenClaims := jwt.MapClaims{
		"username": user.Username,
	}

	accessTokenJWT, err := generateJWT(store, user, accessTokenClaims, validity)
	if err != nil {
		return "", err
	}

	accessToken := BearerPrefix + accessTokenJWT

	return accessToken, nil
}

func generateIDTokenJWT(store static.Store, user models.User, validity time.Duration) (string, error) {
	idTokenClaims := jwt.MapClaims{
		"cognito:username": user.Username,
		"given_name":       user.Forename,
		"family_name":      user.Surname,
		"email":            user.Username,
	}
	return generateJWT(store, user, idTokenClaims, validity)
}

func generateJWT(store static.Store, user models.User, claims jwt.MapClaims, validity time.Duration) (string, error) {
	privateKey := store.GetPrivateKey()
	kids := store.GetKids()

	claims["auth_time"] = time.Now().Unix()         // Auth time
	claims["cognito:groups"] = user.Groups          // Example Group TODO: pull this from somewhere
	claims["iat"] = time.Now().Unix()               // Issued at
	claims["sub"] = user.Username                   // subject (username)
	claims["exp"] = time.Now().Add(validity).Unix() // Expires at

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kids[0]

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func TokenSelfGetHandler(ctx context.Context, store static.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// Load the HTML template
		tmpl, err := store.GetDeleteTokenTemplate()
		if err != nil {
			log.Error(ctx, "Failed to load template", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Execute the template and write to response
		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.Execute(w, nil); err != nil {
			log.Error(ctx, "Failed to render template", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func TokenSelfDeleteHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// retrieve the refresh token from cookies
		refreshCookie, err := req.Cookie(models.RefreshTokenCookie)
		if err != nil {
			log.Error(ctx, "Refresh token not found", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check if the refresh token exists in the in-memory store
		refreshToken := refreshCookie.Value
		if _, exists := models.RefreshTokenStore[refreshToken]; !exists {
			log.Error(ctx, "Invalid or expired refresh token", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Remove the session entry from the in-memory store
		delete(models.RefreshTokenStore, refreshToken)

		invalidateAccessTokenCookie(w)
		invalidateIDTokenCookie(w)
		invalidateRefreshTokenCookie(w)

		// Respond with no content
		w.WriteHeader(http.StatusNoContent)
	}
}

func TokenSelfPutHandler(ctx context.Context, store static.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// retrieve refresh_token cookie from the request
		refreshCookie, err := req.Cookie(models.RefreshTokenCookie)
		if err != nil {
			log.Error(ctx, "Refresh token not present", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		refreshTokenValue := refreshCookie.Value

		// Check if the refresh token exists and hasn't expired
		tokenInfo, exists := models.RefreshTokenStore[refreshTokenValue]
		if !exists || tokenInfo.SessionExpiry.Before(time.Now()) {
			log.Error(ctx, "Invalid or expired refresh token", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Retrieve the user details from the in-memory map using the username
		user := models.User{
			Username: tokenInfo.Username,
		}

		cfg, _ := config.Get()

		// Generate new tokens
		newAccessToken, err := generateAccessTokenJWT(store, user, cfg.AccessTokenValidityDuration)
		if err != nil {
			log.Error(ctx, "Failed to generate access token JWT", err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		newIDToken, err := generateIDTokenJWT(store, user, cfg.IDTokenValidityDuration)
		if err != nil {
			log.Error(ctx, "Failed to generate access token JWT", err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		// Set new tokens as cookies
		setAccessTokenCookie(w, newAccessToken)
		setIDTokenCookie(w, newIDToken)

		// Respond with a 200 OK status
		w.WriteHeader(http.StatusOK)
	}
}

// Verify the service token exists within config
func IdentifyUser(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Retrieve Authorization header
		authorizationHeader := req.Header.Get("Authorization")
		if authorizationHeader == "" {
			log.Error(ctx, "Authorization header missing", nil)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check if service token from header matches one in config
		cfg, _ := config.Get()
		serviceAuthTokens := utils.GetServiceAuthTokens(*cfg)
		serviceToken := strings.Replace(authorizationHeader, BearerPrefix, "", 1)
		if serviceAuthTokens[serviceToken] != "" {
			response := map[string]string{"identifier": serviceAuthTokens[serviceToken]}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				log.Error(ctx, "Error encoding response", err)
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			return
		}

		// Service token did not match with any in config
		w.WriteHeader(http.StatusForbidden)
	}
}

func invalidateAccessTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     models.AccessTokenCookie,
		Expires:  time.Unix(0, 0),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
	})
}

func setAccessTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     models.AccessTokenCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
	})
}

func invalidateRefreshTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     models.RefreshTokenCookie,
		Expires:  time.Unix(0, 0),
		Value:    "",
		Path:     models.RefreshTokenCookiePath,
		HttpOnly: true,
	})
}

func setRefreshTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     models.RefreshTokenCookie,
		Value:    token,
		Path:     models.RefreshTokenCookiePath,
		HttpOnly: true,
	})
}

func invalidateIDTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    models.IDTokenCookie,
		Expires: time.Unix(0, 0),
		Value:   "",
		Path:    "/",
	})
}

func setIDTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:  models.IDTokenCookie,
		Value: token,
		Path:  "/",
	})
}
