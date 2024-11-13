package handlers

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/models"
	"github.com/ONSdigital/dis-authentication-stub/utils"

	"github.com/ONSdigital/log.go/v2/log"
	"github.com/golang-jwt/jwt"
)

func JWTKeysHandler(ctx context.Context, loadKeysFunc func(context.Context, string) ([]models.Response, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		keys, err := loadKeysFunc(ctx, "static/keys/jwt-keys.json")
		if err != nil {
			log.Error(ctx, "Unable to load JWT keys", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		keysMap := make(map[string]string, 2)

		for _, k := range keys {
			keysMap[k.Kid] = k.Key
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(keysMap)
		if err != nil {
			log.Error(ctx, "Unable to encode keysMap", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func FlorenceLoginHandler(ctx context.Context, usersFile string, templateFile string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		redirectURL := req.URL.Query().Get("redirect")
		if redirectURL == "" {
			redirectURL = "/florence/collections"
		}

		users, err := utils.LoadUsers(ctx, usersFile)
		if err != nil {
			log.Error(ctx, "Unable to load users", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		tmpl, err := template.ParseFiles(templateFile)
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

func FlorenceLoginHandlerPOST(ctx context.Context, usersFile string, privateKeyPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			log.Error(ctx, "Unable to parse form", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Check both form and query parameters
		username := req.FormValue("username")

		redirect := req.FormValue("redirect")
		if redirect == "" {
			redirect = req.URL.Query().Get("redirect")
		}
		// Verify the user by email
		user, err := utils.VerifyUser(ctx, usersFile, username)
		if err != nil {
			log.Error(ctx, "Inavlid user", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		//userID := user.Username
		cfg, _ := config.Get()

		//generate the tokens
		access_token := "Bearer " + generateJWT(*user, "access", *cfg, privateKeyPath)
		id_token := generateJWT(*user, "id", *cfg, privateKeyPath)

		refresh_token := "testrefreshtokennn" // Random opaque token string

		// Store refresh token details in the in-memory map
		models.RefreshTokenStore[refresh_token] = models.RefreshTokenInfo{
			Username:      username,
			AuthTime:      time.Now(),
			SessionExpiry: time.Now().Add(cfg.RefreshTokenValidityDuration), // Use your config for duration
		}

		//add to header
		http.SetCookie(w, &http.Cookie{Name: "access_token", Value: access_token, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "id_token", Value: id_token, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: refresh_token, Path: "/"})

		http.Redirect(w, req, redirect, http.StatusSeeOther)
	}
}

func generateJWT(user models.User, tokenType string, cfg config.Config, privateKeyPath string) string {

	//RS256
	privateKeyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err.Error()
	}

	// Parse the RSA private key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		return err.Error()
	}

	// Define claims based on the token type (access or id) //retrieve them from users.json
	claims := jwt.MapClaims{
		"sub":            user.Username,      // subject (username)
		"cognito:groups": []string{"group1"}, // Example group
		"auth_time":      time.Now().Unix(),  // Auth time
		"iat":            time.Now().Unix(),  // Issued at
	}

	if tokenType == "access" {
		// Additional claims for the access token
		claims["username"] = user.Username
		claims["exp"] = time.Now().Add(cfg.AccessTokenValidityDuration).Unix()
	} else if tokenType == "id" {
		// Additional claims for the ID token
		claims["cognito:username"] = user.Username
		claims["given_name"] = user.Forename
		claims["family_name"] = user.Surname
		claims["email"] = user.Username
		claims["exp"] = time.Now().Add(cfg.IDTokenValidityDuration).Unix()

	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign the token with the pvt key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return err.Error()
	}

	return tokenString
}

func TokenSelfGetHandler(ctx context.Context, templatePath string, filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Load the HTML template
		tmplPath := filepath.Join(templatePath, filename)
		tmpl, err := template.ParseFiles(tmplPath)
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
		refreshCookie, err := req.Cookie("refresh_token")
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

		// Expire cookies by removing them entirely
		expiredTime := time.Now().Add(-1 * time.Hour)

		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    "",
			Path:     "/",
			Expires:  expiredTime,
			MaxAge:   -1,
			HttpOnly: true,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "id_token",
			Value:    "",
			Path:     "/",
			Expires:  expiredTime,
			MaxAge:   -1,
			HttpOnly: true,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Path:     "/",
			Expires:  expiredTime,
			MaxAge:   -1,
			HttpOnly: true,
		})

		// Respond with no content
		w.WriteHeader(http.StatusNoContent)
	}
}

func TokenSelfPutHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// retrieve refresh_token cookie from the request
		refreshCookie, err := req.Cookie("refresh_token")
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
		newAccessToken := "Bearer " + generateJWT(user, "access", *cfg, "static/keys/private.key")
		newIDToken := generateJWT(user, "id", *cfg, "static/keys/private.key")

		// Set new tokens as cookies
		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    newAccessToken,
			Path:     "/",
			HttpOnly: true,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "id_token",
			Value:    newIDToken,
			Path:     "/",
			HttpOnly: true,
		})

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
		serviceToken := strings.Replace(authorizationHeader, "Bearer ", "", 1)
		if serviceAuthTokens[serviceToken] != "" {
			response := map[string]string{"identifier": serviceAuthTokens[serviceToken]}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
			return
		}

		// Service token did not match with any in config
		w.WriteHeader(http.StatusForbidden)

	}
}
