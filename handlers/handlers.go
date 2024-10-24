package handlers

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/models"
	"github.com/ONSdigital/dis-authentication-stub/utils"

	"github.com/ONSdigital/log.go/v2/log"
	"github.com/golang-jwt/jwt"
)

func FlorenceLoginHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "Request method not allowed", http.StatusMethodNotAllowed)
		}

		redirectURL := req.URL.Query().Get("redirect")
		if redirectURL == "" {
			redirectURL = "/florence/collections"
		}

		users, err := utils.LoadUsers(ctx, "static/json/users.json")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		filename := "templates/user.login.html"
		tmpl, err := template.ParseFiles(filename)
		if err != nil {
			log.Fatal(ctx, fmt.Sprintf("could not parse template file %s", filename), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var data = models.TemplateData{
			Users:       users,
			RedirectURL: redirectURL,
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			log.Fatal(ctx, "could not apply template", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func FlorenceLoginHandlerPOST(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "Request method not allowed", http.StatusMethodNotAllowed)
		}

		err := req.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}
		// Check both form and query parameters
		username := req.FormValue("username")

		redirect := req.FormValue("redirect")
		if redirect == "" {
			redirect = req.URL.Query().Get("redirect")
		}
		// Verify the user by email
		user, err := utils.VerifyUser(ctx, "static/json/users.json", username)
		if err != nil {
			http.Error(w, "Invalid user", http.StatusBadRequest)
			return
		}

		//userID := user.Username
		cfg, _ := config.Get()

		//generate the tokens
		access_token := "Bearer " + generateJWT(*user, username, "access", *cfg)
		id_token := generateJWT(*user, username, "id", *cfg)

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

func generateJWT(user models.User, username string, tokenType string, cfg config.Config) string {

	//RS256
	privateKeyData, err := os.ReadFile("static/keys/private.key")
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
