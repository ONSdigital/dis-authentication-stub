package handlers

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/models"
	"github.com/ONSdigital/dis-authentication-stub/static"

	"github.com/ONSdigital/log.go/v2/log"
	jwt "github.com/golang-jwt/jwt/v4"
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
		var redirectURL string
		if req.URL.Query().Get("redirect") != "" {
			redirectURL = html.EscapeString(req.URL.Query().Get("redirect"))
		}
		if req.URL.Query().Get("next") != "" {
			redirectURL = html.EscapeString(req.URL.Query().Get("next"))
		}
		// if both 'next' and 'redirect' keys present, set empty string
		if req.URL.Query().Get("next") != "" && req.URL.Query().Get("redirect") != "" {
			redirectURL = ""
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
			PageTitle:   "Login",
			Users:       users,
			RedirectURL: redirectURL,
		}

		err = tmpl.ExecuteTemplate(w, "page", data)
		if err != nil {
			log.Error(ctx, "Could not apply template", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func FlorenceCollectionsHandler(ctx context.Context, store static.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		idTokenCookie, err := req.Cookie(models.IDTokenCookie)
		if err != nil {
			log.Error(ctx, "ID token cookie not found", err)
			http.Redirect(w, req, "/florence/login", http.StatusSeeOther)
			return
		}

		user, err := decodeIDTokenUser(idTokenCookie.Value, store.GetPublicKey())
		if err != nil {
			log.Error(ctx, "Could not decode ID token", err)
			http.Redirect(w, req, "/florence/login", http.StatusSeeOther)
			return
		}

		accessTokenCookie, err := req.Cookie(models.AccessTokenCookie)
		if err != nil {
			log.Error(ctx, "Access token cookie not found", err)
			http.Redirect(w, req, "/florence/login", http.StatusSeeOther)
			return
		}

		tmpl, err := store.GetCollectionTemplate()
		if err != nil {
			log.Error(ctx, "Could not parse template file", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		user.AccessToken = accessTokenCookie.Value

		var data = models.TemplateData{
			PageTitle: "Logged in",
			User:      user,
		}

		err = tmpl.ExecuteTemplate(w, "page", data)
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

		redirectPath := "/florence/collections"
		redirect := req.FormValue("redirect")
		if redirect != "" {
			parsedURL, err := url.Parse(redirect)
			if err != nil {
				log.Error(ctx, "invalid redirect", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			redirectPath = html.EscapeString(parsedURL.Path)
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

		// Store access token in the in-memory map
		models.AccessTokenStore[strings.TrimPrefix(accessToken, BearerPrefix)] = user.Username

		idToken, err := generateIDTokenJWT(store, *user, cfg.IDTokenValidityDuration)
		if err != nil {
			log.Error(ctx, "Failed to generate ID token JWT", err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		refreshToken := "testrefreshtokennn" // Random opaque token string
		refreshTokenData := models.RefreshTokenInfo{
			Username:      username,
			AuthTime:      time.Now(),
			SessionExpiry: time.Now().Add(cfg.RefreshTokenValidityDuration), // Use your config for duration
		}

		// Store refresh token details in the in-memory map
		models.RefreshTokenStore[refreshToken] = refreshTokenData

		// add to header
		setAccessTokenCookie(w, accessToken)
		setIDTokenCookie(w, idToken)
		setRefreshTokenCookie(w, refreshToken)

		http.Redirect(w, req, redirectPath, http.StatusSeeOther)
	}
}

// FlorenceLogoutHandler invalidates the access, ID and refresh tokens and redirects to the login page
func FlorenceLogoutHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		invalidateAccessTokenCookie(w)
		invalidateIDTokenCookie(w)
		invalidateRefreshTokenCookie(w)

		redirectPath := "/florence/login"
		redirect := req.URL.Query().Get("redirect")
		if redirect != "" {
			redirectPath += fmt.Sprintf("?redirect=%s", redirect)
		}

		http.Redirect(w, req, redirectPath, http.StatusSeeOther)
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
		"email":            user.Email,
	}
	return generateJWT(store, user, idTokenClaims, validity)
}

func generateJWT(store static.Store, user models.User, claims jwt.MapClaims, validity time.Duration) (string, error) {
	privateKey := store.GetPrivateKey()
	kids := store.GetKids()

	claims["auth_time"] = time.Now().Unix()           // Auth time
	claims["cognito:groups"] = user.Groups            // Example Group TODO: pull this from somewhere
	claims["iat"] = time.Now().Unix()                 // Issued at
	claims["sub"] = user.Username                     // subject (username)
	claims["exp"] = createExpiryTime(validity).Unix() // Expires at

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kids[0]

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func createExpiryTime(validity time.Duration) time.Time {
	return time.Now().UTC().Add(validity)
}

func TokenSelfGetHandler(ctx context.Context, store static.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		idTokenCookie, err := req.Cookie(models.IDTokenCookie)
		if err != nil {
			log.Error(ctx, "ID token cookie not found", err)
			http.Redirect(w, req, "/florence/login", http.StatusSeeOther)
			return
		}

		user, err := decodeIDTokenUser(idTokenCookie.Value, store.GetPublicKey())
		if err != nil {
			log.Error(ctx, "Could not decode ID token", err)
			http.Redirect(w, req, "/florence/login", http.StatusSeeOther)
			return
		}

		// Load the HTML template
		tmpl, err := store.GetDeleteTokenTemplate()
		if err != nil {
			log.Error(ctx, "Failed to load template", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		data := models.TemplateData{
			PageTitle: "Session Management",
			User:      user,
		}

		// Execute the template and write to response
		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.ExecuteTemplate(w, "page", data); err != nil {
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
			log.Error(ctx, "refresh token not present in request", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		refreshTokenValue := refreshCookie.Value

		// Check if the refresh token exists and hasn't expired
		tokenInfo, exists := models.RefreshTokenStore[refreshTokenValue]
		if !exists {
			log.Error(ctx, "refresh token not present in store", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if tokenInfo.SessionExpiry.Before(time.Now()) {
			log.Error(ctx, "refresh token has expired", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Retrieve the user by email
		user, err := store.GetUser(tokenInfo.Username)
		if err != nil {
			log.Error(ctx, "failed to retrieve user from store", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		cfg, _ := config.Get()

		// Generate new tokens
		newAccessToken, err := generateAccessTokenJWT(store, *user, cfg.AccessTokenValidityDuration)
		if err != nil {
			log.Error(ctx, "failed to generate access token JWT", err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		// Store new access token in the in-memory map
		models.AccessTokenStore[strings.TrimPrefix(newAccessToken, BearerPrefix)] = user.Username

		newIDToken, err := generateIDTokenJWT(store, *user, cfg.IDTokenValidityDuration)
		if err != nil {
			log.Error(ctx, "failed to generate ID token JWT", err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		// Set new tokens as cookies
		setAccessTokenCookie(w, newAccessToken)
		setIDTokenCookie(w, newIDToken)

		responsePayload := models.RefreshResponse{
			ExpirationTime: createExpiryTime(cfg.IDTokenValidityDuration),
		}

		response, err := json.Marshal(responsePayload)
		if err != nil {
			log.Error(ctx, "failed to marshal refresh response payload", err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		_, err = w.Write(response)
		if err != nil {
			log.Error(ctx, "failed to write response body", err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		// Respond with a 200 OK status
		w.WriteHeader(http.StatusOK)
	}
}

func IdentifyUser(ctx context.Context, serviceAuthTokenMap map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("Authorization")
		if authorizationHeader == "" {
			log.Error(ctx, "Authorization header missing", nil)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		serviceToken := strings.TrimPrefix(authorizationHeader, BearerPrefix)

		// Check if the service token matches any in serviceAuthTokenMap, identifier will be the service name
		if identifier := serviceAuthTokenMap[serviceToken]; identifier != "" {
			writeIdentifierResponse(ctx, w, identifier)
			return
		}

		// Check if the service token matches any in AccessTokenStore, identifer will be the username
		if identifier := models.AccessTokenStore[serviceToken]; identifier != "" {
			writeIdentifierResponse(ctx, w, identifier)
			return
		}

		// Service token did not match with any in serviceAuthTokenMap and AccessTokenStore
		w.WriteHeader(http.StatusForbidden)
	}
}

func writeIdentifierResponse(ctx context.Context, w http.ResponseWriter, identifier string) {
	response := map[string]string{"identifier": identifier}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error(ctx, "Error encoding response", err)
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
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

func decodeIDTokenUser(idToken string, publicKey *rsa.PublicKey) (*models.User, error) {
	if idToken == "" {
		return nil, fmt.Errorf("id token is empty")
	}
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	tokenString := strings.TrimPrefix(idToken, BearerPrefix)

	parsedToken, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify id token: %w", err)
	}
	if parsedToken == nil || !parsedToken.Valid {
		return nil, fmt.Errorf("id token is invalid")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("id token claims are not a map")
	}

	email, _ := claims["email"].(string)
	forename, _ := claims["given_name"].(string)
	surname, _ := claims["family_name"].(string)
	username, _ := claims["cognito:username"].(string)
	if username == "" {
		username, _ = claims["username"].(string)
	}

	var groups []string
	switch v := claims["cognito:groups"].(type) {
	case []string:
		groups = append(groups, v...)
	case []interface{}:
		for _, g := range v {
			if s, ok := g.(string); ok {
				groups = append(groups, s)
			}
		}
	case string:
		groups = append(groups, v)
	}

	expClaim, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("id token missing exp claim")
	}

	if time.Now().Unix() >= int64(expClaim) {
		return nil, fmt.Errorf("id token is expired")
	}

	if email == "" && forename == "" && surname == "" && len(groups) == 0 {
		return nil, fmt.Errorf("id token missing expected user claims")
	}

	return &models.User{
		Email:    email,
		Username: username,
		Forename: forename,
		Surname:  surname,
		Groups:   groups,
		Expiry:   time.Unix(int64(expClaim), 0).Format("15:04 02-01-2006"),
	}, nil
}
