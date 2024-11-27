package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/models"
	"github.com/golang-jwt/jwt"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	usersTestJSON          = "../static/json/users_test.json"
	userLoginHTML          = "../templates/user.login.html"
	privateKey             = "../static/keys/private.key"
	publicKey              = "../static/keys/public.key"
	florenceLoginURL       = "/florence/login"
	florenceCollectionsURL = "/florence/collections"
	tokensSelfEndpoint     = "/tokens/self"

	defaultValidRefreshToken = "validRefreshToken"
	validTemplateFilename    = "delete.token.html"
)

func TestJWTKeysHandler_Success(t *testing.T) {
	Convey("Given a JWTKeysHandler", t, func() {
		// mock LoadJwtKeys
		mockLoadJwtKeys := func(ctx context.Context, filename string) ([]models.Response, error) {
			return []models.Response{
				{Kid: "key_id_1", Key: "key1"},
				{Kid: "key_id_2", Key: "key2"},
			}, nil
		}

		handler := JWTKeysHandler(context.Background(), mockLoadJwtKeys)

		Convey("When we make a GET request to the /jwt-keys endpoint", func() {
			request, err := http.NewRequest(http.MethodGet, "/jwt-keys", http.NoBody)
			So(err, ShouldBeNil)

			responseRecorder := httptest.NewRecorder()
			handler.ServeHTTP(responseRecorder, request)

			Convey("Then we have a response 200 and the expected keys", func() {
				expected := map[string]string{
					"key_id_1": "key1",
					"key_id_2": "key2",
				}

				var result map[string]string
				err = json.NewDecoder(responseRecorder.Body).Decode(&result)
				So(err, ShouldBeNil)
				So(result, ShouldResemble, expected)
				So(responseRecorder.Code, ShouldEqual, http.StatusOK)
			})
		})
	})
}

func TestJWTKeysHandler_Error(t *testing.T) {
	Convey("Given a JWTKeysHandler and LoadJwtKeys func returns an error", t, func() {
		// mock LoadJwtKeys
		mockLoadJwtKeys := func(ctx context.Context, filename string) ([]models.Response, error) {
			return nil, errors.New("failed to load jwt keys")
		}

		handler := JWTKeysHandler(context.Background(), mockLoadJwtKeys)

		Convey("When we make a GET request to the /jwt-keys endpoint", func() {
			request, err := http.NewRequest(http.MethodGet, "/jwt-keys", http.NoBody)
			So(err, ShouldBeNil)

			responseRecorder := httptest.NewRecorder()
			handler.ServeHTTP(responseRecorder, request)

			Convey("Then we have a 500 response", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusInternalServerError)
			})
		})
	})
}

func TestFlorenceLoginHandler(t *testing.T) {
	Convey("Given a context, usersFile, templateFile and a FlorenceLoginHandler", t, func() {
		ctx := context.Background()

		Convey("When a valid GET request is made with a redirect URL", func() {
			handler := FlorenceLoginHandler(ctx, usersTestJSON, userLoginHTML)
			request := httptest.NewRequest(http.MethodGet, "/florence/login?redirect=/some/path", http.NoBody)
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 200 OK", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusOK)
			})

			Convey("And the response should contain the redirect URL and user data", func() {
				So(responseRecorder.Body.String(), ShouldContainSubstring, "/some/path")
				So(responseRecorder.Body.String(), ShouldContainSubstring, "admin@ons.gov.uk")
			})
		})

		Convey("When a valid GET request is made without a redirect URL", func() {
			handler := FlorenceLoginHandler(ctx, usersTestJSON, userLoginHTML)
			request := httptest.NewRequest(http.MethodGet, florenceLoginURL, http.NoBody)
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 200 OK", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusOK)
			})

			Convey("And the response should contain the default redirect URL", func() {
				So(responseRecorder.Body.String(), ShouldContainSubstring, florenceCollectionsURL)
			})
		})

		Convey("When the users file is missing", func() {
			Handler := FlorenceLoginHandler(ctx, "../static/json/invalid_users.json", userLoginHTML)
			request := httptest.NewRequest(http.MethodGet, florenceLoginURL, http.NoBody)
			responseRecorder := httptest.NewRecorder()

			Handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 500 Internal Server Error", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusInternalServerError)
			})
		})

		Convey("When the template file is missing", func() {
			Handler := FlorenceLoginHandler(ctx, usersTestJSON, "../templates/invalid_template.html")
			request := httptest.NewRequest(http.MethodGet, florenceLoginURL, http.NoBody)
			responseRecorder := httptest.NewRecorder()

			Handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 500 Internal Server Error", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusInternalServerError)
			})
		})
	})
}

func TestFlorenceLoginHandlerPOST(t *testing.T) {
	Convey("Given a context, usersFile, privateKeyPath and a FlorenceLoginHandlerPOST", t, func() {
		ctx := context.Background()

		Convey("When a POST request is made but form data is missing", func() {
			handler := FlorenceLoginHandlerPOST(ctx, usersTestJSON, privateKey)
			request := httptest.NewRequest(http.MethodPost, florenceLoginURL, http.NoBody)
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 400 Bad Request", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusBadRequest)
			})
		})

		Convey("When a POST request is made but the user is invalid", func() {
			handler := FlorenceLoginHandlerPOST(ctx, usersTestJSON, privateKey)
			formData := url.Values{}
			formData.Set("username", "invalid@ons.gov.uk")
			request := httptest.NewRequest(http.MethodPost, florenceLoginURL, strings.NewReader(formData.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 400 Bad Request", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusBadRequest)
			})
		})

		Convey("When a valid POST request is made without a redirect URL", func() {
			handler := FlorenceLoginHandlerPOST(ctx, usersTestJSON, privateKey)

			formData := url.Values{}
			formData.Set("username", "admin@ons.gov.uk")
			formData.Set("redirect", florenceCollectionsURL)

			request := httptest.NewRequest(http.MethodPost, florenceLoginURL, strings.NewReader(formData.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 303 See Other", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusSeeOther)
			})

			Convey("And the response should contain a default redirect location", func() {
				So(responseRecorder.Header().Get("Location"), ShouldEqual, florenceCollectionsURL)
			})

			Convey("And the response should set access, ID, and refresh token cookies", func() {
				cookies := responseRecorder.Result().Cookies()
				So(len(cookies), ShouldBeGreaterThanOrEqualTo, 3)

				var accessToken, idToken, refreshToken *http.Cookie
				for _, cookie := range cookies {
					if cookie.Name == models.AccessTokenCookie {
						accessToken = cookie
					}
					if cookie.Name == models.IDTokenCookie {
						idToken = cookie
					}
					if cookie.Name == models.RefreshTokenCookie {
						refreshToken = cookie
					}
				}

				So(accessToken, ShouldNotBeNil)
				So(idToken, ShouldNotBeNil)
				So(refreshToken, ShouldNotBeNil)
			})
		})

		Convey("When a valid POST request is made with a redirect URL", func() {
			handler := FlorenceLoginHandlerPOST(ctx, usersTestJSON, privateKey)

			formData := url.Values{}
			formData.Set("username", "admin@ons.gov.uk")

			request := httptest.NewRequest(http.MethodPost, "/florence/login?redirect=/some/path", strings.NewReader(formData.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 303 See Other", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusSeeOther)
			})

			Convey("And the response should contain a default redirect location", func() {
				So(responseRecorder.Header().Get("Location"), ShouldEqual, "/some/path")
			})

			Convey("And the response should set access, ID, and refresh token cookies", func() {
				cookies := responseRecorder.Result().Cookies()
				So(len(cookies), ShouldBeGreaterThanOrEqualTo, 3)

				var accessToken, idToken, refreshToken *http.Cookie
				for _, cookie := range cookies {
					if cookie.Name == models.AccessTokenCookie {
						accessToken = cookie
					}
					if cookie.Name == models.IDTokenCookie {
						idToken = cookie
					}
					if cookie.Name == models.RefreshTokenCookie {
						refreshToken = cookie
					}
				}

				So(accessToken, ShouldNotBeNil)
				So(idToken, ShouldNotBeNil)
				So(refreshToken, ShouldNotBeNil)
			})
		})

		Convey("When the users file is missing", func() {
			handler := FlorenceLoginHandlerPOST(ctx, "../static/json/invalid_users.json", privateKey)
			formData := url.Values{}
			formData.Set("username", "admin@ons.gov.uk")
			request := httptest.NewRequest(http.MethodPost, florenceLoginURL, strings.NewReader(formData.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 400 Bad Request", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusBadRequest)
			})
		})

		Convey("When the private key file is missing", func() {
			handler := FlorenceLoginHandlerPOST(ctx, "../static/json/invalid_users.json", "../static/keys/invalid_private.key")
			formData := url.Values{}
			formData.Set("username", "admin@ons.gov.uk")
			request := httptest.NewRequest(http.MethodPost, florenceLoginURL, strings.NewReader(formData.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 400 Bad Request", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusBadRequest)
			})
		})
	})
}

func TestGenerateJWT(t *testing.T) {
	Convey("Given a user, tokenType, config and privateKeyPath", t, func() {
		cfg, err := config.Get()
		So(err, ShouldBeNil)

		publicKeyData, err := os.ReadFile(publicKey)
		So(err, ShouldBeNil)

		publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
		So(err, ShouldBeNil)

		keyFunc := func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodRSA)
			So(ok, ShouldBeTrue)
			return publicKey, nil
		}

		testUser := models.User{
			Email:    "admin@ons.gov.uk",
			Username: "c6a20lbf-30eb-0235-b621-ke2aw87dd385",
			Forename: "John",
			Surname:  "Smith",
			Groups:   []string{"role-admin"},
		}

		Convey("When generating an access token", func() {
			tokenString := generateJWT(testUser, "access", *cfg, privateKey)

			Convey("Then it should return a valid JWT string", func() {
				token, err := jwt.Parse(tokenString, keyFunc)
				So(err, ShouldBeNil)
				So(token, ShouldNotBeNil)

				claims, ok := token.Claims.(jwt.MapClaims)
				So(ok, ShouldBeTrue)

				So(claims["sub"], ShouldEqual, testUser.Username)
				So(claims["cognito:groups"], ShouldContain, "group1")
				So(claims["auth_time"], ShouldBeBetweenOrEqual, time.Now().Unix(), time.Now().Unix()-10)
				So(claims["iat"], ShouldBeBetweenOrEqual, time.Now().Unix(), time.Now().Unix()-10)
				So(claims["username"], ShouldEqual, testUser.Username)
				So(claims["exp"], ShouldBeBetweenOrEqual, time.Now().Add(cfg.AccessTokenValidityDuration).Unix(), time.Now().Add(cfg.IDTokenValidityDuration).Unix()-10)
			})
		})

		Convey("When generating an id token", func() {
			tokenString := generateJWT(testUser, "id", *cfg, privateKey)

			Convey("Then it should return a valid JWT string", func() {
				token, err := jwt.Parse(tokenString, keyFunc)
				So(err, ShouldBeNil)
				So(token, ShouldNotBeNil)

				claims, ok := token.Claims.(jwt.MapClaims)
				So(ok, ShouldBeTrue)

				So(claims["sub"], ShouldEqual, testUser.Username)
				So(claims["cognito:groups"], ShouldContain, "group1")
				So(claims["auth_time"], ShouldBeBetweenOrEqual, time.Now().Unix(), time.Now().Unix()-10)
				So(claims["iat"], ShouldBeBetweenOrEqual, time.Now().Unix(), time.Now().Unix()-10)
				So(claims["cognito:username"], ShouldEqual, testUser.Username)
				So(claims["given_name"], ShouldEqual, testUser.Forename)
				So(claims["family_name"], ShouldEqual, testUser.Surname)
				So(claims["email"], ShouldEqual, testUser.Username)
				So(claims["exp"], ShouldBeBetweenOrEqual, time.Now().Add(cfg.IDTokenValidityDuration).Unix(), time.Now().Add(cfg.IDTokenValidityDuration).Unix()-10)
			})
		})

		Convey("When generating a token with an invalid token type", func() {
			tokenString := generateJWT(testUser, "invalidType", *cfg, privateKey)

			Convey("Then it should return a JWT string without token-specific claims", func() {
				token, err := jwt.Parse(tokenString, keyFunc)
				So(err, ShouldBeNil)
				So(token, ShouldNotBeNil)

				claims, ok := token.Claims.(jwt.MapClaims)
				So(ok, ShouldBeTrue)

				So(claims["sub"], ShouldEqual, testUser.Username)
				So(claims["cognito:groups"], ShouldContain, "group1")
				So(claims["auth_time"], ShouldBeBetweenOrEqual, time.Now().Unix(), time.Now().Unix()-10)
				So(claims["iat"], ShouldBeBetweenOrEqual, time.Now().Unix(), time.Now().Unix()-10)
				So(claims, ShouldNotContainKey, "username")
				So(claims, ShouldNotContainKey, "cognito:username")
				So(claims, ShouldNotContainKey, "given_name")
				So(claims, ShouldNotContainKey, "family_name")
				So(claims, ShouldNotContainKey, "email")
				So(claims, ShouldNotContainKey, "exp")
			})
		})

		Convey("When generating a token with an invalid private key path", func() {
			tokenString := generateJWT(testUser, "access", *cfg, "../static/keys/missing_private.key")

			Convey("Then it should return an error message indicating no such file or directory", func() {
				So(tokenString, ShouldContainSubstring, "no such file or directory")
			})
		})

		Convey("When generating a token with an invalid private key format", func() {
			invalidPrivateKeyContent := `Not a private key`
			err := os.WriteFile("../static/keys/invalid_private.key", []byte(invalidPrivateKeyContent), 0644)
			So(err, ShouldBeNil)
			defer os.Remove("../static/keys/invalid_private.key")
			tokenString := generateJWT(testUser, "access", *cfg, "../static/keys/invalid_private.key")

			Convey("Then it should return an error message indicating parsing failure", func() {
				So(tokenString, ShouldContainSubstring, "Invalid Key")
			})
		})
	})
}

func TestTokenSelfGetHandler(t *testing.T) {
	Convey("Given a context, templatePath, filepath and TokenSelfGetHandler", t, func() {
		ctx := context.Background()

		Convey("When the template loads and renders successfully", func() {
			validTemplatePath := "../templates"

			handler := TokenSelfGetHandler(ctx, validTemplatePath, validTemplateFilename)

			request := httptest.NewRequest(http.MethodGet, tokensSelfEndpoint, http.NoBody)
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 200 OK", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusOK)
			})

			Convey("And the Content-Type should be 'text/html'", func() {
				So(responseRecorder.Header().Get("Content-Type"), ShouldEqual, "text/html")
			})
		})

		Convey("When the template does not load successfully", func() {
			invalidTemplatePath := "templates"

			handler := TokenSelfGetHandler(ctx, invalidTemplatePath, validTemplateFilename)

			request := httptest.NewRequest(http.MethodGet, tokensSelfEndpoint, http.NoBody)
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 500 Internal Server Error", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusInternalServerError)
			})
		})
	})
}

func TestTokenSelfDeleteHandler(t *testing.T) {
	Convey("Given a context and TokenSelfDeleteHandler", t, func() {
		ctx := context.Background()
		handler := TokenSelfDeleteHandler(ctx)

		Convey("When the refresh token cookie is missing", func() {
			request := httptest.NewRequest(http.MethodDelete, tokensSelfEndpoint, http.NoBody)
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 401 Unauthorized", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusUnauthorized)
			})
		})

		Convey("When the refresh token is not in the in-memory store", func() {
			request := httptest.NewRequest(http.MethodDelete, tokensSelfEndpoint, http.NoBody)
			request.AddCookie(&http.Cookie{Name: models.RefreshTokenCookie, Value: "invalid-token"})
			responseRecorder := httptest.NewRecorder()

			delete(models.RefreshTokenStore, "invalid-token")

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 401 Unauthorized", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusUnauthorized)
			})
		})

		Convey("When the refresh token is valid", func() {
			request := httptest.NewRequest(http.MethodDelete, tokensSelfEndpoint, http.NoBody)
			responseRecorder := httptest.NewRecorder()

			request.AddCookie(&http.Cookie{Name: models.RefreshTokenCookie, Value: defaultValidRefreshToken, Path: "/"})

			cfg, err := config.Get()
			So(err, ShouldBeNil)

			models.RefreshTokenStore[defaultValidRefreshToken] = models.RefreshTokenInfo{
				Username:      "Valid",
				AuthTime:      time.Now(),
				SessionExpiry: time.Now().Add(cfg.RefreshTokenValidityDuration),
			}

			// Assert refresh token was added to in-memory store
			_, exists := models.RefreshTokenStore[defaultValidRefreshToken]
			So(exists, ShouldBeTrue)

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 204 No Content and remove the refresh token from the store", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusNoContent)
				_, exists := models.RefreshTokenStore[defaultValidRefreshToken]
				So(exists, ShouldBeFalse)
			})

			Convey("And it should set expired cookies for access_token, id_token, and refreshToken", func() {
				cookies := responseRecorder.Result().Cookies()

				var accessToken, idToken, refreshToken *http.Cookie
				for _, cookie := range cookies {
					switch cookie.Name {
					case models.AccessTokenCookie:
						accessToken = cookie
					case models.IDTokenCookie:
						idToken = cookie
					case models.RefreshTokenCookie:
						refreshToken = cookie
					}
				}

				So(accessToken, ShouldNotBeNil)
				So(accessToken.Expires.Before(time.Now()), ShouldBeTrue)
				So(accessToken.MaxAge, ShouldEqual, -1)

				So(idToken, ShouldNotBeNil)
				So(idToken.Expires.Before(time.Now()), ShouldBeTrue)
				So(idToken.MaxAge, ShouldEqual, -1)

				So(refreshToken, ShouldNotBeNil)
				So(refreshToken.Expires.Before(time.Now()), ShouldBeTrue)
				So(refreshToken.MaxAge, ShouldEqual, -1)
			})
		})
	})
}

func TestTokenSelfPutHandler(t *testing.T) {
	Convey("Given a context and TokenSelfPutHandler", t, func() {
		ctx := context.Background()
		handler := TokenSelfPutHandler(ctx)

		Convey("When the refresh token cookie is missing", func() {
			request := httptest.NewRequest(http.MethodPut, tokensSelfEndpoint, http.NoBody)
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 400 Bad Request", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusBadRequest)
			})
		})

		Convey("When the refresh token is invalid or expired", func() {
			request := httptest.NewRequest(http.MethodPut, tokensSelfEndpoint, http.NoBody)
			request.AddCookie(&http.Cookie{Name: models.RefreshTokenCookie, Value: "invalid_token", Path: "/"})
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 403 Forbidden", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusForbidden)
			})
		})

		Convey("When the refreshToken is valid", func() {
			request := httptest.NewRequest(http.MethodPut, tokensSelfEndpoint, http.NoBody)
			responseRecorder := httptest.NewRecorder()

			request.AddCookie(&http.Cookie{Name: models.RefreshTokenCookie, Value: defaultValidRefreshToken, Path: "/"})

			cfg, err := config.Get()
			So(err, ShouldBeNil)

			models.RefreshTokenStore[defaultValidRefreshToken] = models.RefreshTokenInfo{
				Username:      "Valid",
				AuthTime:      time.Now(),
				SessionExpiry: time.Now().Add(cfg.RefreshTokenValidityDuration),
			}

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 200 OK", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusOK)
			})

			Convey("And it should set new access_token and id_token cookies", func() {
				cookies := responseRecorder.Result().Cookies()
				var accessToken, idToken *http.Cookie
				for _, cookie := range cookies {
					switch cookie.Name {
					case models.AccessTokenCookie:
						accessToken = cookie
					case models.IDTokenCookie:
						idToken = cookie
					}
				}

				So(accessToken, ShouldNotBeNil)
				So(accessToken.Value, ShouldStartWith, BearerPrefix)
				So(accessToken.HttpOnly, ShouldBeTrue)

				So(idToken, ShouldNotBeNil)
				So(idToken.Value, ShouldNotBeEmpty)
				So(idToken.HttpOnly, ShouldBeTrue)
			})
		})
	})
}

func TestIdentifyUser(t *testing.T) {
	Convey("Given a context and IdentifyUser handler", t, func() {
		ctx := context.Background()
		handler := IdentifyUser(ctx)

		Convey("When the Authorization header is missing", func() {
			request := httptest.NewRequest(http.MethodGet, "/identity", http.NoBody)
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 401 Unauthorized", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusUnauthorized)
			})
		})

		Convey("When the Authorization header has an invalid service token", func() {
			request := httptest.NewRequest(http.MethodGet, "/identity", http.NoBody)
			request.Header.Set("Authorization", "Bearer invalid-token")
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 403 Forbidden", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusForbidden)
			})
		})

		Convey("When the Authorization header has an valid service token", func() {
			request := httptest.NewRequest(http.MethodGet, "/identity", http.NoBody)

			cfg, err := config.Get()
			So(err, ShouldBeNil)

			existingAuthToken := BearerPrefix + cfg.ZebedeeAuthToken

			request.Header.Set("Authorization", existingAuthToken)
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 200 with expected JSON body", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusOK)

				var response map[string]string
				err := json.NewDecoder(responseRecorder.Body).Decode(&response)
				So(err, ShouldBeNil)
				So(response["identifier"], ShouldEqual, "zebedee")
			})
		})
	})
}
