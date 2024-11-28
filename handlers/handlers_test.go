package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/models"
	"github.com/ONSdigital/dis-authentication-stub/static/mock"
	"github.com/golang-jwt/jwt"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	florenceLoginURL       = "/florence/login"
	florenceCollectionsURL = "/florence/collections"
	tokensSelfEndpoint     = "/tokens/self"

	defaultValidRefreshToken = "validRefreshToken"
	mockKID                  = "fakekid"
)

var (
	testUser = models.User{
		Email:    "admin@ons.gov.uk",
		Username: "c6a20lbf-30eb-0235-b621-ke2aw87dd385",
		Forename: "John",
		Surname:  "Smith",
		Groups:   []string{"role-admin"},
	}
)

func TestJWTKeysHandler_Success(t *testing.T) {
	Convey("Given a JWTKeysHandler and a mocked store", t, func() {
		mockKeys := map[string]string{
			"key_id_1": "key",
		}
		mockStore := &mock.StoreMock{
			GetJWKsFunc: func() map[string]string { return mockKeys },
		}
		handler := JWTKeysHandler(context.Background(), mockStore)

		Convey("When we make a GET request to the /jwt-keys endpoint", func() {
			request, err := http.NewRequest(http.MethodGet, "/jwt-keys", http.NoBody)
			So(err, ShouldBeNil)

			responseRecorder := httptest.NewRecorder()
			handler.ServeHTTP(responseRecorder, request)

			Convey("Then the store should be called to get the keys", func() {
				So(mockStore.GetJWKsCalls(), ShouldHaveLength, 1)
			})

			Convey("And the server should serve the keys", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusOK)

				var result map[string]string
				err = json.NewDecoder(responseRecorder.Body).Decode(&result)
				So(err, ShouldBeNil)
				So(result, ShouldResemble, mockKeys)
			})
		})
	})
}

func TestFlorenceLoginHandler(t *testing.T) {
	Convey("Given a context, a mock Store that returns a user and a FlorenceLoginHandler", t, func() {
		ctx := context.Background()
		mockContent := "Hello World"
		mockTemplate, err := template.New("foo").Parse(mockContent)
		So(err, ShouldBeNil)

		mockStore := &mock.StoreMock{
			GetUsersFunc: func() ([]models.User, error) {
				return []models.User{
					testUser,
				}, nil
			},
			GetUserLoginTemplateFunc: func() (*template.Template, error) { return mockTemplate, nil },
		}

		Convey("When a user requests the login page", func() {
			handler := FlorenceLoginHandler(ctx, mockStore)
			request := httptest.NewRequest(http.MethodGet, "/florence/login", http.NoBody)
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 200 OK", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusOK)
			})

			Convey("Then the store should be called to get the users", func() {
				So(mockStore.GetUsersCalls(), ShouldHaveLength, 1)
			})

			Convey("And the response should contain login template", func() {
				So(responseRecorder.Body.String(), ShouldContainSubstring, mockContent)
			})
		})
	})
}

func TestFlorenceLoginHandlerPOST(t *testing.T) {
	Convey("Given a context, a mock store that returns a user and a FlorenceLoginHandlerPOST", t, func() {
		ctx := context.Background()

		mockKey, err := rsa.GenerateKey(rand.Reader, 2048)
		So(err, ShouldBeNil)

		mockStore := &mock.StoreMock{
			GetUserFunc:       func(email string) (*models.User, error) { return &testUser, nil },
			GetPrivateKeyFunc: func() *rsa.PrivateKey { return mockKey },
			GetKidsFunc:       func() []string { return []string{mockKID} },
		}

		Convey("When a POST request is made but form data is missing", func() {
			handler := FlorenceLoginHandlerPOST(ctx, mockStore)
			request := httptest.NewRequest(http.MethodPost, florenceLoginURL, http.NoBody)
			responseRecorder := httptest.NewRecorder()

			handler.ServeHTTP(responseRecorder, request)

			Convey("Then it should return 400 Bad Request", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusBadRequest)
			})
		})

		Convey("When a valid POST request is made without a redirect URL", func() {
			handler := FlorenceLoginHandlerPOST(ctx, mockStore)

			formData := url.Values{}
			formData.Set("username", testUser.Email)
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
			handler := FlorenceLoginHandlerPOST(ctx, mockStore)

			formData := url.Values{}
			formData.Set("username", testUser.Email)

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
	})

	Convey("Given a mock store that returns user not found", t, func() {
		ctx := context.Background()
		mockStore := &mock.StoreMock{
			GetUserFunc: func(email string) (*models.User, error) { return nil, errors.New("user not found") },
		}

		Convey("When a POST request is made to /florence/login", func() {
			handler := FlorenceLoginHandlerPOST(ctx, mockStore)
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
	})
}

func TestGenerateJWT(t *testing.T) {
	Convey("Given a user, and a mock store", t, func() {
		cfg, err := config.Get()
		So(err, ShouldBeNil)

		mockKey, err := rsa.GenerateKey(rand.Reader, 2048)
		So(err, ShouldBeNil)

		mockStore := &mock.StoreMock{
			GetUserFunc:       func(email string) (*models.User, error) { return &testUser, nil },
			GetPrivateKeyFunc: func() *rsa.PrivateKey { return mockKey },
			GetKidsFunc:       func() []string { return []string{mockKID} },
		}

		keyFunc := func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodRSA)
			So(ok, ShouldBeTrue)
			return &mockKey.PublicKey, nil
		}

		Convey("When generating an access token", func() {
			accessToken, err := generateAccessTokenJWT(mockStore, testUser, cfg.AccessTokenValidityDuration)
			So(err, ShouldBeNil)

			tokenString := strings.TrimPrefix(accessToken, BearerPrefix)

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
				So(token.Header["kid"], ShouldEqual, mockKID)
			})
		})

		Convey("When generating an id token", func() {
			idToken, err := generateIDTokenJWT(mockStore, testUser, cfg.IDTokenValidityDuration)
			So(err, ShouldBeNil)

			tokenString := strings.TrimPrefix(idToken, BearerPrefix)

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
				So(token.Header["kid"], ShouldEqual, mockKID)
			})
		})
	})
}

func TestTokenSelfGetHandler(t *testing.T) {
	Convey("Given a context, a mock store and a TokenSelfGetHandler", t, func() {
		ctx := context.Background()

		mockContent := "Delete world"
		mockTemplate, err := template.New("foo").Parse(mockContent)
		So(err, ShouldBeNil)

		mockStore := &mock.StoreMock{
			GetDeleteTokenTemplateFunc: func() (*template.Template, error) { return mockTemplate, nil },
		}

		handler := TokenSelfGetHandler(ctx, mockStore)

		Convey("When the the tokens/self endpoint is requested", func() {
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
	Convey("Given a context, a mock store and TokenSelfPutHandler", t, func() {
		ctx := context.Background()
		mockKey, err := rsa.GenerateKey(rand.Reader, 2048)
		So(err, ShouldBeNil)

		mockStore := &mock.StoreMock{
			GetPrivateKeyFunc: func() *rsa.PrivateKey { return mockKey },
			GetKidsFunc:       func() []string { return []string{mockKID} },
		}

		handler := TokenSelfPutHandler(ctx, mockStore)

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
